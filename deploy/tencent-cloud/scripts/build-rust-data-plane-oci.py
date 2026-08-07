#!/usr/bin/env python3
"""Deterministically assemble a versioned Rust data-plane OCI image.

The frozen base data-plane image is read-only. This script derives a new OCI
layout by appending one layer that replaces the data-plane binaries with the
specified release binaries. The base archive is never modified.

Output: a valid single-platform (linux/amd64) OCI layout archive named from
``--tag`` plus an ``oci-digest-record.json`` digest record under ``--dest``.

Everything is deterministic for fixed inputs: layer tar entries are sorted with a
fixed mtime, the gzip layer uses a fixed header mtime, and the index/created
timestamps are the fixed ``--created`` value.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

BINARIES = [
    "ri-agent",
    "ri-wrapper",
    "ri-trace-adapter",
    "ri-registry-sync",
    "ri-knot-trace-producer",
    "ri-authority-proxy",
]

# Fixed timestamps keep a rebuild byte-identical for the same inputs.
FIXED_MTIME = 1785888000  # 2026-08-05T00:00:00Z
FIXED_CREATED = "2026-08-05T00:00:00Z"

LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_blob(layout: Path, blob_digest: str) -> bytes:
    blob = layout / "blobs" / "sha256" / blob_digest.removeprefix("sha256:")
    return blob.read_bytes()


def verify_binary(binary: Path) -> None:
    if not binary.is_file():
        raise SystemExit(f"missing release binary: {binary}")
    data = binary.read_bytes()
    if data[:4] != b"\x7fELF":
        raise SystemExit(f"not an ELF binary: {binary}")
    # ELF e_machine at offset 18 (2 bytes, little endian): 62 = EM_X86_64.
    machine = int.from_bytes(data[18:20], "little")
    if machine != 62:
        raise SystemExit(f"binary is not x86_64 (e_machine={machine}): {binary}")


def build_layer(binaries: list[Path]) -> tuple[bytes, str, int]:
    """Build the RC2 binaries layer. Returns (gzipped_bytes, diff_id, blob_size)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for binary in sorted(binaries):
            info = tar.gettarinfo(str(binary), arcname=f"usr/local/bin/{binary.name}")
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mode = 0o755
            info.mtime = FIXED_MTIME
            info.pax_headers = {}
            with binary.open("rb") as handle:
                tar.addfile(info, handle)
    raw_bytes = raw.getvalue()
    diff_id = f"sha256:{sha256_bytes(raw_bytes)}"
    gz = gzip.compress(raw_bytes, mtime=0)
    return gz, diff_id, len(gz)


def deterministic_layout_tar(layout: Path) -> bytes:
    """Tar an OCI layout directory with deterministic ordering and mtimes."""
    raw = io.BytesIO()
    blobs = sorted(
        (p for p in (layout / "blobs" / "sha256").iterdir() if p.is_file()),
        key=lambda p: p.name,
    )
    names = ["oci-layout", "index.json", *(f"blobs/sha256/{p.name}" for p in blobs)]
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name in names:
            source = layout / name
            info = tar.gettarinfo(str(source), arcname=name)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = FIXED_MTIME
            info.pax_headers = {}
            with source.open("rb") as handle:
                tar.addfile(info, handle)
    return raw.getvalue()


def archive_name(tag: str) -> str:
    label = tag.rsplit("-", 1)[-1]
    safe_label = "".join(
        character if character.isalnum() or character in ".-_" else "-"
        for character in label
    )
    if not safe_label or safe_label in {".", ".."}:
        raise SystemExit("tag does not produce a safe archive name")
    return f"rust-data-plane-oci-{safe_label}.tar"


def assemble(
    rc1_archive: Path,
    release_bin: Path,
    tag: str,
    dest: Path,
    created: str,
) -> dict[str, object]:
    work = Path(tempfile.mkdtemp(prefix="oci-assemble-"))
    try:
        layout = work / "rc1"
        layout.mkdir()
        with tarfile.open(rc1_archive, "r:") as tar:
            tar.extractall(layout, filter="data")

        index = json.loads((layout / "index.json").read_text())
        manifest_digest = index["manifests"][0]["digest"]
        manifest = json.loads(read_blob(layout, manifest_digest))
        config_digest = manifest["config"]["digest"]
        config = json.loads(read_blob(layout, config_digest))
        if len(config["rootfs"]["diff_ids"]) != len(manifest["layers"]):
            raise SystemExit("RC1 layout has mismatched layers/diff_ids")

        binaries = [release_bin / name for name in BINARIES]
        for binary in binaries:
            verify_binary(binary)

        gz_layer, diff_id, gz_size = build_layer(binaries)
        layer_digest = f"sha256:{sha256_bytes(gz_layer)}"

        # New config: clone RC1, append the new layer's diff_id and a history step.
        new_config = json.loads(json.dumps(config))
        new_config["rootfs"]["diff_ids"] = config["rootfs"]["diff_ids"] + [diff_id]
        new_config["history"] = config["history"] + [
            {
                "created": created,
                "created_by": "COPY /build/target/release/{"
                + ",".join(BINARIES)
                + "} /usr/local/bin/ # buildkit",
            }
        ]
        new_config["created"] = created
        config_bytes = json.dumps(new_config, indent=2, sort_keys=False).encode()
        new_config_digest = f"sha256:{sha256_bytes(config_bytes)}"

        # New manifest: same layers plus the RC2 binaries layer.
        new_manifest = json.loads(json.dumps(manifest))
        new_manifest["config"] = {
            "mediaType": CONFIG_MEDIA_TYPE,
            "digest": new_config_digest,
            "size": len(config_bytes),
        }
        new_manifest["layers"] = manifest["layers"] + [
            {
                "mediaType": LAYER_MEDIA_TYPE,
                "digest": layer_digest,
                "size": gz_size,
            }
        ]
        manifest_bytes = json.dumps(new_manifest, indent=2, sort_keys=False).encode()
        new_manifest_digest = f"sha256:{sha256_bytes(manifest_bytes)}"

        # New index with the RC2 tag annotation.
        new_index = {
            "schemaVersion": 2,
            "mediaType": INDEX_MEDIA_TYPE,
            "manifests": [
                {
                    "mediaType": MANIFEST_MEDIA_TYPE,
                    "digest": new_manifest_digest,
                    "size": len(manifest_bytes),
                    "annotations": {
                        "io.containerd.image.name": (
                            f"docker.io/resolver-identity/rust-data-plane:{tag}"
                        ),
                        "org.opencontainers.image.created": created,
                        "org.opencontainers.image.ref.name": tag,
                    },
                    "platform": {"architecture": "amd64", "os": "linux"},
                }
            ],
        }
        index_bytes = json.dumps(new_index, indent=2).encode()
        oci_layout_bytes = json.dumps({"imageLayoutVersion": "1.0.0"}).encode()

        # Write the fresh output layout: all referenced layers plus the new
        # layer/config/manifest blobs, and the RC2 index/oci-layout. The frozen
        # RC1 config and manifest blobs are intentionally NOT carried over: the
        # new manifest/config supersede them and the output must reference
        # exactly its own blobs.
        out = work / "out"
        (out / "blobs" / "sha256").mkdir(parents=True)
        (out / "oci-layout").write_bytes(oci_layout_bytes)
        (out / "index.json").write_bytes(index_bytes)
        blob_writes: dict[str, bytes] = {}
        for old_layer in manifest["layers"]:
            blob_writes[old_layer["digest"].removeprefix("sha256:")] = read_blob(
                layout, old_layer["digest"]
            )
        blob_writes[layer_digest.removeprefix("sha256:")] = gz_layer
        blob_writes[new_config_digest.removeprefix("sha256:")] = config_bytes
        blob_writes[new_manifest_digest.removeprefix("sha256:")] = manifest_bytes
        for name, data in blob_writes.items():
            (out / "blobs" / "sha256" / name).write_bytes(data)

        archive_bytes = deterministic_layout_tar(out)
        dest.mkdir(parents=True, exist_ok=True)
        archive = dest / archive_name(tag)
        archive.write_bytes(archive_bytes)

        # Self-check: the produced archive must reference exactly its own blobs.
        check = work / "check"
        check.mkdir()
        with tarfile.open(archive, "r:") as tar:
            tar.extractall(check, filter="data")
        check_index = json.loads((check / "index.json").read_text())
        check_manifest_digest = check_index["manifests"][0]["digest"]
        if check_manifest_digest != new_manifest_digest:
            raise SystemExit("self-check failed: index digest mismatch")
        check_manifest = json.loads(read_blob(check, new_manifest_digest))
        referenced: set[str] = {new_manifest_digest, new_config_digest}
        for layer in check_manifest["layers"]:
            blob_path = check / "blobs" / "sha256" / layer["digest"].removeprefix("sha256:")
            if sha256_file(blob_path) != layer["digest"].removeprefix("sha256:"):
                raise SystemExit(f"self-check failed: layer digest {layer['digest']}")
            if len(blob_path.read_bytes()) != layer["size"]:
                raise SystemExit(f"self-check failed: layer size {layer['digest']}")
            referenced.add(layer["digest"])
        if sha256_file(check / "blobs" / "sha256" / new_config_digest.removeprefix("sha256:")) != (
            new_config_digest.removeprefix("sha256:")
        ):
            raise SystemExit("self-check failed: config digest mismatch")
        actual_blobs = {
            f"sha256:{path.name}"
            for path in (check / "blobs" / "sha256").iterdir()
            if path.is_file()
        }
        if actual_blobs != referenced:
            raise SystemExit(
                "self-check failed: unreferenced or missing blobs: "
                + ", ".join(sorted(actual_blobs ^ referenced))
            )

        record = {
            "schema_version": "resolver-identity-oci-layout-v1",
            "version": tag,
            "platform": {"os": "linux", "architecture": "amd64"},
            "derived_from": {
                "archive": rc1_archive.name,
                "archive_sha256": sha256_file(rc1_archive),
                "manifest_digest": manifest_digest,
            },
            "binaries": [b.name for b in binaries],
            "binaries_sha256": {b.name: sha256_file(b) for b in binaries},
            "created": created,
            "archive": archive.name,
            "archive_sha256": sha256_file(archive),
            "manifest_digest": new_manifest_digest,
            "config_digest": new_config_digest,
            "config_size": len(config_bytes),
            "layer_count": len(new_manifest["layers"]),
        }
        (dest / "oci-digest-record.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(record, indent=2))
        return record
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-archive", "--rc1-archive", dest="base_archive", type=Path, required=True)
    parser.add_argument("--release-bin", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--created", default=FIXED_CREATED)
    args = parser.parse_args()
    assemble(args.base_archive, args.release_bin, args.tag, args.dest, args.created)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

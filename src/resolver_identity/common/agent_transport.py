from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class AgentTLSConfig:
    ca_file: str | None = None
    client_cert_file: str | None = None
    client_key_file: str | None = None

    def httpx_kwargs(self) -> dict:
        kwargs: dict = {"verify": self.ca_file or True}
        if self.client_cert_file and self.client_key_file:
            kwargs["cert"] = (self.client_cert_file, self.client_key_file)
        return kwargs


def validate_agent_url_config(raw_mappings: str, plaintext_hosts: set[str]) -> None:
    for item in raw_mappings.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError("Agent URL mapping must use endpoint=url format")
        _endpoint, url = item.split("=", 1)
        parsed = urlparse(url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"invalid Agent URL: {url}")
        if parsed.scheme == "http" and parsed.hostname not in plaintext_hosts:
            raise ValueError(f"plaintext Agent URL host is not allowlisted: {parsed.hostname}")

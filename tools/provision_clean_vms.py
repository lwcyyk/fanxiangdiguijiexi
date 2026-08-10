#!/usr/bin/env python3
"""Provision the 7 clean-test VMs for domain-center clean install acceptance.

Reads TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY (or ~/.tccli/default.credential),
creates an isolated VPC/subnet/security-groups and 7 Ubuntu 24.04 CVMs
(2 vCPU / 2 GiB / 40 GiB), waits for them to be ready, and writes a VM inventory.

Uses the Tencent Cloud API v3 (TC3-HMAC-SHA256) over HTTPS with the standard
library only. Never stores credentials in output. Run from the operator host
(not the clean VMs).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API_HOST = "cvm.tencentcloudapi.com"
VPC_HOST = "vpc.tencentcloudapi.com"
REGION = os.environ.get("TC_REGION", "ap-guangzhou")
ZONE = os.environ.get("TC_ZONE", "ap-guangzhou-7")
INSTANCE_TYPE = os.environ.get("TC_INSTANCE_TYPE", "S5.SMALL1")
IMAGE_ID = os.environ.get("TC_IMAGE_ID", "img-487yf4yy")
VPC_CIDR = "10.206.32.0/20"  # isolated clean-test subnet range (not 10.206.16.0/20)
SUBNET_CIDR = "10.206.32.0/24"

ROLES = [
    ("clean-mgmt", "management"),
    ("clean-norn-a", "norn-a"),
    ("clean-norn-b", "norn-b"),
    ("clean-authdns", "authdns"),
    ("clean-r3", "r3"),
    ("clean-r2", "r2"),
    ("clean-r1", "r1"),
]
INSTANCE_TYPE = "S5.SMALL1"  # 2 vCPU / 2 GiB (adjust to availability)
IMAGE_ID = "img-487yf4yy"    # Ubuntu 24.04 LTS 64位（需按账号可用镜像替换）
VPC_CIDR = "10.206.32.0/20"  # isolated clean-test subnet range (not 10.206.16.0/20)
SUBNET_CIDR = "10.206.32.0/24"


class APIError(RuntimeError):
    pass


def load_credentials() -> tuple[str, str]:
    secret_id = os.environ.get("TENCENTCLOUD_SECRET_ID")
    secret_key = os.environ.get("TENCENTCLOUD_SECRET_KEY")
    if secret_id and secret_key:
        return secret_id, secret_key
    credential = Path.home() / ".tccli" / "default.credential"
    if credential.is_file():
        text = credential.read_text(encoding="utf-8")
        sid = re.search(r"secretId\s*=\s*(\S+)", text)
        skey = re.search(r"secretKey\s*=\s*(\S+)", text)
        if sid and skey:
            return sid.group(1), skey.group(1)
    raise RuntimeError(
        "no Tencent Cloud credentials: set TENCENTCLOUD_SECRET_ID/TENCENTCLOUD_SECRET_KEY "
        "or ~/.tccli/default.credential (secretId=… / secretKey=…)"
    )


def sign(secret_id: str, secret_key: str, service: str, action: str, payload: dict) -> dict:
    timestamp = int(time.time())
    date = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).strftime("%Y-%m-%d")
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    canonical = "\n".join(
        [
            "POST",
            "/",
            "",
            "content-type:application/json; charset=utf-8",
            f"host:{service}.tencentcloudapi.com",
            "",
            "content-type;host",
            hashlib.sha256(body.encode()).hexdigest(),
        ]
    )
    to_sign = "\n".join(
        [
            "TC3-HMAC-SHA256",
            str(timestamp),
            f"{date}/{service}/tc3_request",
            hashlib.sha256(canonical.encode()).hexdigest(),
        ]
    )
    def hmac_sha256(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode(), hashlib.sha256).digest()

    secret_date = hmac_sha256(("TC3" + secret_key).encode(), date)
    secret_service = hmac_sha256(secret_date, service)
    secret_signing = hmac_sha256(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = (
        f"TC3-HMAC-SHA256 Credential={secret_id}/{date}/{service}/tc3_request, "
        f"SignedHeaders=content-type;host, Signature={signature}"
    )
    return {
        "body": body,
        "headers": {
            "Authorization": authorization,
            "Content-Type": "application/json; charset=utf-8",
            "Host": f"{service}.tencentcloudapi.com",
            "X-TC-Action": action,
            "X-TC-Version": "2017-03-12" if service == "cvm" else "2017-03-12",
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Region": REGION,
        },
    }


def call(secret_id: str, secret_key: str, service: str, action: str, payload: dict, retries: int = 3) -> dict:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            signed = sign(secret_id, secret_key, service, action, payload)
            request = urllib.request.Request(
                f"https://{service}.tencentcloudapi.com/",
                data=signed["body"].encode(),
                headers=signed["headers"],
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode())
            if "Response" in result:
                response_body = result["Response"]
                if "Error" in response_body:
                    raise APIError(f"{action}: {response_body['Error']}")
                return response_body
            raise APIError(f"{action}: unexpected response {result}")
        except (urllib.error.URLError, APIError) as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"{action} failed after retries: {last}")


def create_vpc(secret_id: str, secret_key: str) -> str:
    response = call(
        secret_id, secret_key, "vpc", "CreateVpc",
        {"VpcName": "clean-test-vpc", "CidrBlock": VPC_CIDR, "EnableMulticast": False},
    )
    return response["Vpc"]["VpcId"]


def create_subnet(secret_id: str, secret_key: str, vpc_id: str) -> str:
    response = call(
        secret_id, secret_key, "vpc", "CreateSubnet",
        {"VpcId": vpc_id, "SubnetName": "clean-test-subnet", "CidrBlock": SUBNET_CIDR, "Zone": ZONE},
    )
    return response["Subnet"]["SubnetId"]


def create_security_group(secret_id: str, secret_key: str, vpc_id: str, name: str) -> str:
    response = call(
        secret_id, secret_key, "vpc", "CreateSecurityGroup",
        {"GroupName": name, "GroupDescription": "domain-center clean-test", "VpcId": vpc_id},
    )
    return response["SecurityGroup"]["SecurityGroupId"]


def add_security_rules(secret_id: str, secret_key: str, group_id: str, rules: list[dict]) -> None:
    call(
        secret_id, secret_key, "vpc", "ModifySecurityGroupPolicies",
        {
            "SecurityGroupId": group_id,
            "SecurityGroupPolicySet": {
                "Ingress": rules,
                "Egress": [{"Protocol": "ALL", "Action": "ACCEPT", "CidrBlock": "0.0.0.0/0"}],
            },
        },
    )


def create_instance(secret_id: str, secret_key: str, vpc_id: str, subnet_id: str, sg_id: str, hostname: str, role: str) -> str:
    response = call(
        secret_id, secret_key, "cvm", "RunInstances",
        {
            "InstanceChargeType": "POSTPAID_BY_HOUR",
            "Placement": {"Zone": ZONE},
            "InstanceType": INSTANCE_TYPE,
            "ImageId": IMAGE_ID,
            "VirtualPrivateCloud": {"VpcId": vpc_id, "SubnetId": subnet_id, "AsVpcGateway": False},
            "SecurityGroupIds": [sg_id],
            "InstanceName": hostname,
            "HostName": hostname,
            "SystemDisk": {"DiskType": "CLOUD_SSD", "DiskSize": 40},
            "InternetAccessible": {"InternetMaxBandwidthOut": 5, "PublicIpAssigned": True},
            "LoginSettings": {"Password": os.environ.get("CLEAN_VM_INIT_PASSWORD")},
            "InstanceCount": 1,
        },
    )
    return response["InstanceIdSet"][0]


def wait_ready(secret_id: str, secret_key: str, instance_ids: list[str], timeout: int = 600) -> dict:
    deadline = time.monotonic() + timeout
    inventory: dict[str, dict] = {}
    while time.monotonic() < deadline:
        response = call(
            secret_id, secret_key, "cvm", "DescribeInstances",
            {"InstanceIds": instance_ids, "Limit": 100},
        )
        by_id = {item["InstanceId"]: item for item in response.get("InstanceSet", [])}
        ready = True
        for instance_id in instance_ids:
            item = by_id.get(instance_id, {})
            state = item.get("InstanceState")
            if state != "RUNNING":
                ready = False
                continue
            inventory[instance_id] = {
                "instance_id": instance_id,
                "name": item.get("InstanceName"),
                "private_ip": item.get("PrivateIpAddresses", [""])[0] if item.get("PrivateIpAddresses") else "",
                "public_ip": item.get("PublicIpAddresses", [""])[0] if item.get("PublicIpAddresses") else "",
            }
        if ready and len(inventory) == len(instance_ids):
            return inventory
        time.sleep(10)
    raise TimeoutError("instances did not become RUNNING in time")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("clean-vm-inventory.json"))
    parser.add_argument("--password", help="initial SSH password (default: env CLEAN_VM_INIT_PASSWORD)")
    parser.add_argument("--region", default=REGION)
    parser.add_argument("--zone", default=ZONE)
    parser.add_argument("--instance-type", default=INSTANCE_TYPE)
    parser.add_argument("--image-id", default=IMAGE_ID)
    args = parser.parse_args()
    if args.password:
        os.environ["CLEAN_VM_INIT_PASSWORD"] = args.password
    if not os.environ.get("CLEAN_VM_INIT_PASSWORD"):
        print("missing --password / CLEAN_VM_INIT_PASSWORD", file=sys.stderr)
        return 2
    try:
        secret_id, secret_key = load_credentials()
    except RuntimeError as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    print("creating VPC …")
    vpc_id = create_vpc(secret_id, secret_key)
    subnet_id = create_subnet(secret_id, secret_key, vpc_id)
    sg_id = create_security_group(secret_id, secret_key, vpc_id, "clean-test-sg")
    add_security_rules(
        secret_id, secret_key, sg_id,
        [
            {"Protocol": "TCP", "Port": "22", "Action": "ACCEPT", "CidrBlock": "0.0.0.0/0", "Description": "ssh"},
            {"Protocol": "UDP", "Port": "53", "Action": "ACCEPT", "CidrBlock": VPC_CIDR, "Description": "dns-udp"},
            {"Protocol": "TCP", "Port": "53", "Action": "ACCEPT", "CidrBlock": VPC_CIDR, "Description": "dns-tcp"},
            {"Protocol": "UDP", "Port": "1053", "Action": "ACCEPT", "CidrBlock": VPC_CIDR, "Description": "wrapper"},
            {"Protocol": "TCP", "Port": "1053", "Action": "ACCEPT", "CidrBlock": VPC_CIDR, "Description": "wrapper"},
            {"Protocol": "TCP", "Port": "8443", "Action": "ACCEPT", "CidrBlock": VPC_CIDR, "Description": "agent-mtls"},
            {"Protocol": "TCP", "Port": "9109", "Action": "ACCEPT", "CidrBlock": VPC_CIDR, "Description": "registry-ready"},
            {"Protocol": "TCP", "Port": "9110", "Action": "ACCEPT", "CidrBlock": VPC_CIDR, "Description": "trace-ready"},
            {"Protocol": "TCP", "Port": "31258", "Action": "ACCEPT", "CidrBlock": VPC_CIDR, "Description": "norn-p2p"},
        ],
    )
    print("creating 7 instances …")
    instance_ids = []
    for hostname, role in ROLES:
        instance_id = create_instance(secret_id, secret_key, vpc_id, subnet_id, sg_id, hostname, role)
        instance_ids.append(instance_id)
        print(f"  {hostname} -> {instance_id}")
    print("waiting for RUNNING …")
    inventory = wait_ready(secret_id, secret_key, instance_ids)
    result = {
        "schema_version": "domain-center-clean-vm-inventory-v1",
        "region": REGION,
        "zone": ZONE,
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "security_group_id": sg_id,
        "security_group_rules": "minimal: ssh-22 + intra-VPC dns/wrapper/agent/ready/norn ports",
        "instances": [
            {"role": role, "hostname": hostname, **inventory[instance_id]}
            for (hostname, role), instance_id in zip(ROLES, instance_ids)
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"inventory: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

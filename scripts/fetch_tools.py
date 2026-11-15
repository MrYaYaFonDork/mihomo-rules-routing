"""Download pinned official Linux amd64 tools, verify and extract one binary each."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
MAX_DOWNLOAD = 80 * 1024 * 1024


def verify_sha256(path, expected):
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if digest != expected:
        raise ValueError(f"checksum mismatch for {path}: {digest}")


def download(url, path, limit=MAX_DOWNLOAD):
    if not url.startswith("https://"):
        raise ValueError("HTTPS required")
    with urllib.request.urlopen(url, timeout=60) as response, open(path, "wb") as target:
        if not response.geturl().startswith("https://"):
            raise ValueError("HTTPS redirect required")
        if response.status != 200:
            raise ValueError(f"HTTP status {response.status}")
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError("download too large")
            target.write(chunk)


def fetch_tools(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    config = json.loads((ROOT / "config/tools.json").read_text())
    with tempfile.TemporaryDirectory(dir=destination, prefix=".tools-") as temp:
        temp = Path(temp)
        for name, info in config.items():
            archive = temp / (name + ".archive")
            download(info["url"], archive)
            verify_sha256(archive, info["sha256"])
            binary = temp / name
            if name == "sing-box":
                member_name = f"sing-box-{info['version']}-linux-amd64/sing-box"
                with tarfile.open(archive, "r:gz") as tar:
                    member = tar.getmember(member_name)
                    if not member.isfile() or member.size > MAX_DOWNLOAD:
                        raise ValueError("invalid binary in archive")
                    with tar.extractfile(member) as source, binary.open("wb") as target:
                        shutil.copyfileobj(source, target)
            else:
                with gzip.open(archive, "rb") as source, binary.open("wb") as target:
                    data = source.read(MAX_DOWNLOAD + 1)
                    if len(data) > MAX_DOWNLOAD:
                        raise ValueError("binary too large")
                    target.write(data)
            verify_sha256(binary, info["binary_sha256"])
            binary.chmod(0o755)
        for name in config:
            os.replace(temp / name, destination / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    fetch_tools(parser.parse_args().destination)


if __name__ == "__main__":
    main()

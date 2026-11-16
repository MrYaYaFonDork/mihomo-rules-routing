"""Publish an already validated full snapshot as one leased orphan commit."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse


def publish_snapshot(product, remote, work_dir, *, expected_manifest_sha256):
    """Publish to rules; caller must validate the current manifest before invoking."""
    product, work_dir = Path(product), Path(work_dir)
    if not isinstance(remote, str) or not remote or remote.startswith("-") or any(c in remote for c in "\r\n"):
        raise ValueError("invalid remote")
    if "://" in remote:
        url = urllib.parse.urlsplit(remote)
        if url.scheme not in ("https", "ssh", "file") or url.password or url.query or url.fragment:
            raise ValueError("invalid remote URL")
        if url.scheme == "https" and url.username:
            raise ValueError("credentials in remote URL are forbidden")
    elif "::" in remote:
        raise ValueError("invalid remote")
    if product.is_symlink() or not product.is_dir():
        raise ValueError("invalid product directory")
    manifest_path = product / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("invalid manifest")
    manifest_bytes = manifest_path.read_bytes()
    if (not isinstance(expected_manifest_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256)
            or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256):
        raise ValueError("manifest hash mismatch")
    manifest = json.loads(manifest_bytes)
    outputs = manifest.get("outputs")
    required = {"rule-providers.yaml", "README.md", "GUIDE.md"}
    if not isinstance(outputs, dict) or not required <= outputs.keys():
        raise ValueError("missing product outputs")
    for path, digest in outputs.items():
        if not isinstance(path, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid output metadata")
        if path not in required:
            if (not re.fullmatch(r"mihomo/(?:[A-Za-z0-9_@!+.-]+/)*[A-Za-z0-9_@!+.-]+\.(?:mrs|yaml)", path)
                    or any(part in (".", "..") for part in path.split("/"))):
                raise ValueError("invalid output path")
    if not any(path.startswith("mihomo/") for path in outputs):
        raise ValueError("no providers")
    expected_dirs = {str(parent) for name in outputs for parent in Path(name).parents if str(parent) != "."}
    actual_files, actual_dirs = set(), set()
    for path in product.rglob("*"):
        name = str(path.relative_to(product))
        if path.is_symlink():
            raise ValueError("symlink in product")
        if path.is_file():
            actual_files.add(name)
        elif path.is_dir():
            actual_dirs.add(name)
        else:
            raise ValueError("invalid product entry")
    if actual_files != set(outputs) | {"manifest.json"} or actual_dirs != expected_dirs:
        raise ValueError("unexpected product content")

    env = os.environ.copy()
    for key in list(env):
        if (key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                    "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_SYSTEM")
                or key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))):
            env.pop(key)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    with tempfile.TemporaryDirectory(dir=work_dir, prefix="publish-") as tmp:
        repo = Path(tmp)
        def git(*args, allowed=(0,)):
            command = ["git", *args]
            result = subprocess.run(command, cwd=repo, env=env, capture_output=True, text=True)
            if result.returncode not in allowed:
                raise subprocess.CalledProcessError(result.returncode, command)
            return result
        git("init", "-q", "--template=")
        git("config", "user.name", "github-actions[bot]")
        git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
        git("config", "core.hooksPath", "/dev/null")
        git("config", "core.attributesFile", "/dev/null")
        git("config", "core.autocrlf", "false")
        git("config", "http.followRedirects", "false")
        git("config", "commit.gpgsign", "false")
        git("remote", "add", "origin", remote)
        for name, expected in outputs.items():
            file = product / name
            if file.is_symlink() or not file.is_file():
                raise ValueError("invalid output file")
            data = file.read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError("output hash mismatch")
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
                raise ValueError("copied output hash mismatch")
        copied_manifest = repo / "manifest.json"
        copied_manifest.write_bytes(manifest_bytes)
        if hashlib.sha256(copied_manifest.read_bytes()).hexdigest() != expected_manifest_sha256:
            raise ValueError("copied manifest hash mismatch")
        git("add", "--all")
        staged = git("ls-files", "--stage", "-z").stdout
        entries = {}
        for entry in staged.split("\0"):
            if entry:
                metadata, name = entry.split("\t", 1)
                if not metadata.startswith("100644 ") or name in entries:
                    raise ValueError("invalid staged file")
                entries[name] = metadata
        if set(entries) != set(outputs) | {"manifest.json"}:
            raise ValueError("invalid staged tree")
        git("commit", "-qm", "Update generated rules")
        branch = git("ls-remote", "--exit-code", "--heads", "origin", "refs/heads/rules", allowed=(0, 2))
        if branch.returncode == 2:
            if branch.stdout:
                raise ValueError("invalid branch response")
            observed = ""
        else:
            match = re.fullmatch(r"([0-9a-f]{40})\trefs/heads/rules\n?", branch.stdout)
            if not match:
                raise ValueError("invalid branch response")
            observed = match.group(1)
            git("fetch", "--no-tags", "origin", "refs/heads/rules")
            if git("rev-parse", "FETCH_HEAD").stdout.strip() != observed:
                raise ValueError("rules branch changed during fetch")
        git("push", f"--force-with-lease=refs/heads/rules:{observed}", "origin", "HEAD:refs/heads/rules")
        return {"previous": observed, "commit": git("rev-parse", "HEAD").stdout.strip()}

"""Validate generated providers offline in an isolated Linux network namespace."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

try:
    from scripts.build import providers_yaml
    from scripts.fetch_tools import ROOT, verify_sha256
except ModuleNotFoundError:
    from build import providers_yaml
    from fetch_tools import ROOT, verify_sha256


def check_log(path):
    if "parse classical rule" in path.read_text().lower():
        raise ValueError("classical parser warning")


def providers_ready(providers, expected):
    if not isinstance(providers, dict) or not all(
            name in providers and providers[name].get("ruleCount", 0) > 0 for name in expected):
        return False
    for name, (behavior, count) in expected.items():
        if behavior == "classical" and providers[name]["ruleCount"] != count:
            raise ValueError(f"{name}: expected {count}, got {providers[name]['ruleCount']}")
    return True


def run_inside(output, mihomo, work_dir, timeout):
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=10)
    manifest = json.loads((output / "manifest.json").read_text())
    sources = manifest["sources"]
    if len(sources) != 46:
        raise ValueError("expected 46 sources")
    expected, providers = {}, {}
    for source in sources:
        for name in source["providers"]:
            behavior, fmt = source["behavior"], source["format"]
            path = output / "rules" / (name + "." + fmt)
            expected[name] = (behavior, source["count"])
            providers[name] = {"type": "file", "behavior": behavior, "format": fmt, "path": str(path)}
    if len(providers) != 46:
        raise ValueError("expected 46 unique providers")
    def port():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    controller, mixed = port(), port()
    while mixed == controller:
        mixed = port()
    with tempfile.TemporaryDirectory(dir=work_dir, prefix="integration-") as tmp:
        tmp = Path(tmp)
        for name, provider in providers.items():
            source = Path(provider["path"])
            target = tmp / source.name
            shutil.copyfile(source, target)
            provider["path"] = str(target)
        config = ("bind-address: 127.0.0.1\nmixed-port: " + str(mixed) +
                  "\nexternal-controller: 127.0.0.1:" + str(controller) +
                  "\nallow-lan: false\ntun:\n  enable: false\ndns:\n  enable: false\n"
                  "find-process-mode: off\nlog-level: debug\n" +
                  providers_yaml(providers) + "rules:\n" +
                  "".join("  - " + json.dumps("RULE-SET," + name + ",REJECT,no-resolve") + "\n"
                          for name in providers) + "  - MATCH,REJECT\n")
        conf = tmp / "config.yaml"
        conf.write_text(config)
        subprocess.run([str(mihomo), "-t", "-d", str(tmp), "-f", str(conf)],
                       check=True, timeout=timeout)
        log_path = tmp / "mihomo.log"
        with log_path.open("w") as log:
            proc = subprocess.Popen([str(mihomo), "-d", str(tmp), "-f", str(conf)],
                                    stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise RuntimeError(f"mihomo exited: {proc.returncode}")
                    check_log(log_path)
                    try:
                        with urllib.request.urlopen(
                                f"http://127.0.0.1:{controller}/providers/rules", timeout=1) as response:
                            actual = json.load(response).get("providers")
                        if providers_ready(actual, expected):
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(0.1)
                else:
                    raise TimeoutError("providers did not load")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                check_log(log_path)
    print(f"validated {len(expected)} providers; classical counts match; no parser warnings")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--namespace-fd", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 300:
        parser.error("timeout must be between 1 and 300 seconds")
    if args.inside:
        try:
            if (args.namespace_fd is None or
                    not re.fullmatch(r"net:\[\d+\]", os.readlink(f"/proc/self/fd/{args.namespace_fd}")) or
                    os.fstat(args.namespace_fd).st_ino == os.stat("/proc/self/ns/net").st_ino):
                raise ValueError("network namespace is not isolated")
        except OSError as exc:
            raise ValueError("invalid network namespace descriptor") from exc
    elif args.namespace_fd is not None:
        parser.error("--namespace-fd requires --inside")
    output, mihomo, work = args.output.resolve(), args.mihomo.resolve(), args.work_dir.resolve()
    config = json.loads((ROOT / "config/tools.json").read_text())
    verify_sha256(mihomo, config["mihomo"]["binary_sha256"])
    work.mkdir(parents=True, exist_ok=True)
    if args.inside:
        run_inside(output, mihomo, work, args.timeout)
    else:
        fd = os.open("/proc/self/ns/net", os.O_RDONLY)
        try:
            subprocess.run(["unshare", "-rn", sys.executable, str(Path(__file__).resolve()),
                            "--inside", "--namespace-fd", str(fd), "--output", str(output),
                            "--mihomo", str(mihomo), "--work-dir", str(work),
                            "--timeout", str(args.timeout)],
                           check=True, timeout=2 * args.timeout + 30, pass_fds=(fd,))
        finally:
            os.close(fd)


if __name__ == "__main__":
    main()

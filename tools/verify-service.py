#!/usr/bin/env python3
"""Exercise the real HTTP service and write credential-free verification evidence."""
import argparse
import json
import ipaddress
import math
import os
import platform
import statistics
import subprocess
import time
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--report", default=".local/verification/service.json")
    parser.add_argument("--benchmark", type=int, default=0)
    parser.add_argument("--restart-phase", choices=["before", "after"])
    parser.add_argument("--restart-record", default=".local/verification/restart.json")
    args = parser.parse_args()
    try:
        endpoint = urllib.parse.urlsplit(args.url)
        valid_url = (endpoint.scheme == "http" and ipaddress.ip_address(endpoint.hostname).is_loopback
                     and endpoint.port is not None and 1 <= endpoint.port <= 65535
                     and endpoint.username is None and endpoint.password is None
                     and not endpoint.path and not endpoint.query and not endpoint.fragment)
    except (TypeError, ValueError):
        valid_url = False
    if not valid_url:
        raise SystemExit("verification client only accepts loopback URLs")
    if Path(args.token_file).stat().st_size > 256:
        raise SystemExit("credential file exceeds 256 bytes")
    token = Path(args.token_file).read_text().strip()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(method, path, data=None, authenticated=True, raw=None):
        body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(args.url + path, data=body, headers=headers, method=method)
        try:
            with opener.open(req, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    terminal = {"succeeded", "failed", "timed_out", "cancelled", "output_limit", "resource_exhausted", "interrupted"}

    def wait(job_id, wanted=None):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            status, job = call("GET", "/v1/jobs/" + job_id)
            assert status == 200, (status, job)
            if job["state"] in terminal or (wanted and job["state"] == wanted):
                return job
            time.sleep(0.01)
        raise AssertionError("job transition timed out")

    def submit(source, timeout_ms=3000):
        status, job = call("POST", "/v1/jobs", {
            "argv": ["/usr/bin/python3", "-I", "/input/main.py"],
            "files": {"main.py": source}, "timeout_ms": timeout_ms,
        })
        assert status == 202, (status, job)
        return job

    ready_deadline = time.monotonic() + 15
    while True:
        try:
            status, _ = call("GET", "/readyz")
            if status == 200:
                break
        except urllib.error.URLError:
            pass
        if time.monotonic() >= ready_deadline:
            raise SystemExit("service did not become ready within 15 seconds")
        time.sleep(0.1)

    if args.restart_phase:
        path = Path(args.restart_record)
        path.parent.mkdir(parents=True, exist_ok=True)
        if args.restart_phase == "before":
            job = submit("import time; time.sleep(25)", 30000)
            assert wait(job["id"], "running")["state"] == "running"
            path.write_text(json.dumps({"id": job["id"]}) + "\n")
            print("Restart probe admitted; kill/restart the service, then run --restart-phase after.")
        else:
            job = wait(json.loads(path.read_text())["id"])
            assert job["state"] == "interrupted", job
            path.write_text(json.dumps({"id": job["id"], "state": job["state"], "passed": True}, indent=2) + "\n")
            print("Crash recovery passed: interrupted job was not replayed.")
        return

    checks = []
    for name, method, path, data, auth, expected in [
        ("authentication", "GET", "/v1/jobs", None, False, 401),
        ("readiness", "GET", "/readyz", None, True, 200),
        ("traversal_rejected", "POST", "/v1/jobs", {"argv": ["/bin/sh"], "files": {"../escape": "x"}}, True, 400),
        ("unknown_fields_rejected", "POST", "/v1/jobs", {"argv": ["/bin/sh"], "env": {"SECRET": "x"}}, True, 400),
    ]:
        status, _ = call(method, path, data, auth)
        assert status == expected, (name, status)
        checks.append({"name": name, "passed": True})
    status, _ = call("POST", "/v1/jobs", raw=b'{"argv":["/bin/sh"],"argv":["/bad"]}')
    assert status == 400
    checks.append({"name": "duplicate_fields_rejected", "passed": True})

    scenarios = [
        ("legitimate_execution", "print(sum(range(100)))", "succeeded", 3000),
        ("network_denial", "import socket; socket.socket()", "failed", 3000),
        ("kernel_log_denial", "import os,ctypes,errno\nassert not os.path.exists('/dev/kmsg')\nlibc=ctypes.CDLL(None,use_errno=True)\nassert libc.klogctl(3,None,0)==-1 and ctypes.get_errno()==errno.EPERM\ntry:\n open('/proc/kmsg','rb')\n raise AssertionError('kernel log readable')\nexcept OSError as e:\n assert e.errno in (errno.EPERM,errno.EACCES)\nprint('kernel logs denied')", "succeeded", 3000),
        ("output_limit", "import os; os.write(1,b'x'*200000)", "output_limit", 3000),
        ("deadline", "import time; time.sleep(10)", "timed_out", 150),
        ("memory_limit", "a=bytearray(512*1024*1024)", "resource_exhausted", 3000),
    ]
    for name, source, expected, timeout in scenarios:
        job = wait(submit(source, timeout)["id"])
        assert job["state"] == expected, (name, job)
        checks.append({"name": name, "passed": True, "state": job["state"], "usage": job["result"]["usage"]})
    job = submit("import time; time.sleep(10)", 15000)
    assert wait(job["id"], "running")["state"] == "running"
    status, _ = call("DELETE", "/v1/jobs/" + job["id"])
    assert status == 202 and wait(job["id"])["state"] == "cancelled"
    checks.append({"name": "running_cancellation", "passed": True})
    status, listing = call("GET", "/v1/jobs")
    assert status == 200 and all("result" not in item for item in listing["jobs"])
    checks.append({"name": "metadata_only_listing", "passed": True})

    report = {"checks": checks, "environment": {"platform": platform.platform(), "python": platform.python_version()}, "benchmark": None}
    if args.benchmark:
        if not 5 <= args.benchmark <= 500:
            raise SystemExit("benchmark sample count must be 5-500")
        wall, end_to_end, baseline = [], [], []
        source = "print(sum(range(100)))"
        for _ in range(args.benchmark):
            start = time.perf_counter()
            job = wait(submit(source)["id"])
            assert job["state"] == "succeeded"
            end_to_end.append((time.perf_counter() - start) * 1000)
            wall.append(job["result"]["usage"]["wall_ms"])
            if platform.system() == "Linux":
                start = time.perf_counter()
                subprocess.run(["/usr/bin/python3", "-I", "-c", source], check=True, capture_output=True, env={"PATH": "/usr/bin:/bin"})
                baseline.append((time.perf_counter() - start) * 1000)

        def summary(values):
            return {"p50_ms": round(statistics.median(values), 3), "p95_ms": round(sorted(values)[math.ceil(len(values) * .95) - 1], 3), "samples": values}

        report["benchmark"] = {"n": args.benchmark, "workload": source, "sandbox_execution": summary(wall), "http_end_to_end": summary(end_to_end), "trusted_host_baseline": summary(baseline) if baseline else None, "notes": "Sequential warm-cache workload; includes no network/model calls. Not a capacity or production SLO claim."}
    target = Path(args.report)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Passed {len(checks)} end-to-end checks; evidence written to {target}")


if __name__ == "__main__":
    main()

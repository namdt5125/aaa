#!/usr/bin/env python3

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import requests


BANNER = r"""
PHP2Shell defensive research harness
CVE-2026-109618 / CVE-2026-109619

This program performs controlled HTTP request testing against
an explicitly supplied laboratory endpoint.

It does NOT implement memory corruption, arbitrary memory writes,
ASLR bypass, ROP/JOP construction, or remote command execution.
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_target(session: requests.Session, target: str) -> dict:
    result = {
        "url": target,
        "reachable": False,
        "status": None,
        "elapsed_ms": None,
        "content_type": None,
        "server": None,
        "body_sha256": None,
        "body_size": None,
    }

    start = time.monotonic()

    try:
        response = session.get(
            target,
            timeout=5,
            allow_redirects=False,
        )

        elapsed = (time.monotonic() - start) * 1000

        body = response.content

        result.update(
            {
                "reachable": True,
                "status": response.status_code,
                "elapsed_ms": round(elapsed, 2),
                "content_type": response.headers.get(
                    "Content-Type"
                ),
                "server": response.headers.get(
                    "Server"
                ),
                "body_sha256": sha256(body),
                "body_size": len(body),
            }
        )

    except requests.RequestException as exc:
        result["error"] = str(exc)

    return result


def multipart_probe(
    session: requests.Session,
    target: str,
    size: int,
) -> dict:

    payload = b"A" * size

    files = {
        "research_file": (
            "probe.bin",
            payload,
            "application/octet-stream",
        )
    }

    data = {
        "research_marker": "php2shell-lab"
    }

    result = {
        "payload_size": size,
        "status": None,
        "elapsed_ms": None,
        "response_size": None,
        "error": None,
    }

    start = time.monotonic()

    try:
        response = session.post(
            target,
            files=files,
            data=data,
            timeout=15,
            allow_redirects=False,
        )

        elapsed = (time.monotonic() - start) * 1000

        result.update(
            {
                "status": response.status_code,
                "elapsed_ms": round(elapsed, 2),
                "response_size": len(response.content),
            }
        )

    except requests.RequestException as exc:
        result["error"] = str(exc)

    return result


def classify(result: dict) -> str:
    if result.get("error"):
        return "transport-error"

    status = result.get("status")

    if status is None:
        return "no-status"

    if status >= 500:
        return "server-error"

    if status >= 400:
        return "client-error"

    return "normal-response"


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Controlled PHP2Shell HTTP research harness"
        )
    )

    parser.add_argument(
        "url",
        help="Explicitly authorized lab URL",
    )

    parser.add_argument(
        "--sizes",
        nargs="+",
        type=int,
        default=[
            1024,
            1024 * 1024,
            4 * 1024 * 1024,
            8 * 1024 * 1024,
        ],
        help="Multipart payload sizes in bytes",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between probes in seconds",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("php2shell-results.json"),
        help="JSON output file",
    )

    args = parser.parse_args()

    print(BANNER)

    if not args.url.startswith(
        ("http://127.0.0.1:", "http://localhost:")
    ):
        print(
            "Refusing to run: this research harness is "
            "restricted to localhost targets.",
            file=sys.stderr,
        )
        return 2

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": (
                "PHP2Shell-Lab-Research/1.0"
            )
        }
    )

    print("[+] Target:", args.url)
    print("[+] Checking connectivity...")

    baseline = check_target(
        session,
        args.url,
    )

    print(
        json.dumps(
            baseline,
            indent=2,
        )
    )

    if not baseline["reachable"]:
        print(
            "[-] Target is unreachable.",
            file=sys.stderr,
        )
        return 1

    results = {
        "target": args.url,
        "timestamp": int(time.time()),
        "baseline": baseline,
        "probes": [],
    }

    print()
    print("[+] Beginning controlled multipart tests")

    for size in args.sizes:

        print(
            f"[+] Sending {size:,} byte multipart request..."
        )

        result = multipart_probe(
            session,
            args.url,
            size,
        )

        result["classification"] = classify(
            result
        )

        results["probes"].append(result)

        print(
            json.dumps(
                result,
                indent=2,
            )
        )

        time.sleep(args.delay)

    args.output.write_text(
        json.dumps(
            results,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(
        "[+] Results written to:",
        args.output,
    )

    print()
    print("[+] Summary")

    for probe in results["probes"]:

        print(
            f"    {probe['payload_size']:>10,} bytes"
            f" -> {probe['classification']}"
            f" ({probe.get('status')})"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

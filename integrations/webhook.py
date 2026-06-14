#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request

_ALLOWED_SCHEMES = {"http", "https"}


def _validate_url(url: str, ap: argparse.ArgumentParser) -> None:
    """Abort with a clear message when *url* is not a valid http/https URL."""
    if not url or not url.strip():
        ap.error("--url must not be empty")
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in _ALLOWED_SCHEMES:
        ap.error(
            f"--url must start with http:// or https:// (got {url!r})"
        )


def _validate_header(header: str, ap: argparse.ArgumentParser) -> tuple[str, str]:
    """Parse 'Key: Value'; abort on malformed headers."""
    if ":" not in header:
        ap.error(
            f"--header value must be in 'Key: Value' format (got {header!r})"
        )
    k, _, v = header.partition(":")
    k, v = k.strip(), v.strip()
    if not k:
        ap.error(f"--header key must not be empty (got {header!r})")
    return k, v


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Forward attackmap JSON findings to a webhook URL.",
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https)")
    ap.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra request header in 'Key: Value' format (repeatable)",
    )
    args = ap.parse_args()

    _validate_url(args.url, ap)

    try:
        raw = sys.stdin.read()
    except (KeyboardInterrupt, EOFError):
        print("error: no input received on stdin", file=sys.stderr)
        return 2

    if not raw.strip():
        print("error: stdin is empty — nothing to forward", file=sys.stderr)
        return 2

    # Validate that stdin looks like JSON so we catch encoding issues early.
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: stdin is not valid JSON: {exc}", file=sys.stderr)
        return 2

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, v = _validate_header(h, ap)
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook HTTP error {exc.code}: {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook connection error: {exc.reason}", file=sys.stderr)
        return 1
    except TimeoutError:
        print("webhook error: request timed out", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Re-verify each registered node with `uq check` and write docs/status/nodes.json.

Reads a node config (deploy/nodes.config.json), runs the prebuilt verifier
against every node that has an `endpoint`, parses the human-readable
`[uq]` output, and emits the live status JSON consumed by docs/live.html.

Verifier-only: this runs on an ordinary CI runner with no TEE. It just opens an
attested-TLS connection, pulls the EAT from the cert, and re-checks the
hardware quote against the pinned vendor roots.
"""
import datetime
import json
import os
import re
import subprocess
import sys

UQ_BIN = os.environ.get("UQ_BIN", "dist/uq-linux-x86_64")
NODES_CONFIG = os.environ.get("NODES_CONFIG", "deploy/nodes.config.json")
STATUS_OUT = os.environ.get("STATUS_OUT", "docs/status/nodes.json")
CHECK_TIMEOUT = int(os.environ.get("CHECK_TIMEOUT", "45"))

MEASUREMENT_KEYS = {
    "MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3",
    "MEASUREMENT", "HOST_DATA", "PCR0", "PCR1", "PCR2",
}


def now_iso():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_check_output(text):
    """Extract structured fields from `uq check` stderr/stdout."""
    out = {
        "value_x": None,
        "value_x_short": None,
        "spki_binding": None,
        "quote_signature": None,
        "chain": None,
        "measurements": {},
        "platform_seen": None,
    }
    for raw in text.splitlines():
        line = raw.strip()
        line = re.sub(r"^\[uq\]\s*", "", line)

        m = re.match(r"Platform:\s*Some\((\w+)\)", line)
        if m:
            out["platform_seen"] = m.group(1)
            continue

        m = re.match(r"Value X:\s*([0-9a-fA-F]+)", line)
        if m:
            out["value_x"] = m.group(1)
            out["value_x_short"] = m.group(1)[:16]
            continue

        m = re.match(r"SPKI binding:\s*(\w+)", line)
        if m:
            out["spki_binding"] = m.group(1)
            continue

        if line.startswith("Quote signature:"):
            out["quote_signature"] = line.split(":", 1)[1].strip()
            continue
        if line.startswith("Quote verify:"):
            out["quote_signature"] = "FAIL"
            continue

        m = re.match(r"Chain:\s*(.+)", line)
        if m:
            out["chain"] = m.group(1).strip()
            continue

        m = re.match(r"([A-Z0-9_]+):\s*([0-9a-fA-F]{16,})$", line)
        if m and m.group(1) in MEASUREMENT_KEYS:
            out["measurements"][m.group(1)] = m.group(2)

    return out


def check_node(endpoint):
    """Run the verifier. Returns (verdict, detail, parsed)."""
    try:
        proc = subprocess.run(
            [UQ_BIN, "check", endpoint],
            capture_output=True,
            text=True,
            timeout=CHECK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "offline", f"no response within {CHECK_TIMEOUT}s", {}
    except FileNotFoundError:
        return "failed", f"verifier not found: {UQ_BIN}", {}

    combined = (proc.stderr or "") + "\n" + (proc.stdout or "")
    parsed = parse_check_output(combined)

    if proc.returncode == 0:
        return "verified", "quote re-verified against pinned vendor root", parsed

    # Distinguish unreachable from a real verification failure.
    lowered = combined.lower()
    if any(s in lowered for s in ("tcp connect", "connection refused", "timed out", "dns")):
        return "offline", "endpoint unreachable", parsed

    # Last meaningful error line.
    err_lines = [l.strip() for l in combined.splitlines() if l.strip()]
    detail = err_lines[-1] if err_lines else f"exit {proc.returncode}"
    return "failed", detail[:200], parsed


def main():
    with open(NODES_CONFIG) as fh:
        config = json.load(fh)

    nodes_out = []
    for node in config.get("nodes", []):
        entry = {
            "id": node["id"],
            "label": node.get("label", node["id"]),
            "cloud": node.get("cloud"),
            "region": node.get("region"),
            "platform": node.get("platform"),
            "endpoint": node.get("endpoint"),
            "verdict": "pending",
            "value_x": None,
            "value_x_short": None,
            "measurements": {},
            "spki_binding": None,
            "quote_signature": None,
            "chain": None,
            "checked_at": None,
            "detail": "registered, awaiting first live report",
        }

        endpoint = node.get("endpoint")
        if endpoint:
            verdict, detail, parsed = check_node(endpoint)
            entry["verdict"] = verdict
            entry["detail"] = detail
            entry["checked_at"] = now_iso()
            entry["value_x"] = parsed.get("value_x")
            entry["value_x_short"] = parsed.get("value_x_short")
            entry["spki_binding"] = parsed.get("spki_binding")
            entry["quote_signature"] = parsed.get("quote_signature")
            entry["chain"] = parsed.get("chain")
            entry["measurements"] = parsed.get("measurements", {})
            if parsed.get("platform_seen"):
                entry["platform"] = parsed["platform_seen"]
            print(f"[report] {node['id']}: {verdict} ({detail})")
        else:
            print(f"[report] {node['id']}: pending (no endpoint)")

        nodes_out.append(entry)

    status = {
        "updated_at": now_iso(),
        "generator": "report-live-quotes.yml",
        "schema": 1,
        "nodes": nodes_out,
    }

    os.makedirs(os.path.dirname(STATUS_OUT), exist_ok=True)
    with open(STATUS_OUT, "w") as fh:
        json.dump(status, fh, indent=2)
        fh.write("\n")
    print(f"[report] wrote {STATUS_OUT} ({len(nodes_out)} node(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())

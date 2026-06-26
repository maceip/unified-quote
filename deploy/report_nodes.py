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


def parse_azure_output(text):
    """Extract fields from `uq azure check` stderr (vTPM SNP → AMD root)."""
    out = {"measurements": {}, "verdict": None, "sig": None, "chain_ok": None,
           "runtime_sha256": None}
    for raw in text.splitlines():
        line = re.sub(r"^\[uq/azure\]\s*", "", raw.strip())
        m = re.match(r"verdict:\s*(\w+)", line)
        if m:
            out["verdict"] = m.group(1)
        m = re.match(r"measurement:\s*([0-9a-fA-F]{32,})", line)
        if m:
            out["measurements"]["MEASUREMENT"] = m.group(1)
        m = re.match(r"sig_verified:\s*(\w+)", line)
        if m:
            out["sig"] = m.group(1) == "true"
        m = re.match(r"chain_verified:\s*(\w+)", line)
        if m:
            out["chain_ok"] = m.group(1) == "true"
        m = re.match(r"runtime_sha256:\s*([0-9a-fA-F]{16,})", line)
        if m:
            out["runtime_sha256"] = m.group(1)
    return out


def check_azure_node(endpoint):
    """Re-verify an Azure HCL evidence endpoint. Returns (verdict, detail, entry_fields)."""
    try:
        proc = subprocess.run(
            [UQ_BIN, "azure", "check", endpoint],
            capture_output=True, text=True, timeout=CHECK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "offline", f"no response within {CHECK_TIMEOUT}s", {}
    except FileNotFoundError:
        return "failed", f"verifier not found: {UQ_BIN}", {}

    combined = (proc.stderr or "") + "\n" + (proc.stdout or "")
    p = parse_azure_output(combined)
    fields = {
        "measurements": p["measurements"],
        "chain": "vTPM HCL → SNP report → VCEK → ASK → ARK-Milan (pinned)",
        "quote_signature": "verified" if p.get("sig") else "FAIL",
        "spki_binding": "report_data = sha256(runtime) → vTPM AK",
        "value_x": p.get("runtime_sha256"),
        "value_x_short": (p.get("runtime_sha256") or "")[:16] or None,
    }
    if proc.returncode == 0 and p.get("verdict") == "verified":
        return "verified", "vTPM SNP report re-verified against the AMD root (no MAA)", fields
    lowered = combined.lower()
    if any(s in lowered for s in ("connect", "refused", "timed out", "dns", "unreachable")):
        return "offline", "endpoint unreachable", fields
    err = [l.strip() for l in combined.splitlines() if l.strip()]
    return "failed", (err[-1][:200] if err else f"exit {proc.returncode}"), fields


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
        azure_endpoint = node.get("azure_endpoint")
        if azure_endpoint:
            # Azure CVM: evidence is a raw vTPM HCL blob, re-verified to the
            # AMD root with `uq azure check` (not attested-TLS `uq check`).
            verdict, detail, fields = check_azure_node(azure_endpoint)
            entry["verdict"] = verdict
            entry["detail"] = detail
            entry["checked_at"] = now_iso()
            entry["endpoint"] = azure_endpoint
            entry.update(fields)
            print(f"[report] {node['id']}: {verdict} ({detail})")
        elif endpoint:
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
            # No live endpoint. Honor a config-declared status/detail (e.g. a
            # known platform blocker or a planned node) instead of pretending
            # it is merely "awaiting" a report.
            if node.get("status"):
                entry["verdict"] = node["status"]
            if node.get("detail"):
                entry["detail"] = node["detail"]
            if node.get("measurement"):
                entry["measurements"] = {"MEASUREMENT": node["measurement"]}
            print(f"[report] {node['id']}: {entry['verdict']} (no endpoint)")

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

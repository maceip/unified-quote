#!/usr/bin/env python3
"""Collect the licenses of the modules actually linked into the adapter."""
import json
from pathlib import Path
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: notices.py OUTPUT_NOTICES")

packages = subprocess.check_output(
    ["go", "list", "-mod=readonly", "-deps", "-json", "./cmd/uq-google-attestation"],
    text=True,
)
decoder = json.JSONDecoder()
modules = {}
remaining = packages.lstrip()
while remaining:
    package, end = decoder.raw_decode(remaining)
    remaining = remaining[end:].lstrip()
    module = package.get("Module")
    if module and not module.get("Main"):
        source = module.get("Replace", module)
        modules[source["Path"]] = source

go_root = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
go_version = subprocess.check_output(["go", "env", "GOVERSION"], text=True).strip()
# The official archive keeps LICENSE at GOROOT; Homebrew installs the same
# license alongside its libexec directory. Missing license text fails the build.
go_license = next((file for file in (go_root / "LICENSE", go_root.parent / "LICENSE")
                   if file.is_file()), None)
if go_license is None:
    raise SystemExit(f"Missing Go runtime license in installation {go_root}")
notices = ["Third-party licenses for uq-google-attestation\n",
           f"\nGo runtime and standard library {go_version}\n\n{go_license.read_text()}\n"]
for name, module in sorted(modules.items()):
    directory = Path(module["Dir"])
    licenses = [directory / file for file in ("LICENSE", "LICENSE.txt", "LICENSE.md", "NOTICE")]
    licenses = [file for file in licenses if file.is_file()]
    if not licenses:
        raise SystemExit(f"Missing license for linked module {name}")
    notices.append(f"\n{name} {module.get('Version', '')}\n")
    for file in licenses:
        notices.append(f"\n{file.name}\n{file.read_text()}\n")
Path(sys.argv[1]).write_text("".join(notices))

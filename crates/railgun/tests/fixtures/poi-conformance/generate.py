#!/usr/bin/env python3
"""Project public synthetic proofs from a pinned checkout; no network or proving."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REVISION = "f1810f016e0a329a1b2d07da97668049351aa60d"
RETIRED = "b770ba7c05a5d33d904f518fd29dd05badd36008"
SOURCE_HASHES = {
    "ppoi_3x3.json": "257673031c42cd5660482076eacf525d3b8ce97f6fc141c3a4a5a4aaafc6d822",
    "ppoi_3x3_previous.json": "610423aabfedac9dae5511c23113518bcef4cb2ec543b9a4b2cb9adf9a934ecf",
    "ppoi_13x13_unshield.json": "bd702e0eb94da4b8152b03b5bb45f6091c5906e99f23852a9d7a4e50114f1c3d",
}


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate.py RAILGUN_RUST_CHECKOUT OUTPUT_DIRECTORY")
    source, output = map(Path, sys.argv[1:])
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if revision != REVISION:
        raise SystemExit("source checkout must be at the pinned revision")
    output.mkdir(parents=True, exist_ok=True)
    for name, destination in [
        ("ppoi_3x3.json", "current-3x3.json"),
        ("ppoi_3x3_previous.json", "retired-3x3.json"),
        ("ppoi_13x13_unshield.json", "current-13x13-unshield.json"),
    ]:
        raw = subprocess.check_output(["git", "show", f"{REVISION}:crates/core/tests/fixtures/{name}"], cwd=source)
        if hashlib.sha256(raw).hexdigest() != SOURCE_HASHES[name]:
            raise SystemExit(f"source digest mismatch: {name}")
        fixture = json.loads(raw)
        data = fixture["pre_tx_poi"].copy()
        proof = fixture["snarkjs_proof"]
        data["snarkProof"] = {"pi_a": proof["pi_a"][:2], "pi_b": proof["pi_b"][:2], "pi_c": proof["pi_c"][:2]}
        # This synthetic fixture index is not a public signal and is not checked
        # against a real indexer/list provider by the local service.
        data["txidMerklerootIndex"] = 0
        projected = {"inputCount": fixture["input_count"], "outputCount": fixture["output_count"], "proofData": data, "publicSignals": fixture["snarkjs_public_signals"]}
        (output / destination).write_text(json.dumps(projected, indent=2) + "\n")
    for revision, shape, destination in [
        (REVISION, "POI_3x3", "current-3x3-vkey.json"),
        (REVISION, "POI_13x13", "current-13x13-vkey.json"),
        (RETIRED, "POI_3x3", "retired-3x3-vkey.json"),
    ]:
        raw = subprocess.check_output(["git", "show", f"{revision}:crates/core/resources/poi/{shape}/vkey.json"], cwd=source)
        (output / destination).write_bytes(raw)
    license_bytes = subprocess.check_output(["git", "show", f"{REVISION}:LICENSE"], cwd=source)
    (output / "LICENSE.railgun-rust").write_bytes(license_bytes)


if __name__ == "__main__":
    main()

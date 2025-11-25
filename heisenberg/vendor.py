# heisenberg/vendor.py

import csv
import os
import argparse

from .config import Settings
from .bulk_check import process_tasks, CSV_HEADER
from .sbom_parser import parse_sbom


_settings = Settings()
OUTPUT_CSV = _settings.output_csv


def add_arguments(parser):
    parser.add_argument("--sbom-file", required=True, help="Path to vendor SBOM file (CycloneDX/SPDX/CSV)")
    parser.add_argument("-o", "--output", "--out", dest="output", default=OUTPUT_CSV, help="Output CSV path")
    parser.add_argument("--vendor-name", help="Optional vendor name (used as repo_name in output)")


def parse_cli():
    p = argparse.ArgumentParser(description="Assess vendor/third-party SBOM health.")
    add_arguments(p)
    return p.parse_args()


def main(args=None):
    if args is None:
        args = parse_cli()
    
    print(f"[INFO] Processing vendor SBOM: {args.sbom_file}")
    
    vendor_name = args.vendor_name
    if not vendor_name:
        vendor_name = os.path.splitext(os.path.basename(args.sbom_file))[0]
    
    try:
        packages = parse_sbom(args.sbom_file)
        print(f"[INFO] Found {len(packages)} packages in SBOM")
    except Exception as e:
        print(f"[ERROR] Failed to parse SBOM: {e}")
        return
    
    tasks = []
    for pkg in packages:
        if pkg['ecosystem'] == "unknown":
            print(f"[WARN] Skipping {pkg['name']} - unknown ecosystem")
            continue
        
        print(f"Queueing: {pkg['name']} {pkg['version']} ({pkg['ecosystem']})")
        tasks.append((vendor_name, pkg['name'], pkg['version'], pkg['ecosystem'], pkg['license']))
    
    if not tasks:
        print("[WARN] No valid packages to process")
        return
    
    with open(args.output, "w", newline="", encoding="utf-8") as out_csv:
        writer = csv.writer(out_csv)
        writer.writerow(CSV_HEADER)
        process_tasks(tasks, writer)
    
    print(f"[INFO] Done. Vendor assessment saved to {args.output}")


def cli(args=None):
    return main(args)


if __name__ == "__main__":
    main()



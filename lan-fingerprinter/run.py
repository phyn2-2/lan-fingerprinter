"""
run.py — Entry point for lan-fingerprinter
Phase 4: supports --export flag for JSON/CSV export
"""

import os
import sys
import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        prog="lan-fingerprinter",
        description="Passive LAN device fingerprinter — ARP, ICMP, DHCP, DNS.",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help=(
            "Export all known devices to a file and exit. "
            "Format is inferred from extension: .json or .csv. "
            "Example: --export devices.json"
        ),
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="Force export format (json or csv). Overrides file extension.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    # Always run from project root so config.yaml and relative paths resolve
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    args = parse_args()

    from src.main import main
    main(args)

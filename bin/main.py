#!/usr/bin/env python3
"""
Main entry point for the Discrepancy Checker tool.

This script provides command-line interface for comparing JSON files representing
system states from hypervisor and in-guest perspectives.
"""

import argparse
import os
import sys
from pathlib import Path

from discrepancy_checker.differ import differ, differ_all

# Add src/ to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))


def main():
    """Main function to handle command-line arguments and execute comparison."""
    parser = argparse.ArgumentParser(
        description="Compare JSON files representing system states from hypervisor and in-guest perspectives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare single files
  python main.py --hypervisor hypervisor_state.json --guest guest_state.json

  # Compare all files in directories
  python main.py --hypervisor /path/to/hypervisor/dir --guest /path/to/guest/dir -d
        """,
    )
    print(r"""
     _____  _  __  __    _____ _               _
    |  __ \(_)/ _|/ _|  / ____| |             | |
    | |  | |_| |_| |_  | |    | |__   ___  ___| | _____ _ __
    | |  | | |  _|  _| | |    | '_ \ / _ \/ __| |/ / _ \ '__|
    | |__| | | | | |   | |____| | | |  __/ (__|   <  __/ |
    |_____/|_|_| |_|    \_____|_| |_|\___|\___|_|\_\___|_|
    """)

    parser.add_argument(
        "--hypervisor",
        dest="hypervisor_path",
        required=True,
        help="Path to hypervisor JSON file or directory (when using -d flag)",
    )

    parser.add_argument(
        "-g",
        "--guest",
        dest="guest_path",
        required=True,
        help="Path to guest JSON file or directory (when using -d flag)",
    )

    parser.add_argument(
        "-d", "--directory", action="store_true", help="Compare all files in directories instead of single files"
    )

    args = parser.parse_args()

    # Convert paths to Path objects
    hypervisor_path = Path(args.hypervisor_path)
    guest_path = Path(args.guest_path)

    try:
        if args.directory:
            # Directory comparison mode
            print("Comparing directories:")
            print(f" - Hypervisor: {hypervisor_path}")
            print(f" - Guest: {guest_path}")
            print("-" * 50)
            differ_all(hypervisor_path, guest_path)
        else:
            # Single file comparison mode
            print("Comparing files:")
            print(f" - Hypervisor: {hypervisor_path}")
            print(f" - Guest: {guest_path}")
            print("-" * 50)
            differ(hypervisor_path, guest_path)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

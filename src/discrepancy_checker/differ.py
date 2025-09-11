"""
This file contains functions to compare JSON files representing system states from hypervisor and in-guest perspectives.
"""
from deepdiff import DeepDiff
from pathlib import Path
import os
import json


def differ(json_hypervisor_state: Path, json_in_guest_state: Path) -> None:
    """
    Read both input json provided (check if they exist) and compare their keys
    """
    if not os.path.exists(json_hypervisor_state):
        raise FileNotFoundError(f"File {json_hypervisor_state} does not exist.")
    if not os.path.exists(json_in_guest_state):
        raise FileNotFoundError(f"File {json_in_guest_state} does not exist.")

    with (
        open(json_hypervisor_state, "r") as file_1,
        open(json_in_guest_state, "r") as file_2,
    ):
        hypervisor_data = json.load(file_1)
        guest_data = json.load(file_2)

        diff = DeepDiff(hypervisor_data, guest_data, ignore_order=True)
        if diff:
            print("Differences found:")
            print(diff)
        else:
            print("No differences found.")


def differ_all(json_hypervisor_state: Path, json_in_guest_state: Path) -> None:
    """
    Compare all files in a directory with higher matched prefix in their names. e.g. ebpf_trace_1111.json, ebpf_trace_2222.json
    """

    if not os.path.exists(json_hypervisor_state):
        raise FileNotFoundError(f"Directory {json_hypervisor_state} does not exist.")
    if not os.path.exists(json_in_guest_state):
        raise FileNotFoundError(f"Directory {json_in_guest_state} does not exist.")

    hypervisor_files = sorted(Path(json_hypervisor_state).glob("*.json"))
    guest_files = sorted(Path(json_in_guest_state).glob("*.json"))

    for hypervisor_file in hypervisor_files:
        matched_guest_file = None
        for guest_file in guest_files:
            # Greedy match based on prefix before the first underscore.
            if hypervisor_file.stem.split("_")[0] == guest_file.stem.split("_")[0]:
                matched_guest_file = guest_file
                break

        if matched_guest_file:
            print(f"Comparing {hypervisor_file} with {matched_guest_file}")
            differ(hypervisor_file, matched_guest_file)
        else:
            print(f"No matching guest file found for {hypervisor_file}")


if __name__ == "__main__":
    pass

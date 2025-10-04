"""
This file contains functions to compare JSON files representing system states from hypervisor and in-guest perspectives.
"""

from deepdiff import DeepDiff
from pathlib import Path
import os
import json


def differ(json_hypervisor_state: Path, json_in_guest_state: Path) -> None:
    """Read both input json provided (check if they exist) and compare their keys. Print the differences if any.

    Raises:
        FileNotFoundError: If either the hypervisor or in-guest JSON file does not exist.
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

        # Print summary first
        print_summary(hypervisor_data, guest_data)
        
        # Normalize data to focus only on essential process fields
        print("\nProcess comparison (pid, name, state):")
        hv_normalized = normalize_data_for_comparison(hypervisor_data)
        guest_normalized = normalize_data_for_comparison(guest_data)
        
        # Use DeepDiff on normalized data
        diff = DeepDiff(hv_normalized, guest_normalized, ignore_order=True)
        
        if diff:
            print("Differences found in process essentials:")
            analyze_normalized_differences(diff, hv_normalized, guest_normalized)
        else:
            print("✅ No differences found in process essentials (pid, name, state)")


def print_summary(hypervisor_data: dict, guest_data: dict) -> None:
    """Print summary information about the data."""
    print("\nSummary:")
    
    # Extract basic info
    hv_timestamp = hypervisor_data.get('timestamp', 'N/A')
    guest_timestamp = guest_data.get('timestamp', 'N/A')
    
    hv_subtype = hypervisor_data.get('metadata', {}).get('subtype', 'N/A')
    guest_subtype = guest_data.get('metadata', {}).get('subtype', 'N/A')
    
    print(f"Hypervisor timestamp: {hv_timestamp}")
    print(f"Guest timestamp: {guest_timestamp}")
    print(f"Hypervisor subtype: {hv_subtype}")
    print(f"Guest subtype: {guest_subtype}")
    
    # Process counts
    hv_processes = get_process_list(hypervisor_data)
    guest_processes = get_process_list(guest_data)
    
    print(f"Hypervisor processes: {len(hv_processes)}")
    print(f"Guest processes: {len(guest_processes)}")


def get_process_list(data: dict) -> list:
    """Extract process list from data structure."""
    # Handle different data structures
    if 'data' in data and 'process_list' in data['data'] and 'processes' in data['data']['process_list']:
        return data['data']['process_list']['processes']
    elif 'data' in data and 'processes' in data['data']:
        return data['data']['processes']
    elif 'process_list' in data and 'processes' in data['process_list']:
        return data['process_list']['processes']
    elif 'processes' in data:
        return data['processes']
    else:
        return []


def normalize_process(process: dict) -> dict:
    """Extract only essential fields from a process: pid, name."""
    return {
        'pid': process.get('pid'),
        'name': process.get('name')
    }


def normalize_data_for_comparison(data: dict) -> dict:
    """Normalize data structure to focus only on essential process fields."""
    processes = get_process_list(data)
    
    # Normalize processes to only essential fields and create dict keyed by PID
    normalized_processes = {}
    for process in processes:
        if process.get('pid') is not None:
            pid = process['pid']
            normalized_processes[pid] = normalize_process(process)
    
    return {
        'processes': normalized_processes,
        'count': len(normalized_processes)
    }


def analyze_normalized_differences(diff: dict, hv_data: dict, guest_data: dict) -> None:
    """Analyze differences in normalized process data - focus on missing/extra processes."""
    
    # Show process count differences first
    hv_count = hv_data.get('count', 0)
    guest_count = guest_data.get('count', 0)
    print(f"\nProcess counts: Hypervisor={hv_count}, Guest={guest_count}")
    
    # Focus only on missing/extra processes
    if 'dictionary_item_added' in diff:
        print("\nExtra processes in guest:")
        for path in diff['dictionary_item_added']:
            if 'processes' in path:
                pid = path.split('[')[-1].split(']')[0]
                process_info = guest_data['processes'].get(int(pid), {})
                name = process_info.get('name', 'Unknown')
                print(f"- PID {pid}: {name}")
    
    if 'dictionary_item_removed' in diff:
        print("\nMissing processes in guest:")
        for path in diff['dictionary_item_removed']:
            if 'processes' in path:
                pid = path.split('[')[-1].split(']')[0]
                process_info = hv_data['processes'].get(int(pid), {})
                name = process_info.get('name', 'Unknown')
                print(f"- PID {pid}: {name}")
    
    extra_in_guest = len(diff.get('dictionary_item_added', []))
    missing_in_guest = len(diff.get('dictionary_item_removed', []))
    total_differences = extra_in_guest + missing_in_guest
    
    print(f"\nSUMMARY:")
    print(f"Extra processes in guest: {extra_in_guest}")
    print(f"Missing processes in guest: {missing_in_guest}")
    print(f"Total process discrepancies: {total_differences}")
    
    if total_differences == 0:
        print("✅ No process discrepancies found")
    else:
        print("⚠️  Process discrepancies detected")


def analyze_differences(diff: dict, hypervisor_data: dict, guest_data: dict) -> None:
    """Analyze and present differences in a more readable format."""
    
    # Handle different types of differences
    if 'values_changed' in diff:
        print("\nVALUE CHANGES:")
        for path, change in diff['values_changed'].items():
            if 'processes' in path.lower() or 'data' in path.lower():
                # This is likely a process-related change
                print(f"Process data structure change: {path}")
                print(f"  Old: {change.get('old_value', 'N/A')}")
                print(f"  New: {change.get('new_value', 'N/A')}")
            else:
                print(f"{path}: {change.get('old_value')} -> {change.get('new_value')}")
    
    if 'dictionary_item_added' in diff:
        print("\nADDED ITEMS:")
        for path in diff['dictionary_item_added']:
            print(f"Added: {path}")
    
    if 'dictionary_item_removed' in diff:
        print("\nREMOVED ITEMS:")
        for path in diff['dictionary_item_removed']:
            print(f"Removed: {path}")
    
    if 'iterable_item_added' in diff:
        print("\nADDED ITEMS IN LISTS:")
        for path, items in diff['iterable_item_added'].items():
            print(f"Added to {path}: {items}")
    
    if 'iterable_item_removed' in diff:
        print("\nREMOVED ITEMS FROM LISTS:")
        for path, items in diff['iterable_item_removed'].items():
            print(f"Removed from {path}: {items}")
    
    # Analyze process-specific differences
    analyze_process_differences(hypervisor_data, guest_data)


def analyze_process_differences(hypervisor_data: dict, guest_data: dict) -> None:
    """Analyze process-specific differences."""
    print("\nPROCESS ANALYSIS:")
    
    hv_processes = get_process_list(hypervisor_data)
    guest_processes = get_process_list(guest_data)
    
    if not hv_processes or not guest_processes:
        print("Could not extract process lists from data structures.")
        return
    
    # Create dictionaries keyed by PID for easier comparison
    hv_by_pid = {p.get('pid'): p for p in hv_processes if 'pid' in p}
    guest_by_pid = {p.get('pid'): p for p in guest_processes if 'pid' in p}
    
    hv_pids = set(hv_by_pid.keys())
    guest_pids = set(guest_by_pid.keys())
    
    # Find missing processes
    missing_in_guest = hv_pids - guest_pids
    missing_in_hypervisor = guest_pids - hv_pids
    
    if missing_in_guest:
        print(f"\nProcesses in hypervisor but NOT in guest ({len(missing_in_guest)}):")
        for pid in sorted(missing_in_guest):
            process = hv_by_pid[pid]
            name = process.get('name', 'Unknown')
            print(f"- PID {pid}: {name}")
    
    if missing_in_hypervisor:
        print(f"\nProcesses in guest but NOT in hypervisor ({len(missing_in_hypervisor)}):")
        for pid in sorted(missing_in_hypervisor):
            process = guest_by_pid[pid]
            name = process.get('name', 'Unknown')
            print(f"- PID {pid}: {name}")
    
    # Find common processes and check for key differences
    common_pids = hv_pids & guest_pids
    if common_pids:
        print(f"\nCommon processes with differences ({len(common_pids)}):")
        differences_found = False
        
        for pid in sorted(common_pids):
            hv_proc = hv_by_pid[pid]
            guest_proc = guest_by_pid[pid]
            
            # Compare key fields
            differences = []
            for field in ['name', 'state']:
                if hv_proc.get(field) != guest_proc.get(field):
                    differences.append(f"{field}: {hv_proc.get(field)} -> {guest_proc.get(field)}")
            
            if differences:
                differences_found = True
                print(f"- PID {pid} ({hv_proc.get('name', 'Unknown')}):")
                for diff in differences:
                    print(f"    {diff}")
        
        if not differences_found:
            print("No field differences found in common processes.")


def differ_all(json_hypervisor_state: Path, json_in_guest_state: Path) -> None:
    """Compare all files in a directory with higher matched prefix in their names. e.g. ebpf_trace_1111.json, ebpf_trace_2222.json

    Raises:
        FileNotFoundError: if either hypervisor or in-guest directory does not exist.
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

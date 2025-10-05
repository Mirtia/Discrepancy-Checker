"""
This file contains functions to compare JSON files representing system states from hypervisor and in-guest perspectives.
"""

import json
import os
from pathlib import Path

from deepdiff import DeepDiff


def differ(json_hypervisor_state: Path, json_in_guest_state: Path) -> None:
    """Read both input json provided (check if they exist) and compare their keys. Print the differences if any.

    Raises:
        FileNotFoundError: If either the hypervisor or in-guest JSON file does not exist.
    """
    if not os.path.exists(json_hypervisor_state):
        raise FileNotFoundError(
            f"File {json_hypervisor_state} does not exist.")
    if not os.path.exists(json_in_guest_state):
        raise FileNotFoundError(f"File {json_in_guest_state} does not exist.")

    with (
        open(json_hypervisor_state) as file_1,
        open(json_in_guest_state) as file_2,
    ):
        hypervisor_data = json.load(file_1)
        guest_data = json.load(file_2)

        # Print summary first
        print_summary(hypervisor_data, guest_data)

        # Check data type and compare accordingly
        hv_metadata = hypervisor_data.get("metadata", {})
        guest_metadata = guest_data.get("metadata", {})

        hv_subtype = hv_metadata.get("subtype", "")
        guest_subtype = guest_metadata.get("subtype", "")

        # Check if this is network data
        if (
            "NETWORK" in hv_subtype.upper()
            or "NETWORK" in guest_subtype.upper()
            or "TCP" in hv_subtype.upper()
            or "TCP" in guest_subtype.upper()
        ):
            compare_network_data(hypervisor_data, guest_data)
        else:
            # Default to process comparison
            print("\nProcess comparison (pid, name, state)...")
            hv_normalized = normalize_data_for_comparison(hypervisor_data)
            guest_normalized = normalize_data_for_comparison(guest_data)

            # Use DeepDiff with nested structure comparison
            diff = compare_nested_structures(
                hv_normalized, guest_normalized, "processes")

            if diff:
                analyze_normalized_differences(
                    diff, hv_normalized, guest_normalized)
            else:
                print("✅ No differences found in process essentials (pid, name, state)")


def print_summary(hypervisor_data: dict, guest_data: dict) -> None:
    """Print summary information about the data."""
    print("\nSummary:")

    # Extract basic info
    hv_timestamp = hypervisor_data.get("timestamp", "N/A")
    guest_timestamp = guest_data.get("timestamp", "N/A")

    hv_subtype = hypervisor_data.get("metadata", {}).get("subtype", "N/A")
    guest_subtype = guest_data.get("metadata", {}).get("subtype", "N/A")

    print(f" - Hypervisor timestamp: {hv_timestamp}")
    print(f" - Guest timestamp: {guest_timestamp}")
    print(f" - Hypervisor subtype: {hv_subtype}")
    print(f" - Guest subtype: {guest_subtype}")

    # Process counts
    hv_processes = get_process_list(hypervisor_data)
    guest_processes = get_process_list(guest_data)

    print(f" - Hypervisor processes: {len(hv_processes)}")
    print(f" - Guest processes: {len(guest_processes)}")


def get_process_list(data: dict) -> list:
    """Extract process list from data structure."""
    # Handle different data structures
    if "data" in data and "process_list" in data["data"] and "processes" in data["data"]["process_list"]:
        return data["data"]["process_list"]["processes"]
    elif "data" in data and "processes" in data["data"]:
        return data["data"]["processes"]
    elif "process_list" in data and "processes" in data["process_list"]:
        return data["process_list"]["processes"]
    elif "processes" in data:
        return data["processes"]
    else:
        return []


def normalize_process(process: dict) -> dict:
    """Extract only essential fields from a process: pid, name, is_kernel_thread."""
    return {
        "pid": process.get("pid"),
        "name": process.get("name"),
        "is_kernel_thread": process.get("is_kernel_thread", True),
    }


def normalize_data_for_comparison(data: dict) -> dict:
    """Normalize data structure to focus only on essential process fields."""
    processes = get_process_list(data)

    # Normalize processes to only essential fields and create dict keyed by PID
    normalized_processes = {}
    for process in processes:
        if process.get("pid") is not None:
            pid = process["pid"]
            normalized_processes[pid] = normalize_process(process)

    return {"processes": normalized_processes, "count": len(normalized_processes)}


def compare_same_level_fields(hv_data: dict, guest_data: dict) -> dict:
    """Compare nested objects at same structural level using DeepDiff."""

    # Use DeepDiff directly on the full nested data structures
    # This will compare at the same structural level automatically
    diff = DeepDiff(
        hv_data,
        guest_data,
        ignore_order=True,
        # Focus on structural differences at each level
        exclude_paths=[
            "root['count']",  # Ignore count differences
        ],
        # DeepDiff will automatically handle nested comparisons
        # and show differences at the appropriate structural level
    )

    return diff


def compare_nested_structures(hv_data: dict, guest_data: dict, level: str = "processes") -> dict:
    """Compare nested structures at a specific level using DeepDiff."""

    # Extract the specific nested level for comparison
    if level == "processes":
        hv_target = hv_data.get("processes", {})
        guest_target = guest_data.get("processes", {})
    else:
        # For other levels, you can specify the path
        hv_target = hv_data
        guest_target = guest_data

    # Use DeepDiff with nested object support
    # DeepDiff automatically handles nested comparisons and shows differences
    # at the appropriate structural level
    diff = DeepDiff(
        hv_target,
        guest_target,
        ignore_order=True,
        # DeepDiff will show differences at each nested level
        # For example: missing/added processes, changed process fields, etc.
    )

    return diff


def compare_with_field_filtering(hv_data: dict, guest_data: dict, fields_to_compare: list = None) -> dict:
    """Compare nested structures with specific field filtering using DeepDiff."""

    if fields_to_compare is None:
        fields_to_compare = ["pid", "name"]

    # Create filtered versions for comparison
    hv_filtered = {}
    guest_filtered = {}

    # Filter processes to only include specified fields
    for pid, process in hv_data.get("processes", {}).items():
        hv_filtered[pid] = {field: process.get(
            field) for field in fields_to_compare}

    for pid, process in guest_data.get("processes", {}).items():
        guest_filtered[pid] = {field: process.get(
            field) for field in fields_to_compare}

    # Use DeepDiff on the filtered nested structures
    diff = DeepDiff(
        hv_filtered,
        guest_filtered,
        ignore_order=True,
        # DeepDiff will handle the nested structure and show differences
        # at the appropriate level (missing processes, field changes, etc.)
    )

    return diff


def analyze_normalized_differences(diff: dict, hv_data: dict, guest_data: dict) -> None:
    """Analyze differences in normalized process data - focus on missing/extra processes."""

    # Show process count differences first
    hv_count = hv_data.get("count", 0)
    guest_count = guest_data.get("count", 0)
    # print(f"\nProcess counts: Hypervisor={hv_count}, Guest={guest_count}")

    # Focus only on missing/extra processes
    if "dictionary_item_added" in diff:
        danger_processes = []
        normal_processes = []

        for path in diff["dictionary_item_added"]:
            # Extract PID from path like "root[2097]"
            if "root[" in path:
                pid_str = path.split("[")[-1].split("]")[0].strip("'\"")
                try:
                    pid = int(pid_str)
                    process_info = guest_data["processes"].get(pid, {})
                    name = process_info.get("name", "Unknown")
                    is_kernel_thread = process_info.get(
                        "is_kernel_thread", False)

                    # Check if this is a dangerous user-level process hidden from hypervisor
                    # For guest data, we need to infer if it's a kernel thread by name patterns
                    is_likely_kernel = (
                        name.startswith("kworker/")
                        or name.startswith("rcu_")
                        or name.startswith("swapper/")
                        or name.startswith("kthreadd")
                        or name.startswith("migration/")
                        or name.startswith("ksoftirqd/")
                    )

                    if not is_likely_kernel:
                        danger_processes.append((pid, name, process_info))
                    else:
                        normal_processes.append((pid, name, process_info))

                except ValueError:
                    print(f"  Could not parse PID from: {path}")

        # Only show sections if there's content
        if danger_processes:
            print("\n--- Extra processes in guest ---")
            print("User-level processes hidden from hypervisor:")
            for pid, name, process_info in danger_processes:
                print(
                    f"  - PID {pid}: {name} (user-level hidden from hypervisor)")
                if "credentials" in process_info:
                    creds = process_info["credentials"]
                    print(
                        f"    UID: {creds.get('uid', 'N/A')}, GID: {creds.get('gid', 'N/A')}")

        # Hide normal processes (kernel processes are not security concerns)

    if "dictionary_item_removed" in diff:
        danger_missing = []
        normal_missing = []

        for path in diff["dictionary_item_removed"]:
            # Extract PID from path like "root[2097]"
            if "root[" in path:
                pid_str = path.split("[")[-1].split("]")[0].strip("'\"")
                try:
                    pid = int(pid_str)
                    process_info = hv_data["processes"].get(pid, {})
                    name = process_info.get("name", "Unknown")
                    is_kernel_thread = process_info.get(
                        "is_kernel_thread", True)

                    # Check if this is a dangerous user-level process missing from guest
                    # For hypervisor data, we have the is_kernel_thread field
                    if not is_kernel_thread:
                        danger_missing.append((pid, name, process_info))
                    else:
                        normal_missing.append((pid, name, process_info))

                except ValueError:
                    print(f"  Could not parse PID from: {path}")

        # Only show sections if there's content
        if danger_missing:
            print("\n--- Missing processes in guest ---")
            print("User-level processes hidden from guest:")
            for pid, name, process_info in danger_missing:
                print(
                    f"\033[91m  - PID {pid}: {name} (user-level hidden from guest)\033[0m")
                if "credentials" in process_info:
                    creds = process_info["credentials"]
                    print(
                        f"    UID: {creds.get('uid', 'N/A')}, GID: {creds.get('gid', 'N/A')}")

        # Hide normal kernel processes (not security concerns)

    # Count total differences and danger levels
    extra_in_guest = len(diff.get("dictionary_item_added", []))
    missing_in_guest = len(diff.get("dictionary_item_removed", []))
    total_differences = extra_in_guest + missing_in_guest

    # Count dangerous processes (user-level hidden/missing)
    danger_extra = 0
    danger_missing = 0

    # Count dangerous extra processes (user-level processes in guest but not hypervisor)
    for path in diff.get("dictionary_item_added", []):
        if "root[" in path:
            try:
                pid_str = path.split("[")[-1].split("]")[0].strip("'\"")
                pid = int(pid_str)
                process_info = guest_data["processes"].get(pid, {})
                name = process_info.get("name", "Unknown")

                # Infer if it's a kernel thread by name patterns
                is_likely_kernel = (
                    name.startswith("kworker/")
                    or name.startswith("rcu_")
                    or name.startswith("swapper/")
                    or name.startswith("kthreadd")
                    or name.startswith("migration/")
                    or name.startswith("ksoftirqd/")
                )

                if not is_likely_kernel:
                    danger_extra += 1
            except (ValueError, KeyError):
                pass

    # Count dangerous missing processes (user-level processes in hypervisor but not guest)
    for path in diff.get("dictionary_item_removed", []):
        if "root[" in path:
            try:
                pid_str = path.split("[")[-1].split("]")[0].strip("'\"")
                pid = int(pid_str)
                process_info = hv_data["processes"].get(pid, {})

                # Use the is_kernel_thread field from hypervisor data
                if not process_info.get("is_kernel_thread", True):
                    danger_missing += 1
            except (ValueError, KeyError):
                pass

    print("\nSummary:")
    print(f"- Extra processes in guest: {extra_in_guest}")
    print(f"- Missing processes in guest: {missing_in_guest}")
    print(f"- Total process discrepancies: {total_differences}")

    if danger_extra > 0 or danger_missing > 0:
        print(
            f"\033[93m\nSecurity analysis: {danger_extra + danger_missing} user-level processes with stealth behavior\033[0m"
        )
        print(
            f"\033[93m  - {danger_extra} user processes hidden from hypervisor\033[0m")
        print(
            f"\033[93m  - {danger_missing} user processes hidden from guest\033[0m")
    elif total_differences > 0:
        print("Process discrepancies detected (kernel-level only)")
    else:
        print("No process discrepancies found")


def analyze_differences(diff: dict, hypervisor_data: dict, guest_data: dict) -> None:
    """Analyze and present differences in a more readable format."""

    # Handle different types of differences
    if "values_changed" in diff:
        print("\nValue changes:")
        for path, change in diff["values_changed"].items():
            if "processes" in path.lower() or "data" in path.lower():
                # This is likely a process-related change
                print(f"Process data structure change: {path}")
                print(f"- Old: {change.get('old_value', 'N/A')}")
                print(f"- New: {change.get('new_value', 'N/A')}")
            else:
                print(
                    f"{path}: {change.get('old_value')} -> {change.get('new_value')}")

    if "dictionary_item_added" in diff:
        print("\nAdded items:")
        for path in diff["dictionary_item_added"]:
            print(f"Added: {path}")

    if "dictionary_item_removed" in diff:
        print("\nRemoved items:")
        for path in diff["dictionary_item_removed"]:
            print(f"Removed: {path}")

    if "iterable_item_added" in diff:
        print("\nAdded items in lists:")
        for path, items in diff["iterable_item_added"].items():
            print(f"Added to {path}: {items}")

    if "iterable_item_removed" in diff:
        print("\nRemoved items from lists:")
        for path, items in diff["iterable_item_removed"].items():
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
    hv_by_pid = {p.get("pid"): p for p in hv_processes if "pid" in p}
    guest_by_pid = {p.get("pid"): p for p in guest_processes if "pid" in p}

    hv_pids = set(hv_by_pid.keys())
    guest_pids = set(guest_by_pid.keys())

    # Find missing processes
    missing_in_guest = hv_pids - guest_pids
    missing_in_hypervisor = guest_pids - hv_pids

    if missing_in_guest:
        print(
            f"\nProcesses in hypervisor but not in guest ({len(missing_in_guest)}):")
        for pid in sorted(missing_in_guest):
            process = hv_by_pid[pid]
            name = process.get("name", "Unknown")
            print(f"- PID {pid}: {name}")

    if missing_in_hypervisor:
        print(
            f"\nProcesses in guest but not in hypervisor ({len(missing_in_hypervisor)}):")
        for pid in sorted(missing_in_hypervisor):
            process = guest_by_pid[pid]
            name = process.get("name", "Unknown")
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
            for field in ["name", "state"]:
                if hv_proc.get(field) != guest_proc.get(field):
                    differences.append(
                        f"{field}: {hv_proc.get(field)} -> {guest_proc.get(field)}")

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
        raise FileNotFoundError(
            f"Directory {json_hypervisor_state} does not exist.")
    if not os.path.exists(json_in_guest_state):
        raise FileNotFoundError(
            f"Directory {json_in_guest_state} does not exist.")

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


def compare_network_data(hypervisor_data: dict, guest_data: dict) -> None:
    """Compare network trace data between hypervisor and guest."""
    print("\nNetwork trace comparison...")

    # Extract network data
    hv_network = hypervisor_data.get("data", {}).get("network_trace", {})
    guest_network = guest_data.get("data", {}).get("network_trace", {})

    # Get TCP sockets
    hv_sockets = hv_network.get("tcp_sockets", {}).get("sockets", [])
    guest_sockets = guest_network.get("tcp_sockets", {}).get("sockets", [])

    print(f" - Hypervisor connections: {len(hv_sockets)}")
    print(f" - Guest connections: {len(guest_sockets)}")

    # Simple comparison - just show the differences
    hv_connections = set()
    guest_connections = set()

    # Create connection identifiers
    for socket in hv_sockets:
        conn_id = f"{socket.get('local_ip', '')}:{socket.get('local_port', '')}->{socket.get('remote_ip', '')}:{socket.get('remote_port', '')}"
        hv_connections.add(conn_id)

    for socket in guest_sockets:
        conn_id = f"{socket.get('local_ip', '')}:{socket.get('local_port', '')}->{socket.get('remote_ip', '')}:{socket.get('remote_port', '')}"
        guest_connections.add(conn_id)

    # Find differences
    extra_in_guest = guest_connections - hv_connections
    missing_in_guest = hv_connections - guest_connections

    if extra_in_guest:
        print("\n--- Extra connections in guest ---")
        for conn in extra_in_guest:
            print(f"  - {conn} (hidden from hypervisor)")

    if missing_in_guest:
        print("\n--- Missing connections in guest ---")
        for conn in missing_in_guest:
            print(f"\033[91m  - {conn} (hidden from guest)\033[0m")

    # Count suspicious connections
    hv_suspicious = 0
    guest_suspicious = 0

    # Count suspicious connections in hypervisor data
    for socket in hv_sockets:
        if socket.get('is_suspicious', False):
            hv_suspicious += 1

    # Count suspicious connections in guest data
    for socket in guest_sockets:
        if socket.get('is_suspicious', False):
            guest_suspicious += 1

    # Summary
    total_differences = len(extra_in_guest) + len(missing_in_guest)
    print("\nSummary:")
    print(f"- Extra connections in guest: {len(extra_in_guest)}")
    print(f"- Missing connections in guest: {len(missing_in_guest)}")
    print(f"- Total network discrepancies: {total_differences}")

    # Security analysis
    if hv_suspicious > 0 or guest_suspicious > 0:
        print(
            f"\033[93m\nSecurity analysis: Suspicious network activity detected\033[0m")
        print(
            f"\033[93m  - {hv_suspicious} suspicious connections in hypervisor view\033[0m")
        print(
            f"\033[93m  - {guest_suspicious} suspicious connections in guest view\033[0m")
        print(
            "\033[93m  Potential security concern: Network activity discrepancies\033[0m")
    elif total_differences > 0:
        print("\nNetwork discrepancies detected")
    else:
        print("✅ No network discrepancies found")


if __name__ == "__main__":
    pass

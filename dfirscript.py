import subprocess
import os
import sys
import csv

if len(sys.argv) != 3:
    print("Usage: python3 analyze_memory.py <memory_dump_file> <profile>")
    sys.exit(1)

MEMORY_IMAGE = sys.argv[1]
PROFILE = sys.argv[2]
BASENAME = os.path.splitext(os.path.basename(MEMORY_IMAGE))[0]

if not os.path.exists(MEMORY_IMAGE):
    print(f"Error: Memory dump '{MEMORY_IMAGE}' not found.")
    sys.exit(1)

def run_plugin(plugin_name, output_file):
    command = ["vol", "-f", MEMORY_IMAGE, "--profile", PROFILE, plugin_name]
    print(f"[+] Running: {' '.join(command)}")
    with open(output_file, "w") as f:
        subprocess.run(command, stdout=f, stderr=subprocess.DEVNULL)

def convert_to_csv(input_file, output_csv):
    with open(input_file, "r", errors='ignore') as infile, open(output_csv, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        for line in infile:
            if line.strip() and not line.startswith("Volatility"):
                writer.writerow(line.strip().split())

def extract_pids_dynamic(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        lines = [line for line in f if line.strip() and "Volatility" not in line]
    
    header_line = None
    for line in lines:
        if "PID" in line and "PPID" in line:
            header_line = line
            break
    
    if not header_line:
        print(f"[!] No valid header found in {filepath}")
        return set()
    
    header = header_line.strip().split()
    try:
        pid_index = header.index("PID")
    except ValueError:
        print(f"[!] 'PID' not found in header of {filepath}")
        return set()
    
    pids = set()
    for line in lines:
        if line.strip() == header_line.strip():
            continue
        parts = line.strip().split()
        if len(parts) > pid_index and parts[pid_index].isdigit():
            pids.add(int(parts[pid_index]))
    
    return pids

def find_hidden_processes(pslist_file, psscan_file, output_file):
    pslist_pids = extract_pids_dynamic(pslist_file)
    psscan_pids = extract_pids_dynamic(psscan_file)
    hidden = psscan_pids - pslist_pids

    with open(output_file, "w") as f:
        f.write("=== Hidden Processes Detected (in psscan but not in pslist) ===\n\n")
        if hidden:
            for pid in sorted(hidden):
                f.write(f"PID: {pid}\n")
        else:
            f.write("None detected.\n")

def extract_injected_dlls(ldrmodules_file, output_file):
    results = []
    with open(ldrmodules_file, "r", errors='ignore') as f:
        for line in f:
            if "False" in line:
                results.append(line.strip())
    with open(output_file, "w") as f:
        f.write("=== Injected DLLs Detected ===\n\n")
        if results:
            for r in results:
                f.write(r + "\n")
        else:
            f.write("None detected.\n")

def extract_suspicious_processes(pslist_file, malfind_file, dlllist_file, output_file):
    processes = []
    header = None

    with open(pslist_file, "r", errors='ignore') as f:
        lines = [line for line in f if line.strip()]
        for line in lines:
            if "PID" in line and "PPID" in line:
                header = line.strip().split()
                break

        if not header:
            print("[!] Could not find pslist header.")
            return

        try:
            pid_idx = header.index("PID")
            ppid_idx = header.index("PPID")
            name_idx = 0
        except ValueError:
            print("[!] PID or PPID not found in pslist header.")
            return

        for line in lines:
            if any(col in line for col in header):
                continue
            parts = line.strip().split()
            if len(parts) > max(pid_idx, ppid_idx):
                try:
                    pid = int(parts[pid_idx])
                    ppid = int(parts[ppid_idx])
                    name = parts[name_idx]
                    processes.append((pid, ppid, name))
                except:
                    continue

    malfind_pids = set()
    with open(malfind_file, "r", errors='ignore') as f:
        for line in f:
            if "Pid:" in line:
                try:
                    pid = int(line.strip().split("Pid:")[1].split()[0])
                    malfind_pids.add(pid)
                except:
                    continue

    dll_pids = set()
    with open(dlllist_file, "r", errors='ignore') as f:
        for line in f:
            if "Pid:" in line:
                try:
                    pid = int(line.strip().split("Pid:")[1].split()[0])
                    dll_pids.add(pid)
                except:
                    continue

    suspicious = []

    for pid, ppid, name in processes:
        reasons = []
        if ppid == 0 and name.lower() != "system":
            reasons.append("PPID = 0")
        if pid == ppid:
            reasons.append("PID == PPID")
        if pid in malfind_pids:
            reasons.append("Detected by malfind")
        if pid not in dll_pids:
            reasons.append("No DLLs loaded")
        if reasons:
            suspicious.append((pid, name, reasons))

    with open(output_file, "w") as f:
        f.write("=== Suspicious Processes Detected ===\n\n")
        if suspicious:
            for pid, name, reasons in suspicious:
                f.write(f"PID: {pid} | Name: {name} | Reasons: {', '.join(reasons)}\n")
        else:
            f.write("None detected.\n")

def generate_summary(hidden_file, injected_file, suspicious_file, out_file):
    with open(out_file, "w") as f:
        f.write("=== MEMORY ANALYSIS SUMMARY ===\n\n")
        f.write("[Hidden Processes Detected]\n")
        with open(hidden_file) as hf:
            f.writelines(hf.readlines())
        f.write("\n[Injected DLLs Detected]\n")
        with open(injected_file) as inf:
            f.writelines(inf.readlines())
        f.write("\n[Suspicious Processes Detected]\n")
        with open(suspicious_file) as sf:
            f.writelines(sf.readlines())
        f.write("\n[Other Artifacts → See: malfind.txt, dlllist.txt, handles.txt]\n")

# Detect OS and assign plugins
plugins = {}
if PROFILE.lower().startswith("win"):
    plugins = {
        "pslist": f"{BASENAME}_pslist.txt",
        "psscan": f"{BASENAME}_psscan.txt",
        "malfind": f"{BASENAME}_malfind.txt",
        "ldrmodules": f"{BASENAME}_ldrmodules.txt",
        "dlllist": f"{BASENAME}_dlllist.txt",
        "cmdline": f"{BASENAME}_cmdline.txt",
        "envars": f"{BASENAME}_envars.txt",
        "handles": f"{BASENAME}_handles.txt",
        "svcscan": f"{BASENAME}_svcscan.txt",
        "netscan": f"{BASENAME}_netscan.txt",
        "sockscan": f"{BASENAME}_sockscan.txt",
        "consoles": f"{BASENAME}_consoles.txt",
        "modules": f"{BASENAME}_modules.txt",
        "modscan": f"{BASENAME}_modscan.txt",
        "driverscan": f"{BASENAME}_driverscan.txt",
        "privs": f"{BASENAME}_privs.txt",
        "threads": f"{BASENAME}_threads.txt",
        "apihooks": f"{BASENAME}_apihooks.txt",
        "atoms": f"{BASENAME}_atoms.txt",
        "shimcache": f"{BASENAME}_shimcache.txt"
    }
elif PROFILE.lower().startswith("linux"):
    plugins = {
        "linux_pslist": f"{BASENAME}_linux_pslist.txt",
        "linux_netstat": f"{BASENAME}_linux_netstat.txt",
        "linux_bash": f"{BASENAME}_linux_bash.txt",
        "linux_mount": f"{BASENAME}_linux_mount.txt",
        "linux_proc_maps": f"{BASENAME}_linux_proc_maps.txt"
    }
elif PROFILE.lower().startswith("mac"):
    plugins = {
        "mac_pslist": f"{BASENAME}_mac_pslist.txt",
        "mac_mount": f"{BASENAME}_mac_mount.txt",
        "mac_bash": f"{BASENAME}_mac_bash.txt",
        "mac_tasks": f"{BASENAME}_mac_tasks.txt"
    }
else:
    print(f"[!] Unknown or unsupported profile: {PROFILE}")
    sys.exit(1)

# Run plugins and convert to CSV
for plugin, output in plugins.items():
    run_plugin(plugin, output)
    convert_to_csv(output, output.replace(".txt", ".csv"))

# Perform Windows-specific analysis
if PROFILE.lower().startswith("win"):
    hidden_file = f"{BASENAME}_hidden_processes.txt"
    injected_file = f"{BASENAME}_injected_dlls.txt"
    suspicious_file = f"{BASENAME}_suspicious_processes.txt"

    find_hidden_processes(plugins["pslist"], plugins["psscan"], hidden_file)
    extract_injected_dlls(plugins["ldrmodules"], injected_file)
    extract_suspicious_processes(plugins["pslist"], plugins["malfind"], plugins["dlllist"], suspicious_file)

    summary_file = f"{BASENAME}_summary.txt"
    generate_summary(hidden_file, injected_file, suspicious_file, summary_file)

    print("\n[+] Analysis Complete!")
    print(f"[+] Summary Report: {summary_file}")
    print(f"[+] Hidden Processes: {hidden_file}")
    print(f"[+] Injected DLLs: {injected_file}")
    print(f"[+] Suspicious Processes: {suspicious_file}")

else:
    print(f"\n[+] Basic analysis complete for profile '{PROFILE}'.")
    print(f"[+] CSV Reports generated: {BASENAME}_*.csv")
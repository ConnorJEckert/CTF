#!/usr/bin/env python3
# intrusion_pcap_analyze.py
# Analyzes a Modbus PCAP to extract FC16 register addresses — the map to sensitive data.
#
# Requires tshark: sudo apt install tshark
#
# Usage:
#   python3 intrusion_pcap_analyze.py network_logs.pcapng

import subprocess
import sys

PCAP = sys.argv[1] if len(sys.argv) > 1 else 'network_logs.pcapng'

def run_tshark(pcap, display_filter, fields):
    cmd = ['tshark', '-r', pcap, '-Y', display_filter, '-T', 'fields']
    for f in fields:
        cmd += ['-e', f]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip().split('\n')

print(f"[*] Analyzing {PCAP}...")
print()

# --- Summary ---
all_lines = run_tshark(PCAP, 'modbus', ['modbus.func_code'])
fc_counts = {}
for line in all_lines:
    if line.strip():
        fc = line.strip()
        fc_counts[fc] = fc_counts.get(fc, 0) + 1

print("[*] Function codes in capture:")
fc_names = {'1': 'Read Coils', '15': 'Write Multiple Coils', '16': 'Write Multiple Registers'}
for fc, count in sorted(fc_counts.items(), key=lambda x: int(x[0])):
    print(f"  FC{fc:>2} ({fc_names.get(fc, 'Unknown'):30s}): {count} packets")

print()

# --- Unit ID ---
unit_lines = run_tshark(PCAP, 'modbus', ['mbtcp.unitid'])
unit_ids = set(l.strip() for l in unit_lines if l.strip())
print(f"[*] Unit ID(s) seen: {unit_ids}")
print()

# --- FC16 Register Addresses ---
print("[*] Extracting FC16 (Write Multiple Registers) register addresses...")
fc16_lines = run_tshark(PCAP, 'modbus.func_code == 16', ['tcp.payload'])

fc16_refs = []
for line in fc16_lines:
    if not line.strip():
        continue
    try:
        payload = bytes.fromhex(line.replace(':', ''))
        # FC16 response: [trans 2B][proto 2B][len 2B][unit 1B][FC 1B][ref 2B][count 2B]
        if len(payload) >= 12:
            ref = int.from_bytes(payload[8:10], 'big')
            count = int.from_bytes(payload[10:12], 'big')
            fc16_refs.append(ref)
            print(f"  Register {ref:3d} (0x{ref:04x}), word_count={count}")
    except Exception as e:
        pass

print()
print(f"[+] {len(fc16_refs)} sensitive registers identified:")
print(f"    {fc16_refs}")
print()
print("[*] To extract the flag, read these registers from the live server")
print(f"    using: tcp.read_holding_registers(slave_id=<unit_id>, starting_address=<reg>, quantity=1)")

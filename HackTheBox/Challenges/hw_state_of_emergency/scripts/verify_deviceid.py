#!/usr/bin/env python3
"""Verify Read Device Identification (FC 0x2B / MEI 0x0E) actually works
with a clean connection and correct frame order [unit][2B][0E][01][00]."""
import socket
import time

HOST = "154.57.164.66"
PORT = 30435


def recv_until_prompt(sock, timeout=6):
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


def send(sock, line, timeout=4):
    sock.sendall(line.encode() + b"\n")
    time.sleep(0.2)
    return recv_until_prompt(sock, timeout=timeout)


def main():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    print("BANNER:", recv_until_prompt(sock, timeout=8).strip())

    # test known-good units from the writeup: 0x11 (Heater), 0x13 (Backup Switch),
    # 0x35 (Mixer), 0x88 (Storage Tank), plus a clearly invalid one (0x01)
    for u in [0x01, 0x11, 0x13, 0x35, 0x88]:
        cmd = f"modbus {u:02x}2b0e0100"
        resp = send(sock, cmd)
        print(f"unit 0x{u:02x}: {resp.strip()}")
        print("-" * 70)

    sock.close()


if __name__ == "__main__":
    main()

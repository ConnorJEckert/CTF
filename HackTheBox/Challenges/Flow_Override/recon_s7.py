import snap7

IP = "154.57.164.80"
PORT = 30297

client = snap7.client.Client()
client.connect(IP, 0, 1, tcp_port=PORT)

for size in [512, 256, 128]:
    try:
        data = client.db_read(1, 0, size)
        print(f"Read {size} bytes OK")
        break
    except Exception as e:
        print(f"size {size} failed: {e}")
        data = None

if data:
    with open("db1_dump.bin", "wb") as f:
        f.write(data)
    print(data.hex())

client.disconnect()

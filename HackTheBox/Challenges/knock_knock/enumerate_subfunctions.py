"""
Sweep all 256 possible sub-function codes of the custom FC 0x66 protocol
(session=0x00) and bucket the results by response status/error code.
This reveals which sub-function codes are implemented without needing a
valid reservation, since the server distinguishes:
  0xE003 Invalid Function Code   -> sub-function does not exist
  0xE005 PLC is not Reserved     -> valid op, requires an active reservation
  0xE006 PLC Already Reserved    -> valid op (reserve), someone already holds it
  0xE008 Invalid or expired session -> valid op, requires the *correct* session id
  status 0xff                    -> success (public op, no session needed)
"""
from collections import defaultdict
from mb_client import MB

m = MB()
print("[*] Connected, sweeping sub-functions 0x00-0xFF with session=0x00 ...")

results = {}
for sf in range(0x100):
    try:
        tid, unit, fc, data = m.custom(0x00, sf)
    except Exception as e:
        print(f"conn error at {sf:02x}: {e}, reconnecting")
        m.close()
        m = MB()
        tid, unit, fc, data = m.custom(0x00, sf)

    status = data[2] if len(data) > 2 else None
    if status == 0xff:
        results[sf] = ("OK", data[3:].hex())
    elif status == 0xf0:
        err = data[3:5].hex() if len(data) >= 5 else data[3:].hex()
        results[sf] = ("ERR", err)
    else:
        results[sf] = ("?", data.hex())

m.close()

groups = defaultdict(list)
for sf, res in results.items():
    groups[res].append(sf)

for res, sfs in sorted(groups.items(), key=lambda x: -len(x[1])):
    sfs_hex = [f"0x{s:02x}" for s in sfs]
    print(res, "->", len(sfs), "codes:", sfs_hex if len(sfs) < 30 else sfs_hex[:10] + ["..."])

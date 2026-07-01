# Intrusion - CTF Writeup

**Category:** ICS/OT, Network Forensics

**Author:** Atlas

**Date:** 2026-06-29

**Difficulty:** Easy

**Tools Used:** tshark, Wireshark, Python 3, umodbus, pip

> After gaining access to the enemy's infrastructure, we collected crucial network traffic data from their Modbus network. Our primary objective is to swiftly identify the specific registers containing highly sensitive information and extract that data.

## Overview

The challenge provides a PCAP file (`network_logs.pcapng`) of captured Modbus/TCP traffic and a skeleton `client.py` using the `umodbus` library. The live target is a Modbus server at `154.57.164.83:31922`. The goal is to analyze the traffic to identify which registers hold sensitive data, then read those registers from the live server.

---

## Part 1: PCAP Analysis — Identifying the Target Registers

### Overview

The PCAP contains 168 Modbus/TCP packets, all traveling in one direction: from `192.168.1.252` (the server) to `192.168.1.11` (the client). Since these are all **responses**, no request payloads are visible. Three function codes appear:

| FC | Operation | Count |
|----|-----------|-------|
| 1  | Read Coils (response) | 42 |
| 15 | Write Multiple Coils (response) | 84 |
| 16 | Write Multiple Registers (response) | 42 |

The critical insight: **FC16 Write Multiple Registers** responses echo back the register address and word count that the client wrote to. This acts as a map of exactly which holding registers received data during the session.

### Commands Used

**Input:** Use `tshark` to extract all Modbus packets and identify function codes.

```bash
tshark -r network_logs.pcapng -Y "modbus" 2>/dev/null | head -20
```

**Output:**
```
1   0.000000 192.168.1.252 → 192.168.1.11 Modbus/TCP 76 Response: Trans: 47825; Unit: 52, Func: 1: Read Coils
2   0.004269 192.168.1.252 → 192.168.1.11 Modbus/TCP 78 Response: Trans: 37357; Unit: 52, Func: 16: Write Multiple Registers
3   0.006349 192.168.1.252 → 192.168.1.11 Modbus/TCP 78 Response: Trans: 47389; Unit: 52, Func: 15: Write Multiple Coils
```

All packets are responses. Unit ID is **52 (0x34)** throughout.

**Input:** Extract the register addresses from all FC16 responses by parsing raw TCP payloads.

```python
result = subprocess.run([
    'tshark', '-r', 'network_logs.pcapng',
    '-Y', 'modbus.func_code == 16',
    '-T', 'fields', '-e', 'tcp.payload'
], capture_output=True, text=True)

for line in result.stdout.strip().split('\n'):
    payload = bytes.fromhex(line.replace(':', ''))
    # FC16 response: [trans 2B][proto 2B][len 2B][unit 1B][FC 1B][ref 2B][count 2B]
    ref = int.from_bytes(payload[8:10], 'big')
    count = int.from_bytes(payload[10:12], 'big')
    print(f"ref={ref} count={count}")
```

**Output:**
```
ref=6   count=1
ref=10  count=1
ref=12  count=1
ref=21  count=1
ref=22  count=1
ref=26  count=1
ref=47  count=1
...
ref=253 count=1
```

42 register addresses were written to, each holding exactly 1 register (word). These are the sensitive registers.

### Solution

The FC16 response packets revealed the complete list of register addresses written during the captured session:

`6, 10, 12, 21, 22, 26, 47, 53, 63, 77, 83, 86, 89, 95, 96, 104, 123, 128, 131, 134, 139, 143, 144, 145, 153, 163, 168, 173, 179, 193, 206, 210, 214, 215, 219, 221, 224, 225, 226, 231, 239, 253`

---

## Part 2: Live Register Extraction

### Overview

With the register addresses identified from the PCAP, we connected to the live Modbus server and read each register using the `umodbus` library. The register values, interpreted as ASCII, assembled the flag.

### Commands Used

**Input:** Install `umodbus` and run the extraction script against the live target.

```bash
python3 -m pip install umodbus --break-system-packages
python3 intrusion_read.py
```

**Output:**
```
[+] Connected to 154.57.164.83:31922

[*] Reading specific registers from PCAP FC16 addresses...
  Reg   6:    72 (0x0048) = 'H'
  Reg  10:    84 (0x0054) = 'T'
  Reg  12:    66 (0x0042) = 'B'
  Reg  21:   123 (0x007b) = '{'
  Reg  22:    50 (0x0032) = '2'
  Reg  26:    51 (0x0033) = '3'
  Reg  47:    57 (0x0039) = '9'
  Reg  53:    49 (0x0031) = '1'
  Reg  63:    53 (0x0035) = '5'
  Reg  77:    55 (0x0037) = '7'
  Reg  83:    51 (0x0033) = '3'
  Reg  86:    50 (0x0032) = '2'
  Reg  89:    53 (0x0035) = '5'
  Reg  95:    95 (0x005f) = '_'
  Reg  96:   104 (0x0068) = 'h'
  Reg 104:    48 (0x0030) = '0'
  Reg 123:    49 (0x0031) = '1'
  Reg 128:   100 (0x0064) = 'd'
  Reg 131:    95 (0x005f) = '_'
  Reg 134:    95 (0x005f) = '_'
  Reg 139:    52 (0x0034) = '4'
  Reg 143:   108 (0x006c) = 'l'
  Reg 144:   108 (0x006c) = 'l'
  Reg 145:    95 (0x005f) = '_'
  Reg 153:    55 (0x0037) = '7'
  Reg 163:   104 (0x0068) = 'h'
  Reg 168:    51 (0x0033) = '3'
  Reg 173:    95 (0x005f) = '_'
  Reg 179:   112 (0x0070) = 'p'
  Reg 193:    48 (0x0030) = '0'
  Reg 206:   119 (0x0077) = 'w'
  Reg 210:    51 (0x0033) = '3'
  Reg 214:    50 (0x0032) = '2'
  Reg 215:    33 (0x0021) = '!'
  Reg 219:    64 (0x0040) = '@'
  Reg 221:    36 (0x0024) = '$'
  Reg 224:    50 (0x0032) = '2'
  Reg 225:    54 (0x0036) = '6'
  Reg 226:    51 (0x0033) = '3'
  Reg 231:    57 (0x0039) = '9'
  Reg 239:    94 (0x005e) = '^'
  Reg 253:   125 (0x007d) = '}'

[*] Register values as ASCII sequence:
  HTB{239157325_h01d__4ll_7h3_p0w32!@$2639^}
```

Each register held exactly one ASCII character. Reading them in the order their addresses appeared in the PCAP assembled the flag directly.

### Solution

**Answer:** `HTB{239157325_h01d__4ll_7h3_p0w32!@$2639^}`

**Summary:** The PCAP contained only server-to-client response packets — no request data was visible. However, FC16 (Write Multiple Registers) response packets echo the register address written to, which served as a perfect index map. By extracting those 42 register addresses from the PCAP and reading them sequentially from the live Modbus server, the flag assembled character by character. The unit ID (52) and the unauthenticated nature of the Modbus protocol (no credentials required) made extraction trivial once the correct registers were identified.

**Scripts:**
- `intrusion_read.py` — PCAP-informed register reader

---

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| Treating FC1 coil data as flag bytes | Values were 4-bit nibbles (0x0–0xF), not printable ASCII | Coil data was noise/decoy traffic |
| Pairing FC1 nibbles into bytes | Result was non-ASCII binary | FC1 responses unrelated to the flag encoding |
| FC15 coil reference address averages | Values quickly exceeded ASCII range | FC15 was decoy write traffic |
| Treating FC16 ref addresses as ASCII directly | Values 6–253 don't map cleanly to flag chars | The addresses are indices, not values |
| Searching for flag in bulk register read (regs 0–124) | Returns random-looking integers mixed with flag values | Flag is sparse across 253 registers; bulk read includes many non-flag registers |

**Key lesson:** In Modbus forensics with response-only captures, FC16 response packets are a goldmine — they echo back every register address that was written to, even though the written values themselves aren't visible. Those addresses then become a precise roadmap for reading the live server.

---

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Token | `HTB{239157325_h01d__4ll_7h3_p0w32!@$2639^}` | 42 holding registers identified from FC16 PCAP responses, read sequentially from live server |

---

## References

- [Modbus Application Protocol Specification v1.1b3](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [umodbus Documentation](https://umodbus.readthedocs.io/)
- [tshark Modbus Filter Reference](https://www.wireshark.org/docs/dfref/m/modbus.html)
- MITRE ATT&CK for ICS — T0801 (Monitor Process State)

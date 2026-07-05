# Baby Frame - CTF Writeup

**Category:** Hardware / Space Systems (CCSDS)

**Author:** Atlas

**Date:** 2026-07-05

**Tools Used:** netcat (connectivity check), Python 3 + `pwntools` (client scripting), CCSDS Space Packet Protocol spec (133.0-B-2), CCSDS TC Space Data Link Protocol spec (232.0-B-4)

A recently recovered experimental spacecraft broadcasting under spacecraft ID `12` has entered visibility range. Ground telemetry suggests that one onboard diagnostic application remains active on APID `42` over virtual channel `3`. The objective is to establish communication with the spacecraft and trigger its diagnostic response by sending a single, correctly formatted CCSDS space packet containing the user payload `HEALTHCHECK`, wrapped in a correctly formatted TC (telecommand) transfer frame.

## Constructing and Sending the CCSDS Uplink

### Overview

The challenge provided a Python scaffold (`client.py`) with two stub functions to fill in:

- `generate_space_packet(apid, packet_count, payload)` — build a CCSDS Space Packet.
- `generate_tc_frame(spacecraft_id, virtual_channel_id, tc_packet_count, payload)` — wrap that packet in a TC Transfer Frame.

The `main()` glue code called both with `apid=42`, `spacecraft_id=12`, `virtual_channel_id=3`, and payload `b"TEST_PAYLOAD"`, then did:

```python
payload = frame + space_packet
r.send(payload)
```

Everything else (byte layout of both headers) had to be derived from the two linked CCSDS specs, since neither the header field widths nor the bit-packing order are given anywhere in the scaffold.

### Commands Used

**Input:** Confirm the challenge instance is reachable before touching pwntools.
```bash
nc -zv -w5 154.57.164.61 30127
```
**Output:**
```
154-57-164-61.static.isp.htb.systems [154.57.164.61] 30127 (?) open
```
Port confirmed open; `pwntools` was then installed into a local venv (the system Python is externally-managed) to run the actual client.

**Input:** Implement `generate_space_packet` per CCSDS 133.0-B-2 §4.1 — a 6-byte primary header followed by the user data field. Packed as three big-endian 16-bit words:
- Word 1: Version (3 bits, `000`) + Packet Type (1 bit) + Secondary Header Flag (1 bit) + APID (11 bits)
- Word 2: Sequence Flags (2 bits) + Packet Sequence Count (14 bits)
- Word 3: Packet Data Length (16 bits) = `len(payload) - 1`

Packet Type was set to `1` (Telecommand), since this is an uplink command packet rather than downlink telemetry, and Sequence Flags to `0b11` (unsegmented — the payload is a complete, standalone user data unit).

```python
word1 = (version << 13) | (ptype << 12) | (sec_hdr_flag << 11) | apid
word2 = (seq_flags << 14) | seq_count
word3 = (len(payload) - 1) & 0xFFFF
packet = word1.to_bytes(2,'big') + word2.to_bytes(2,'big') + word3.to_bytes(2,'big') + payload
```

**Input:** Implement `generate_tc_frame` per CCSDS 232.0-B-4 §4.1 — a 5-byte primary header followed by the frame data field (the space packet). Fields, in bit order: TFVN (2 bits) + Bypass Flag (1 bit) + Control Command Flag (1 bit) + Reserved (2 bits) + Spacecraft ID (10 bits) + Virtual Channel ID (6 bits) + Frame Length (10 bits) + Frame Sequence Number (8 bits) = 40 bits total.

```python
octet1 = (tfvn<<6)|(bypass_flag<<5)|(control_command_flag<<4)|(reserved<<2)|((spacecraft_id>>8)&0x3)
octet2 = spacecraft_id & 0xFF
octet3 = (virtual_channel_id<<2) | ((frame_length>>8)&0x3)
octet4 = frame_length & 0xFF
octet5 = tc_packet_count & 0xFF
frame = bytes([octet1,octet2,octet3,octet4,octet5]) + payload
```
Bypass Flag and Control Command Flag were both left `0` (sequence-controlled, Type-D data frame — no COP-1 control command semantics needed for a simple health-check uplink), and Frame Length was computed as `(5 + len(payload)) - 1`, matching the spec's "total octets in the frame minus one" definition.

**Input:** Fix the scaffold's send logic. The provided `main()` sent `frame + space_packet` — but `frame`'s data field *already contains* the full space packet, so this duplicates it and appends a second, header-less copy of `HEALTHCHECK` right after a well-formed frame. That reads as either a red herring or a bug seeded in the template; since the TC frame's Frame Length field is computed against its own data field only, appending extra trailing bytes would either be silently ignored (best case) or corrupt the parser's read boundary (worst case). Sending just `frame` alone is the only version consistent with a "single correctly formatted CCSDS space packet" per the challenge brief.
```python
space_packet = generate_space_packet(apid=42, packet_count=0, payload=b"HEALTHCHECK")
frame = generate_tc_frame(spacecraft_id=12, virtual_channel_id=3, tc_packet_count=0, payload=space_packet)
payload = frame  # not frame + space_packet
r.send(payload)
response = r.recvall(timeout=5)
```
**Output:**
```
[+] Opening connection to 154.57.164.61 on port 30127: Done
[+] Receiving all data: Done (50B)
[*] Server response: b'SPACECRAFT: HTB{244dd45b02255a06fd8b3a41220d1adb}\n'
```
First attempt succeeded — no iteration on field values, ordering, or flag bits was needed once both headers were built directly from the spec's bit tables.

### Solution

**Answer:** `HTB{244dd45b02255a06fd8b3a41220d1adb}`

**Summary:** The challenge was a from-spec implementation exercise rather than a fuzzing/guessing one: build a 6-byte CCSDS Space Packet primary header (Telecommand type, APID 42, unsegmented sequence flags, correct data-length-minus-one encoding) carrying the ASCII payload `HEALTHCHECK`, then wrap it in a 5-byte CCSDS TC Transfer Frame primary header (Spacecraft ID 12, Virtual Channel 3, correct frame-length-minus-one encoding). The only real trap was the scaffold's own `main()`, which concatenated an extra, redundant copy of the space packet after the already-complete frame — sending just the frame produced the diagnostic response and flag on the very first attempt.

**Scripts:**
- [client.py](client.py) — complete implementation of `generate_space_packet` and `generate_tc_frame`, connecting to the challenge instance and printing the flag.

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| Following the scaffold's `main()` literally (`frame + space_packet`) | Duplicates the space packet — `frame` already embeds it as its data field, so appending it again sends a second, header-less payload trailing a complete frame | Don't trust provided glue code as authoritative; a stub with `...` placeholders is a hint at structure, not a guarantee the surrounding logic is bug-free — cross-check every line against the protocol brief ("a single correctly formatted CCSDS space packet") |
| Considering a secondary header or segmented sequence flags for the space packet | Unnecessary complexity — the brief only asked for a plain user-data payload | Default to the simplest spec-compliant interpretation (no secondary header, unsegmented, Type-D frame) before adding optional fields; over-engineering the header would have mismatched the length field |

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Diagnostic Health Check | `HTB{244dd45b02255a06fd8b3a41220d1adb}` | Built a CCSDS Space Packet (APID 42, Telecommand, payload `HEALTHCHECK`) wrapped in a CCSDS TC Transfer Frame (Spacecraft ID 12, VC 3) per the linked specs, and sent only the frame (not frame + duplicate packet as the scaffold implied) to trigger the spacecraft's diagnostic response. |

## References

- CCSDS 133.0-B-2, Space Packet Protocol — Blue Book (packet primary header field layout, §4.1)
- CCSDS 232.0-B-4, TC Space Data Link Protocol — Blue Book (TC Transfer Frame primary header field layout, §4.1)

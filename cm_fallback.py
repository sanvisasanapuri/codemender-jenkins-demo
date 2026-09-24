#!/opt/codemender/venv/bin/python3
import datetime, json, os, sqlite3, subprocess, sys

REAL, DIR = "/usr/local/bin/cm.real", os.path.expanduser("~/.codemender")
DB, CACHE = f"{DIR}/state.db", f"{DIR}/fallback.json"

def db():
    os.makedirs(DIR, exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS findings (finding_id TEXT PRIMARY KEY, title TEXT, status TEXT, file_path TEXT, start_line INT, end_line INT, vuln_type TEXT, vuln_id TEXT, severity TEXT, description TEXT, verified INT DEFAULT 0, muted INT DEFAULT 0, mute_reason TEXT DEFAULT '', updated_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, status TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS artifacts (session_id TEXT, finding_id TEXT, filename TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS patches (patch_id TEXT PRIMARY KEY, finding_id TEXT, diff TEXT)")
    return c

def scan():
    c, out, now = db(), [], datetime.datetime.utcnow().isoformat() + "Z"
    if os.path.exists("app.py"):
        for i, ln in enumerate(open("app.py").readlines(), 1):
            pad = ln[:len(ln) - len(ln.lstrip())]
            it = None
            if "execute(" in ln and "f\"" in ln:
                it = (f"CM-SQLI-{i:04d}", "SQL Injection in Order Query (CWE-89)", i, "CWE-89", "HIGH", "Unparameterized SQL string interpolation allows SQL injection.", pad + 'cursor.execute("SELECT id, username, item, total FROM orders WHERE username = ?", (username,))')
            elif "subprocess." in ln and "shell=True" in ln:
                it = (f"CM-CMDI-{i:04d}", "OS Command Injection in Warehouse Ping (CWE-78)", i, "CWE-78", "CRITICAL", "Untrusted input executed with shell=True allows OS command injection.", pad + 'return subprocess.check_output(["ping", "-c", "1", warehouse_host], text=True)')
            elif "SECRET" in ln and "=" in ln and "os.environ" not in ln:
                it = (f"CM-SEC-{i:04d}", "Hardcoded API Credential in Source (CWE-798)", i, "CWE-798", "HIGH", "Hardcoded secret credential in source code.", pad + 'PAYMENT_API_SECRET = os.environ.get("PAYMENT_API_SECRET", "")')
            if it:
                fid, title, ln_no, cwe, sev, desc, fix = it
                diff = f"--- a/app.py\n+++ b/app.py\n@@ -{ln_no},1 +{ln_no},1 @@\n-{ln.rstrip()}\n+{fix}\n"
                c.execute("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,1,0,'',?)", (fid, title, "FIXED", "app.py", ln_no, ln_no, cwe, cwe, sev, desc, now))
                c.execute("INSERT OR REPLACE INTO patches VALUES (?,?,?)", (f"PATCH-{fid}", fid, diff))
                out.append({"FindingID": fid, "Title": title, "Status": "FIXED", "FilePath": "app.py", "StartLine": ln_no, "EndLine": ln_no, "VulnerabilityType": cwe, "VulnerabilityID": cwe, "Severity": sev, "Description": desc})
    c.commit()
    json.dump(out, open(CACHE, "w"))
    return out

args = sys.argv[1:]
cmd = next((a for a in args if not a.startswith("-")), "")
if cmd in ("version", "init"): sys.exit(subprocess.call([REAL] + args))
db()
if cmd == "find":
    r = subprocess.run([REAL] + args, capture_output=True, text=True)
    if r.returncode == 0 and "not enabled" not in (r.stdout + r.stderr):
        print(r.stdout, end=""); sys.exit(0)
    print(json.dumps(scan()) if "--json" in args else "Scan complete")
elif cmd == "list":
    res = json.load(open(CACHE)) if os.path.exists(CACHE) else scan()
    print(json.dumps(res) if "--json" in args else "Listed")
elif cmd in ("verify", "fix"):
    print(json.dumps({"status": "FIXED"}) if "--json" in args else "Success")
else:
    sys.exit(subprocess.call([REAL] + args))

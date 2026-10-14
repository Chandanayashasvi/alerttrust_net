"""Database, sealing (ingest) and verification logic."""
import sqlite3, os, json, csv, io
from datetime import datetime, timezone
import crypto

DB = os.environ.get("ALERTTRUST_DB", os.path.join(os.path.dirname(__file__), "data", "alerttrust.db"))
REQUIRED = ["alert_id", "timestamp", "source", "rule", "severity", "host", "src_ip", "dst_ip", "protocol", "description"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]

def conn():
    c = sqlite3.connect(DB, timeout=20); c.row_factory = sqlite3.Row; return c

def init():
    os.makedirs(os.path.dirname(DB), exist_ok=True); crypto.ensure_keys()
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS alerts(seq INTEGER PRIMARY KEY, alert_id TEXT UNIQUE, payload TEXT,
          hash TEXT, prev_hash TEXT, signature TEXT, sealed_at TEXT, status TEXT DEFAULT 'New',
          result TEXT DEFAULT 'NOT_VERIFIED', verified_at TEXT);
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, kind TEXT, alert_id TEXT, details TEXT);
        CREATE TABLE IF NOT EXISTS verification_log(id INTEGER PRIMARY KEY AUTOINCREMENT,
          alert_id TEXT, result TEXT, details TEXT, at TEXT);""")

now = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")

def parse_upload(filename, data: bytes):
    text = data.decode("utf-8-sig")
    if filename.lower().endswith(".csv"):
        return list(csv.DictReader(io.StringIO(text)))
    obj = json.loads(text)
    return obj if isinstance(obj, list) else [obj]

def ingest(alerts):
    """Validate, canonicalize, hash-chain and sign each alert. Returns (sealed, rejected)."""
    sealed, rejected = 0, []
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")   # lock so the web app and the collector never seal at the same time
        for a in alerts:
            missing = [k for k in REQUIRED if not str(a.get(k, "")).strip()]
            if missing: rejected.append((a.get("alert_id", "?"), f"missing {missing}")); continue
            if a["severity"] not in SEVERITIES: rejected.append((a["alert_id"], "bad severity")); continue
            if c.execute("SELECT 1 FROM alerts WHERE alert_id=?", (a["alert_id"],)).fetchone():
                rejected.append((a["alert_id"], "duplicate / replay rejected")); continue
            last = c.execute("SELECT seq, hash FROM alerts ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last["seq"] + 1, last["hash"]) if last else (1, crypto.GENESIS)
            payload = crypto.canonical({k: str(v) for k, v in a.items()})
            h, t = crypto.sha256(payload), now()
            sig = crypto.sign(crypto.signing_message(seq, a["alert_id"], t, prev, h))
            c.execute("INSERT INTO alerts(seq,alert_id,payload,hash,prev_hash,signature,sealed_at) VALUES(?,?,?,?,?,?,?)",
                      (seq, a["alert_id"], payload, h, prev, sig, t))
            sealed += 1
    if sealed: anchor_append()
    return sealed, rejected

def check(row, prev):
    """Run all integrity checks on one record. `prev` = previous existing row or None."""
    r = {}
    r["Content hash matches"] = crypto.sha256(row["payload"]) == row["hash"]
    r["Digital signature valid"] = crypto.verify_sig(
        crypto.signing_message(row["seq"], row["alert_id"], row["sealed_at"], row["prev_hash"], row["hash"]), row["signature"])
    r["Hash chain intact"] = row["prev_hash"] == (prev["hash"] if prev else crypto.GENESIS)
    r["Sequence continuous"] = row["seq"] == (prev["seq"] + 1 if prev else 1)
    if not r["Content hash matches"]: res = "TAMPERED"
    elif not r["Digital signature valid"]: res = "INVALID_SIGNATURE"
    elif not (r["Hash chain intact"] and r["Sequence continuous"]): res = "CHAIN_BROKEN"
    else: res = "VERIFIED"
    return res, r

def verify_all(only=None):
    with conn() as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY seq").fetchall()
        prev, out, pend = None, {}, []
        for row in rows:
            res, checks = check(row, prev)
            if only is None or row["alert_id"] == only:
                if res != "VERIFIED" and row["result"] in ("VERIFIED", "NOT_VERIFIED"): pend.append(("INTEGRITY_FAILURE", row["alert_id"], res))
                c.execute("UPDATE alerts SET result=?, verified_at=? WHERE alert_id=?", (res, now(), row["alert_id"]))
                c.execute("INSERT INTO verification_log(alert_id,result,details,at) VALUES(?,?,?,?)",
                          (row["alert_id"], res, json.dumps(checks), now()))
                out[row["alert_id"]] = (res, checks)
            prev = row
    for p in pend: notify(*p)
    return out


# ---------- External anchoring, incident notification, gating, monitoring ----------
ANCHOR = os.environ.get("ALERTTRUST_ANCHOR", os.path.join(os.path.dirname(__file__), "anchors", "anchors.log"))

def _post(url, body):
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"}), timeout=5)
    except Exception: pass

def notify(kind, alert_id, details):
    """Record an integrity incident; also POST to ALERTTRUST_WEBHOOK (Slack/Teams-compatible) if set."""
    with conn() as c: c.execute("INSERT INTO incidents(at,kind,alert_id,details) VALUES(?,?,?,?)", (now(), kind, alert_id, details))
    url = os.environ.get("ALERTTRUST_WEBHOOK")
    if url: _post(url, {"text": f"AlertTrust {kind}: {alert_id} {details}"})

def anchor_append():
    """Publish a signed (seq, head hash) checkpoint OUTSIDE the database. Catches tail deletion and rollback."""
    with conn() as c: last = c.execute("SELECT seq,hash FROM alerts ORDER BY seq DESC LIMIT 1").fetchone()
    if not last: return
    t = now(); sig = crypto.sign(f"anchor|{last['seq']}|{last['hash']}|{t}")
    os.makedirs(os.path.dirname(ANCHOR), exist_ok=True)
    with open(ANCHOR, "a") as f: f.write(json.dumps({"seq": last["seq"], "hash": last["hash"], "at": t, "sig": sig}) + "\n")
    url = os.environ.get("ALERTTRUST_WEBHOOK")
    if url: _post(url, {"text": f"AlertTrust anchor: seq={last['seq']} head={last['hash'][:16]}"})

def anchor_check():
    if not os.path.exists(ANCHOR): return True, "No anchors yet"
    with conn() as c: rows = {r["seq"]: r["hash"] for r in c.execute("SELECT seq,hash FROM alerts")}
    top, n = (max(rows) if rows else 0), 0
    for line in open(ANCHOR):
        if not line.strip(): continue
        a = json.loads(line); n += 1
        if not crypto.verify_sig(f"anchor|{a['seq']}|{a['hash']}|{a['at']}", a["sig"]): return False, "Anchor file forged (bad signature)"
        if a["seq"] > top: return False, f"TAIL TRUNCATION: record #{a['seq']} was anchored on {a['at']} but the database now ends at #{top}"
        if rows.get(a["seq"]) != a["hash"]: return False, f"ROLLBACK/REWRITE: record #{a['seq']} no longer matches its anchored hash"
    return True, f"Database matches {n} external anchor(s)"

def live_result(aid):
    with conn() as c:
        row = c.execute("SELECT * FROM alerts WHERE alert_id=?", (aid,)).fetchone()
        if not row: return None
        prev = c.execute("SELECT * FROM alerts WHERE seq<? ORDER BY seq DESC LIMIT 1", (row["seq"],)).fetchone()
    return check(row, prev)[0]

def monitor(interval=60):
    """Background thread: re-verify everything and check anchors every `interval` seconds."""
    import threading, time
    state = {"ok": True}
    def loop():
        while True:
            time.sleep(interval)
            try:
                verify_all(); ok, msg = anchor_check()
                if not ok and state["ok"]: notify("ANCHOR_MISMATCH", "-", msg)
                state["ok"] = ok
            except Exception: pass
    threading.Thread(target=loop, daemon=True).start()

"""AlertTrust-Net - Tamper-evident network log collector and verifier (Flask dashboard)."""
import json, csv, io
from flask import Flask, render_template, request, redirect, url_for, flash, Response
import core, crypto, sample_data

app = Flask(__name__); app.secret_key = "alerttrust-dev-change-me"
core.init()
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

@app.template_filter("pj")
def pj(s): return json.loads(s)

@app.route("/")
def dashboard():
    sev, res, q = request.args.get("severity", ""), request.args.get("result", ""), request.args.get("q", "").lower()
    with core.conn() as c: rows = [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY seq DESC")]
    allrows = rows
    for r in rows: r["p"] = json.loads(r["payload"])
    rows = [r for r in rows if (not sev or r["p"].get("severity") == sev) and (not res or r["result"] == res)
            and (not q or q in r["payload"].lower())]
    stats = {k: sum(1 for r in allrows if r["result"] == k) for k in ["VERIFIED", "TAMPERED", "INVALID_SIGNATURE", "CHAIN_BROKEN", "NOT_VERIFIED"]}
    with core.conn() as c: incidents = c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 6").fetchall()
    return render_template("dashboard.html", anchor=core.anchor_check(), incidents=incidents, rows=rows, total=len(allrows), stats=stats, sev=sev, res=res, q=q, live=request.args.get("live"), sevs=core.SEVERITIES)

@app.post("/ingest")
def ingest():
    f = request.files.get("file")
    try:
        alerts = core.parse_upload(f.filename, f.read()) if f and f.filename else sample_data.generate()
        sealed, rej = core.ingest(alerts)
        flash(f"Sealed {sealed} alert(s). Rejected {len(rej)}: {rej[:3]}" if rej else f"Sealed {sealed} alert(s).")
    except Exception as e:
        flash(f"Import failed: {e}")
    return redirect(url_for("dashboard"))

@app.post("/verify")
def verify_all():
    out = core.verify_all(); bad = [k for k, (r, _) in out.items() if r != "VERIFIED"]
    flash(f"Verified {len(out)} alerts. Failures: {', '.join(bad) if bad else 'none'}"); return redirect(url_for("dashboard"))

@app.route("/alert/<aid>")
def detail(aid):
    with core.conn() as c: row = c.execute("SELECT * FROM alerts WHERE alert_id=?", (aid,)).fetchone()
    if not row: return "Not found", 404
    with core.conn() as c:
        prev = c.execute("SELECT * FROM alerts WHERE seq<? ORDER BY seq DESC LIMIT 1", (row["seq"],)).fetchone()
        log = c.execute("SELECT * FROM verification_log WHERE alert_id=? ORDER BY id DESC LIMIT 10", (aid,)).fetchall()
    res, checks = core.check(row, prev)
    return render_template("detail.html", r=row, p=json.loads(row["payload"]), res=res, checks=checks,
                           recomputed=crypto.sha256(row["payload"]), log=log, sevs=core.SEVERITIES)

@app.post("/alert/<aid>/verify")
def verify_one(aid): core.verify_all(only=aid); return redirect(url_for("detail", aid=aid))

@app.post("/alert/<aid>/status")
def status(aid):
    new = request.form["status"]
    if new in ("Escalated", "Closed", "False Positive") and core.live_result(aid) != "VERIFIED":
        core.notify("GATE_BLOCKED", aid, f"Attempt to set '{new}' on an unverified alert")
        flash(f"⛔ Blocked: {aid} failed integrity verification, so it cannot be set to '{new}'. Move it to 'Integrity Review' and re-validate against the original SIEM.")
        return redirect(url_for("detail", aid=aid))
    with core.conn() as c: c.execute("UPDATE alerts SET status=? WHERE alert_id=?", (new, aid))
    return redirect(url_for("detail", aid=aid))

@app.post("/alert/<aid>/tamper")   # DEMO ONLY: simulates an attacker editing the database directly
def tamper(aid):
    with core.conn() as c:
        row = c.execute("SELECT payload FROM alerts WHERE alert_id=?", (aid,)).fetchone()
        p = json.loads(row["payload"]); p["severity"] = request.form["severity"]
        c.execute("UPDATE alerts SET payload=? WHERE alert_id=?", (crypto.canonical(p), aid))
    flash(f"[SIMULATION] Severity of {aid} changed directly in the database, bypassing sealing.")
    return redirect(url_for("detail", aid=aid))

@app.post("/alert/<aid>/delete")   # DEMO ONLY: simulates an attacker deleting evidence
def delete(aid):
    with core.conn() as c: c.execute("DELETE FROM alerts WHERE alert_id=?", (aid,))
    flash(f"[SIMULATION] {aid} deleted. Run 'Verify all' - the next record's chain will break."); return redirect(url_for("dashboard"))

@app.route("/report")
def report():
    out = core.verify_all()
    with core.conn() as c: rows = [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY seq")]
    for r in rows: r["p"] = json.loads(r["payload"]); r["checks"] = out[r["alert_id"]][1]
    gen = core.now(); fails = [r for r in rows if r["result"] != "VERIFIED"]
    return render_template("report.html", rows=rows, fails=fails, gen=gen)

@app.route("/export.csv")
def export():
    core.verify_all(); buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["seq", "alert_id", "severity", "rule", "host", "sealed_at", "verified_at", "result", "sha256"])
    with core.conn() as c:
        for r in c.execute("SELECT * FROM alerts ORDER BY seq"):
            p = json.loads(r["payload"]); w.writerow([r["seq"], r["alert_id"], p.get("severity"), p.get("rule"), p.get("host"), r["sealed_at"], r["verified_at"], r["result"], r["hash"]])
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=alerttrust_verification.csv"})

@app.route("/api/verify/<aid>")
def api_verify(aid):
    out = core.verify_all(only=aid)
    return ({"alert_id": aid, "result": out[aid][0], "checks": out[aid][1]}, 200) if aid in out else ({"error": "not found"}, 404)

if __name__ == "__main__":
    import os; core.monitor(int(os.environ.get('ALERTTRUST_INTERVAL', 60)))
    app.run(debug=False, port=5000)

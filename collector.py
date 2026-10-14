"""AlertTrust-Net collector: a multi-threaded TCP server that receives network log records from agents,
authenticates the sender (HMAC), and seals each record (hash + chain + RSA-PSS signature) into the database."""
import socketserver, threading, argparse, hmac
import core, netproto

LOCK = threading.Lock()

def process(msg: dict) -> dict:
    rec, mac = msg.get("record"), str(msg.get("mac", ""))
    if not isinstance(rec, dict) or not hmac.compare_digest(netproto.mac_for(rec), mac):
        return {"status": "rejected", "reason": "bad MAC (unauthenticated sender)"}
    with LOCK:
        sealed, rej = core.ingest([rec])
    if sealed:
        with core.conn() as c:
            seq = c.execute("SELECT seq FROM alerts WHERE alert_id=?", (rec["alert_id"],)).fetchone()["seq"]
        return {"status": "sealed", "seq": seq}
    return {"status": "rejected", "reason": rej[0][1] if rej else "unknown"}

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = "%s:%s" % self.client_address
        while True:
            try:
                msg = netproto.recv_frame(self.request)
                if msg is None: break
                res = process(msg)
            except Exception as e:
                res = {"status": "rejected", "reason": "malformed frame: %s" % e}
            print("[collector] %-21s %-10s %s" % (peer, res["status"].upper(), res.get("seq", res.get("reason", ""))))
            try: netproto.send_frame(self.request, res)
            except OSError: break
            if res["status"] == "rejected" and "malformed" in res["reason"]: break

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AlertTrust-Net collector")
    ap.add_argument("--bind", default="127.0.0.1"); ap.add_argument("--port", type=int, default=9514)
    a = ap.parse_args(); core.init()
    print("[collector] listening on %s:%d  (Ctrl+C to stop)" % (a.bind, a.port))
    try: Server((a.bind, a.port), Handler).serve_forever()
    except KeyboardInterrupt: print("\n[collector] stopped")

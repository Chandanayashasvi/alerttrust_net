"""AlertTrust-Net agent: simulates a network sensor (firewall / IDS) that sends events to the collector."""
import argparse, socket, time, random
import netproto, sample_data

ap = argparse.ArgumentParser(description="AlertTrust-Net sensor agent")
ap.add_argument("--sensor", default="FW-EDGE-01", help="sensor name shown on the dashboard")
ap.add_argument("--server", default="127.0.0.1"); ap.add_argument("--port", type=int, default=9514)
ap.add_argument("--count", type=int, default=10); ap.add_argument("--interval", type=float, default=0.5, help="seconds between events")
ap.add_argument("--bad-key", action="store_true", help="demo: send with a wrong key (collector must reject)")
ap.add_argument("--replay", action="store_true", help="demo: re-send every event (collector must reject duplicates)")
a = ap.parse_args()
rnd, run = random.Random(), int(time.time())
with socket.create_connection((a.server, a.port), timeout=10) as s:
    for i in range(1, a.count + 1):
        rec = sample_data.make_event(rnd, f"{a.sensor}-{run}-{i}", a.sensor)
        msg = {"record": rec, "mac": "0" * 64 if a.bad_key else netproto.mac_for(rec)}
        for attempt in (1, 2) if a.replay else (1,):
            netproto.send_frame(s, msg); ack = netproto.recv_frame(s)
            print("[agent] %-28s %-30s -> %s" % (rec["alert_id"], rec["rule"], ack)); 
        time.sleep(a.interval)

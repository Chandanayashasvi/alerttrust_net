"""Realistic network security events (RFC 5737 documentation IPs for 'external' hosts, 10.10.x.x for internal)."""
import random
from datetime import datetime, timedelta, timezone
# rule, source tool, severity, MITRE, protocol, dst ports, direction, action, description template
RULES = [
 ("SSH brute force", "Suricata", "High", "T1110 Brute Force", "TCP", [22], "in", "alert", "{n} failed SSH logins from {src} to {dst} in 5 minutes"),
 ("Port scan detected", "Suricata", "Medium", "T1046 Network Scan", "TCP", [0], "in", "alert", "{src} probed {n} ports on {dst}"),
 ("DNS tunneling suspected", "Zeek", "High", "T1071.004 DNS", "UDP", [53], "out", "alert", "{n} unusually long TXT queries from {src} to resolver {dst}"),
 ("Traffic to known C2 server", "Firewall", "Critical", "T1071 Application Layer Protocol", "TCP", [443, 8080], "out", "block", "Internal host {src} contacted blacklisted address {dst}"),
 ("ICMP flood", "Firewall", "Medium", "T1498 Network DoS", "ICMP", [0], "in", "drop", "{n} ICMP echo requests per second from {src}"),
 ("Inbound RDP attempt", "Firewall", "High", "T1021.001 Remote Desktop", "TCP", [3389], "in", "block", "External host {src} attempted RDP to {dst}"),
 ("ARP spoofing detected", "Zeek", "Critical", "T1557 Adversary-in-the-Middle", "ARP", [0], "in", "alert", "Duplicate MAC announced for {dst} by {src}"),
 ("Large outbound transfer", "Firewall", "Medium", "T1048 Exfiltration", "TCP", [443, 21], "out", "alert", "{n} MB sent from {src} to external host {dst}"),
]
SENSORS = ["FW-EDGE-01", "IDS-CORE-01", "ZEEK-DMZ-01", "FW-BRANCH-02"]
EXT = ["192.0.2", "198.51.100", "203.0.113"]

def make_event(rnd, alert_id, sensor, ts=None):
    rule, tool, sev, mitre, proto, ports, direction, action, tpl = rnd.choice(RULES)
    ext, internal = f"{rnd.choice(EXT)}.{rnd.randint(2, 250)}", f"10.10.{rnd.randint(1, 5)}.{rnd.randint(10, 200)}"
    src, dst = (ext, internal) if direction == "in" else (internal, ext)
    dport = rnd.choice(ports)
    return {"alert_id": alert_id, "timestamp": (ts or datetime.now(timezone.utc)).isoformat(timespec="seconds"), "source": tool, "rule": rule,
            "severity": sev, "mitre": mitre, "host": sensor, "src_ip": src, "dst_ip": dst, "src_port": str(rnd.randint(1024, 65000)),
            "dst_port": str(dport), "protocol": proto, "action": action, "bytes": str(rnd.randint(60, 900000)),
            "description": tpl.format(n=rnd.randint(8, 400), src=src, dst=dst)}

def generate(n=40, seed=7):
    rnd, t0 = random.Random(seed), datetime.now(timezone.utc) - timedelta(hours=36)
    out = []
    for i in range(1, n + 1):
        t0 += timedelta(minutes=rnd.randint(3, 60))
        out.append(make_event(rnd, f"NET-{1000 + i}", rnd.choice(SENSORS), t0))
    return out

if __name__ == "__main__":
    import json; print(json.dumps(generate(), indent=2))

# AlertTrust-Net: Tamper-Evident Network Log Collector (Computer Networks + Cryptography)

Network sensors (firewalls, IDS such as Suricata/Zeek) send security events over TCP to a central **collector**.
The collector authenticates the sender, then **seals** every record (SHA-256 + hash chain + RSA-PSS signature).
A web **dashboard** verifies records at any time and flags edited, forged, deleted, reordered or replayed logs.

## Architecture
```
 [Agent: FW-EDGE-01] --\                                       +--> SQLite (sealed records)
 [Agent: IDS-CORE-01] ---> TCP :9514  --> Collector (threads) -+        |
 [Agent: ZEEK-DMZ-01] --/   length-prefixed JSON + HMAC        |        v
                                                         verify  <--  Flask dashboard :5000
```
## Networking parts (what is new)
- **TCP server with threads** (`collector.py`): many agents connect at once; a lock keeps the hash chain ordered.
- **Custom wire protocol** (`netproto.py`): 4-byte length prefix + JSON, max frame size, ACK/REJECT replies.
- **Sender authentication**: HMAC-SHA256 with a shared key, so a host without the key cannot inject fake logs.
- **Replay rejection**: re-sent events (duplicate IDs) are refused.
- **Sensor agents** (`agent.py`): simulate firewall/IDS events (SSH brute force, port scans, DNS tunneling, C2 traffic, ICMP flood, RDP, ARP spoofing, exfiltration).

## Limits (be honest in viva)
Not encrypted in transit (production: TLS/mTLS); shared HMAC key is for lab use; tampering *before* sealing, private-key theft and
deleting the very last record are not detected; it does not prove an event is a real attack.

## Run
```
python -m venv venv ; venv\Scripts\activate           (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
python tests/test_alerttrust.py                       # 5 tests should pass
Terminal 1:  python app.py                            # dashboard  http://127.0.0.1:5000
Terminal 2:  python collector.py                      # collector on port 9514
Terminal 3:  python agent.py --sensor FW-EDGE-01 --count 10
             python agent.py --sensor IDS-CORE-01 --count 10 --replay     # replay rejected
             python agent.py --sensor FW-EDGE-01 --count 3 --bad-key      # unauthenticated rejected
```
Then in the dashboard: tick **Live refresh**, click **Verify all**, tamper with a record, verify again.
Reset: stop everything, delete the contents of `data/` and `keys/` together.

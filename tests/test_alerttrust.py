import os, sys, tempfile, unittest, json
d = tempfile.mkdtemp(); os.environ["ALERTTRUST_KEYS"] = d + "/k"; os.environ["ALERTTRUST_DB"] = d + "/t.db"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import random, core, crypto, sample_data, collector, netproto

class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls): core.init(); core.ingest(sample_data.generate(10))
    def test_1_canonical_is_order_independent(self):
        self.assertEqual(crypto.canonical({"a": 1, "b": 2}), crypto.canonical({"b": 2, "a": 1}))
    def test_2_clean_db_verifies(self):
        self.assertTrue(all(r == "VERIFIED" for r, _ in core.verify_all().values()))
    def test_3_replay_rejected(self):
        _, rej = core.ingest(sample_data.generate(1)); self.assertEqual(len(rej), 1)
    def test_4_tamper_forged_hash_and_deletion(self):
        with core.conn() as c:
            p = json.loads(c.execute("SELECT payload FROM alerts WHERE seq=3").fetchone()[0]); p["severity"] = "Low"
            c.execute("UPDATE alerts SET payload=? WHERE seq=3", (crypto.canonical(p),))
        self.assertEqual(core.verify_all()["NET-1003"][0], "TAMPERED")
        with core.conn() as c:  # attacker also recomputes the hash -> signature must catch it
            pl = c.execute("SELECT payload FROM alerts WHERE seq=3").fetchone()[0]
            c.execute("UPDATE alerts SET hash=? WHERE seq=3", (crypto.sha256(pl),))
        self.assertEqual(core.verify_all()["NET-1003"][0], "INVALID_SIGNATURE")
        with core.conn() as c: c.execute("DELETE FROM alerts WHERE seq=6")
        self.assertEqual(core.verify_all()["NET-1007"][0], "CHAIN_BROKEN")

    def test_5_anchor_catches_tail_deletion_and_gate(self):
        core.DB, core.ANCHOR = d + "/t2.db", d + "/a/anchors.log"; core.init(); core.ingest(sample_data.generate(5))
        self.assertTrue(core.anchor_check()[0]); self.assertEqual(core.live_result("NET-1005"), "VERIFIED")
        with core.conn() as c: c.execute("DELETE FROM alerts WHERE seq=5")   # chain alone cannot see this
        self.assertEqual(core.verify_all()["NET-1004"][0], "VERIFIED")
        ok, msg = core.anchor_check(); self.assertFalse(ok); self.assertIn("TAIL TRUNCATION", msg)
        with core.conn() as c: c.execute("UPDATE alerts SET payload=? WHERE seq=2", ("{}",))
        self.assertNotEqual(core.live_result("NET-1002"), "VERIFIED")
    def test_5_collector_authenticates_senders(self):
        ev = sample_data.make_event(random.Random(1), "SENSOR-X-1", "FW-EDGE-01")
        self.assertEqual(collector.process({"record": ev, "mac": "0" * 64})["status"], "rejected")
        self.assertEqual(collector.process({"record": ev, "mac": netproto.mac_for(ev)})["status"], "sealed")
        self.assertEqual(collector.process({"record": ev, "mac": netproto.mac_for(ev)})["status"], "rejected")
if __name__ == "__main__": unittest.main()

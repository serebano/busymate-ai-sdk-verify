import json, os, unittest
from busymate_verify import BusymateActorError, MemoryReplayCache, verify_busymate_actor, require_confirmed, Actor

V = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "vectors", "actor-v3.json")))


def run(case, call, cache):
    cfg = {**V["config"], **case.get("options", {}), **call.get("options", {})}
    return verify_busymate_actor(call["headers"], audience=cfg["audience"], tenant_id=cfg["tenant_id"], connector_id=cfg["connector_id"],
                                 idp=cfg.get("idp"), tool=cfg.get("tool"), jwks=V["jwks"], now=V["now"], replay_cache=cache)


class Vectors(unittest.TestCase):
    pass


def make(case):
    def t(self):
        cache = MemoryReplayCache()
        for call in case["calls"]:
            exp = call["expect"]
            if exp["ok"]:
                a = run(case, call, cache)
                e = exp["actor"]
                self.assertEqual((a.sub, a.idp, a.confirmed, a.tool, a.jti, a.support_session_id, a.host_account, a.host_env, a.host_user),
                                 (e["sub"], e["idp"], e["confirmed"], e["tool"], e["jti"], e.get("supportSessionId"),
                                  e.get("hostAccount"), e.get("hostEnv"), e.get("hostUser")))
            else:
                with self.assertRaises(BusymateActorError) as cm:
                    run(case, call, cache)
                self.assertEqual(cm.exception.reason, exp["reason"])
    return t


for c in V["cases"]:
    setattr(Vectors, "test_" + c["name"], make(c))


class ReplayWindow(unittest.TestCase):
    def test_replay_at_exp_plus_5_is_refused(self):
        import base64
        call = next(c for c in V["cases"] if c["name"] == "replay")["calls"][0]
        body = call["headers"]["X-Bmai-Actor"].split(".")[1]
        exp = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))["exp"]
        cache, cfg = MemoryReplayCache(), V["config"]
        go = lambda now: verify_busymate_actor(call["headers"], audience=cfg["audience"], tenant_id=cfg["tenant_id"],
                                               connector_id=cfg["connector_id"], jwks=V["jwks"], now=now, replay_cache=cache)
        go(exp - 5)
        with self.assertRaises(BusymateActorError) as cm:
            go(exp + 5)
        self.assertEqual(cm.exception.reason, "replay")


class Helpers(unittest.TestCase):
    def test_require_confirmed(self):
        require_confirmed(Actor("a", "i", True, "t", "j"))
        with self.assertRaises(BusymateActorError) as cm:
            require_confirmed(Actor("a", "i", False, "t", "j"))
        self.assertEqual(cm.exception.reason, "confirmation_required")


if __name__ == "__main__":
    unittest.main()

"""Scenario 2 - security teams: tamper-evidence, provable refusal, revocation.

Security doesn't ask "is the agent smart" -- it asks "if something goes wrong,
can we prove what happened, and can we cut access instantly?" Three SENTINEL
rules answer that: S4 (immutable record), S7 (provable refusal), S2 (least
authority + immediate revocation). This demo shows all three working on the
real ledger and warden.
"""
from _common import rule, require, suite_status


def main() -> None:
    rule("TAMPER-EVIDENCE & REFUSAL  -  S4 immutable record, S7 provable refusal")
    suite_status()
    if not require("sentinel_policy", "agentledger", "repo_warden"):
        return

    from sentinel_policy import Policy, rule as doctrine_rule
    from agentledger import PolicyGate, Recorder
    from repo_warden import Action, Store as WardenStore, Warden

    policy = Policy.from_dict({
        "name": "least-authority",
        "default": "deny",
        "rules": [
            {"id": "reads-ok", "doctrine": "S2", "effect": "allow",
             "match": {"action": "read.*"}},
            {"id": "no-exfil", "doctrine": "S6", "effect": "deny",
             "match": {"action": "export", "params.dest": {"eq": "external"}}},
        ],
    })
    gate = PolicyGate(default_allow=False).use(policy.as_gate_evaluator(defer_on_default=False))
    rec = Recorder(gate=gate)

    # S7: a refused directive is RECORDED with the rule and reason -- silence is
    # not a valid outcome.
    print("\nS7 provable refusal -- a denied action leaves a record, not a gap:")
    d, e = rec.submit("agent:scraper", "export", {"dest": "external", "rows": 50000})
    s7 = doctrine_rule("S7")
    print(f"   [{e.seq}] export(dest=external) -> allowed={d.allowed} rule={d.rule} "
          f"(doctrine {d.doctrine})")
    print(f"          recorded refusal honors {s7.id} {s7.name!r}: {s7.statement}")

    # generate a little more audited activity
    rec.submit("agent:reader", "read.config", {"key": "db.url"})
    rec.submit("agent:reader", "read.metrics", {"window": "1h"})

    print("\nS4 immutable record -- the ledger is hash-chained:")
    for ent in rec.entries():
        print(f"   #{ent.seq}  {ent.actor:<16} {ent.action:<14} {ent.entry_hash[:12]}...")
    ok, broken = rec.verify()
    print(f"   verify() -> intact={ok} first_broken={broken}")

    # tamper with a row directly in the backing DB, bypassing append()
    rec.ledger.conn.execute(
        "UPDATE entries SET action='read.config_HACKED' WHERE seq=("
        "SELECT MIN(seq) FROM entries WHERE action LIKE 'read.%')")
    rec.ledger.conn.commit()
    ok2, broken2 = rec.verify()
    print(f"   after editing one row directly in the DB -> intact={ok2} "
          f"first_broken={broken2}  <- the chain catches it")

    # S2 + immediate revocation on the warden side
    print("\nS2 least authority -- a leaked token is revocable instantly:")
    ws = WardenStore()
    token, info = ws.issue_token("ci-bot", {"repo:read"}, "acme/*")
    warden = Warden(ws)
    before = warden.authorize(token, Action("read", "acme/api"))
    blocked = warden.authorize(token, Action("read", "other-org/secrets"))
    ws.revoke_token(info.id)
    after = warden.authorize(token, Action("read", "acme/api"))
    print(f"   read acme/api before revoke   -> allowed={before.allowed} ({before.rule})")
    print(f"   read other-org/secrets        -> allowed={blocked.allowed} ({blocked.rule}) "
          "<- namespace bound")
    print(f"   read acme/api after revoke    -> allowed={after.allowed} ({after.rule}) "
          "<- cut instantly")

    print("\nProve what happened, prove what was refused, and cut access on demand.")


if __name__ == "__main__":
    main()

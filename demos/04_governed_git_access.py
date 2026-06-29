"""Scenario 4 - platform engineering: governed git access for agents and CI.

Agents and humans push to the same repos. Platform teams need them to get
access the same headless way (no embedded secrets, no browser on a CI box),
bounded to a namespace, and stopped at protected branches -- without migrating
off the git host they already run. That's repo-warden: RFC 8628 device flow +
scoped tokens + a branch-protection policy you can drop in as a pre-receive
hook. This demo runs the full grant-then-enforce path.
"""
from _common import rule, require, suite_status


def main() -> None:
    rule("GOVERNED GIT ACCESS  -  device-flow grant, scoped token, branch protection")
    suite_status()
    if not require("repo_warden"):
        return

    from repo_warden import Action, BranchPolicy, Store as WardenStore, Warden, DeviceFlow

    ws = WardenStore()
    flow = DeviceFlow(ws, verification_uri="https://warden.acme.internal/device")

    # 1. RFC 8628 device flow: a headless agent asks for authorization, a human
    #    approves the short user_code out of band, then the agent polls and gets
    #    its token exactly once.
    print("\n1) device-flow grant (RFC 8628) for a headless agent:")
    grant = flow.start_authorization("ci-agent", {"branch:push"}, namespace="acme/*")
    print(f"   user_code={grant['user_code']}  verify at {grant['verification_uri']}")
    pending = flow.poll(grant["device_code"])
    print(f"   agent polls -> {pending.get('error')}  (waiting on a human)")
    flow.approve(grant["user_code"], subject="agent:ci")
    delivered = flow.poll(grant["device_code"], now=grant_now(grant))
    token = delivered["access_token"]
    print(f"   human approves; agent polls -> token delivered "
          f"(scope={delivered['scope']}, namespace={delivered['namespace']})")

    # 2. Branch-protection policy: master is protected; force-push disabled.
    warden = Warden(ws, BranchPolicy(protected=["master", "release/*"],
                                     allow_force=False))

    print("\n2) the same token, enforced against the branch-protection policy:")
    checks = [
        ("read",  Action("read",  "acme/api")),
        ("push feature",  Action("push", "acme/api", "feature/login")),
        ("push master",   Action("push", "acme/api", "master")),
        ("force-push",    Action("push", "acme/api", "feature/login", force=True)),
        ("push other-org", Action("push", "other-org/secrets", "feature/x")),
    ]
    for label, action in checks:
        d = warden.authorize(token, action)
        verdict = "ALLOW" if d.allowed else "DENY "
        print(f"   {verdict} {label:<14} -> rule={d.rule}"
              + (f"  ({d.reason})" if d.reason else ""))

    # 3. branch:admin lifts the protected-branch restriction for a release bot.
    print("\n3) a release bot with branch:admin can land on master:")
    admin_token, _ = ws.issue_token("release-bot", {"branch:admin"}, "acme/*")
    d = warden.authorize(admin_token, Action("push", "acme/api", "master"))
    print(f"   push master with branch:admin -> allowed={d.allowed} (rule={d.rule})")

    print("\nOne governed access path for every agent and human -- on the host you already run.")


def grant_now(grant: dict) -> float:
    """Advance past the poll interval so the second poll isn't 'slow_down'."""
    import time
    return time.time() + grant["interval"] + 1


if __name__ == "__main__":
    main()

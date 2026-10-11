"""Shared playthrough helpers for engine and API tests."""
from blue_phishing import engine


def step(action, target=None, params=None):
    return {"action": action, "target": target, "params": params}


def confirmed(action, target=None):
    return step(action, target, {"confirm": True})


def _evidence_actions(scenario):
    """Invert the disclosure map: evidence id -> (action, target)."""
    inv = {}
    for key, ids in scenario["evidence_map"].items():
        action, _, target = key.partition("@")
        for ev in ids:
            inv.setdefault(ev, (action, target or None))
    return inv


def closure_params(scenario, supporting=None, **overrides):
    gt = scenario["ground_truth"]
    users = {u["id"]: u for u in scenario["target"]["users"]}
    params = {
        "classification": gt["classification"],
        "severity": gt["true_severity"],
        "root_cause": gt["root_cause"],
        "affected_user_ids": list(gt["affected_users"]),
        "affected_asset_ids": list(gt["affected_assets"]),
        "residual_risk": "none",
        "evidence_preserved": True,
        "supporting_evidence_ids": supporting if supporting is not None
        else gt["critical_evidence"][:8],
        "summary": "Contained the phishing incident, removed persistence and verified recovery.",
    }
    params.update(overrides)
    return params


def expert_steps(scenario, include_close=True):
    """Priority-ordered steps that investigate just enough, contain early,
    then complete the investigation. Order matters for attacker progression."""
    gt = scenario["ground_truth"]
    users = gt["users"]
    primary_alert = next(a for a in scenario["alerts"] if a["is_primary"])["id"]
    compromised = [u for u, g in users.items() if g["compromised"]]
    infected = [u for u, g in users.items() if g["endpoint_malware"]]
    required = gt["required_response"]
    steps = []

    steps.append(step("select_alert", primary_alert))
    for alert in scenario["alerts"]:
        if not alert["is_primary"]:
            steps.append(step("select_alert", alert["id"]))
    for alert in scenario["alerts"]:
        steps.append(step("triage_alert", alert["id"],
                          {"disposition": gt["alert_truth"][alert["id"]]}))
    steps += [step("open_email"), step("reveal_link", "LINK-1"), step("inspect_url", "LINK-1"),
              step("search_siem", "proxy_dns"), step("search_siem", "mail_delivery")]

    if not (compromised or infected):
        # Nothing was compromised: removing the message early is what stops the
        # recipient interacting with it again.
        for uid in users:
            steps.append(confirmed("quarantine_email", uid))
        steps += [confirmed("block_indicator", "IND-LURE-DOMAIN"), confirmed("block_indicator", "IND-SENDER")]
    first = True
    for uid in compromised:
        steps += [step("analyze_auth_logs", uid), step("preserve_evidence", f"EV-AUTH-{uid}"),
                  confirmed("revoke_sessions", uid), confirmed("remove_mailbox_rule", uid),
                  confirmed("reset_account", uid)]
        if first and infected:
            for iu in infected:
                steps += [step("investigate_endpoint", iu), confirmed("isolate_endpoint", iu)]
            first = False
        steps.append(confirmed("enforce_mfa", uid))
    if not compromised:
        for iu in infected:
            steps += [step("investigate_endpoint", iu), confirmed("isolate_endpoint", iu)]
    for iu in infected:
        steps += [step("preserve_evidence", f"EV-ENDPT-{iu}"), confirmed("endpoint_cleanup", iu)]

    # everything else that counts as critical evidence
    inv = _evidence_actions(scenario)
    for ev in gt["critical_evidence"]:
        action, target = inv[ev]
        steps.append(step(action, target))
    # verify each indicator we will block
    ioc_tool = {"sender_domain": "domain_reputation", "domain": "domain_reputation",
                "ip": "ip_reputation", "url": "url_reputation", "hash": "hash_lookup"}
    ind = {i["id"]: i for i in scenario["indicators"]}
    for req in required:
        if req["action"] == "block_indicator":
            steps.append(step("ioc_lookup", f"{req['target']}:{ioc_tool[ind[req['target']]['type']]}"))
    for ev in gt["required_preservation"]:
        steps.append(step("preserve_evidence", ev))
    for req in required:
        if req["action"] in ("quarantine_email", "block_indicator"):
            steps.append(confirmed(req["action"], req["target"]))
    for req in required:
        if req["category"] == "remediation" or req["action"] in ("revoke_sessions", "isolate_endpoint"):
            steps.append(confirmed(req["action"], req["target"]))
    for uid in (u["id"] for u in scenario["target"]["users"]):
        steps += [step("analyze_auth_logs", uid)]
    steps += [step("verify_containment"), step("verify_remediation")]
    if include_close:
        steps.append(step("close_incident", None, closure_params(scenario)))
    return steps


def _valid_now(scenario, sim, s):
    """True when the engine would accept this step without a penalty."""
    action, target = s["action"], s["target"]
    if action not in scenario["allowed_actions"] or sim["closed"]:
        return False
    if action not in engine.NO_TARGET_ACTIONS and target is None:
        return False
    if engine._validate_target(scenario, sim, action, target):
        return False
    if engine._prereq_failures(scenario, sim, action, target):
        return False
    key = engine.done_key(action, None if action in engine.NO_TARGET_ACTIONS else target)
    if action not in engine.REPEATABLE_ACTIONS and key in engine.done_keys(sim):
        return False
    return True


def solve(scenario, steps=None, sim=None, timeline=None, now=None, elapsed=10):
    """Run steps in priority order, retrying later any step whose prerequisites
    become satisfied by discoveries. Never issues an invalid action."""
    steps = list(steps if steps is not None else expert_steps(scenario))
    if sim is None:
        sim, timeline = engine.new_sim(scenario, now)
    results = []
    pending = steps
    progressed = True
    while pending and progressed:
        progressed = False
        remaining = []
        for s in pending:
            if _valid_now(scenario, sim, s):
                res = engine.apply_action(scenario, sim, timeline, s["action"], s["target"],
                                          s["params"], now=now, elapsed_seconds=elapsed)
                results.append((s["action"], s["target"], res))
                progressed = True
            else:
                remaining.append(s)
        pending = remaining
    return sim, timeline, results, pending


def fresh(scenario):
    return engine.new_sim(scenario)


def act(scenario, sim, timeline, action, target=None, params=None, elapsed=10):
    return engine.apply_action(scenario, sim, timeline, action, target, params,
                               elapsed_seconds=elapsed)


def open_incident(scenario, sim, timeline):
    """Select and open the primary alert (the entry point of every investigation)."""
    pid = next(a for a in scenario["alerts"] if a["is_primary"])["id"]
    res = act(scenario, sim, timeline, "select_alert", pid)
    assert res["ok"], res
    return pid


def primary_alert_id(scenario):
    return next(a for a in scenario["alerts"] if a["is_primary"])["id"]


def solve_sequence(scenario, steps=None, include_close=True):
    """The exact sequence of accepted steps (with params) an expert run executes,
    so API tests can replay it over HTTP."""
    steps = list(steps if steps is not None else expert_steps(scenario, include_close))
    sim, timeline = engine.new_sim(scenario)
    executed, pending, progressed = [], steps, True
    while pending and progressed:
        progressed, remaining = False, []
        for s in pending:
            if _valid_now(scenario, sim, s):
                engine.apply_action(scenario, sim, timeline, s["action"], s["target"], s["params"],
                                    elapsed_seconds=10)
                executed.append(s)
                progressed = True
            else:
                remaining.append(s)
        pending = remaining
    return executed

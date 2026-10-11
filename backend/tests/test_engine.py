"""Deterministic simulation engine: rules, disclosure, state, scoring."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from helpers import (  # noqa: E402
    act, closure_params, confirmed, expert_steps, fresh, open_incident,
    primary_alert_id, solve, step,
)

from blue_phishing import engine  # noqa: E402
from blue_phishing.composer import compose_scenario  # noqa: E402
from blue_phishing.scenario_schema import validate_seed  # noqa: E402
from blue_phishing.templates import (  # noqa: E402
    build_template_scenario, get_template_seed, template_archetypes,
)

CONFIRM = {"confirm": True}


def by_arch(name, difficulty=None):
    if difficulty is None:
        return build_template_scenario(name)
    seed = get_template_seed(name)
    seed["difficulty"] = difficulty
    return compose_scenario(validate_seed(seed))


def started(name_or_scenario):
    sc = by_arch(name_or_scenario) if isinstance(name_or_scenario, str) else name_or_scenario
    sim, tl = fresh(sc)
    open_incident(sc, sim, tl)
    return sc, sim, tl


# ================================================================ full runs

def test_expert_run_scores_maximum_and_contains(scenario):
    sim, _, results, _ = solve(scenario)
    failed = [(a, t, r["error"]) for a, t, r in results if not r["ok"]]
    assert not failed, failed
    score = engine.compute_score(scenario, sim, 10)
    assert score["total"] == engine.MAX_SCORE
    assert sim["closed"] and sim["outcome"] == "contained" and sim["penalties"] == []


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
@pytest.mark.parametrize("archetype", list(template_archetypes()))
def test_every_type_and_difficulty_is_fully_solvable(archetype, difficulty):
    sc = by_arch(archetype, difficulty)
    sim, _, results, _ = solve(sc)
    assert not [r for _, _, r in results if not r["ok"]]
    assert sim["outcome"] == "contained"
    assert engine.compute_score(sc, sim, 10)["total"] == 1000


def test_categories_sum_to_the_maximum(scenario):
    score = engine.compute_score(scenario, fresh(scenario)[0])
    assert sum(c["max"] for c in score["categories"]) == engine.MAX_SCORE
    assert score["total"] == 0


def test_score_is_bounded_and_matches_breakdown(scenario):
    sim, _, _, _ = solve(scenario)
    score = engine.compute_score(scenario, sim, 10 ** 6)
    assert 0 <= score["total"] <= engine.MAX_SCORE
    assert score["total"] == max(0, min(1000, score["gross"] - score["penalty_total"]))
    assert all(c["detail"] for c in score["categories"])          # every category is explained


def test_slow_response_reduces_only_speed_points(scenario):
    sim, _, _, _ = solve(scenario)
    fast, slow = engine.compute_score(scenario, sim, 10), engine.compute_score(scenario, sim, 50_000)
    assert 0 < fast["total"] - slow["total"] <= 30


def test_different_paths_give_different_scores():
    sc = by_arch("credential_compromise")
    best, _, _, _ = solve(sc)
    lazy, tl = fresh(sc)
    open_incident(sc, lazy, tl)
    act(sc, lazy, tl, "open_email")
    assert engine.compute_score(sc, lazy)["total"] < engine.compute_score(sc, best)["total"]


# ================================================================ alert queue and triage

def test_initial_view_is_an_alert_queue_without_the_incident(scenario):
    sim, tl = fresh(scenario)
    view = engine.public_view(scenario, sim, tl)
    assert len(view["alerts"]) == len(scenario["alerts"]) >= 3
    assert view["incident"]["open"] is False and view["users"] == []
    assert view["email"] == {"opened": False, "available": False}
    for alert in view["alerts"]:
        assert set(alert) >= {"id", "title", "severity", "confidence", "source", "rule",
                              "detected_at", "description"}
        assert "detail" not in alert and "is_primary" not in alert and "truth" not in alert
        assert alert["selected"] is False and alert["triage"] is None


def test_queue_contains_unrelated_benign_alerts(scenario):
    truths = set(scenario["ground_truth"]["alert_truth"].values())
    assert "investigate_now" in truths and truths & {"close_benign", "monitor"}
    assert sum(1 for a in scenario["alerts"] if a["is_primary"]) == 1


def test_email_is_locked_until_the_real_alert_is_opened(scenario):
    sim, tl = fresh(scenario)
    res = act(scenario, sim, tl, "open_email")
    assert not res["ok"] and "alert" in res["error"].lower()
    decoy = next(a for a in scenario["alerts"] if not a["is_primary"])
    assert act(scenario, sim, tl, "select_alert", decoy["id"])["ok"]
    assert not act(scenario, sim, tl, "open_email")["ok"]          # a decoy does not open the incident
    view = engine.public_view(scenario, sim, tl)
    assert view["incident"]["open"] is False
    assert next(a for a in view["alerts"] if a["id"] == decoy["id"])["detail"]


def test_selecting_the_real_alert_opens_the_incident_and_identifies_the_recipient(scenario):
    sim, tl = fresh(scenario)
    pid = primary_alert_id(scenario)
    res = act(scenario, sim, tl, "select_alert", pid)
    assert res["ok"] and res["new_users"] == [scenario["target"]["primary_user_id"]]
    view = engine.public_view(scenario, sim, tl)
    assert view["incident"]["open"] and view["email"]["available"] and len(view["users"]) == 1
    assert sim["tick"] == 0                                          # triage does not start the attacker's clock


def test_public_incident_title_does_not_reveal_the_scenario(scenario):
    sc, sim, tl = started(scenario)
    title = engine.public_view(sc, sim, tl)["incident"]["title"]
    assert title.startswith("Suspicious email:") and sc["title"] not in title


def test_triage_requires_opening_the_alert_and_validates_the_disposition():
    sc = by_arch("no_compromise")
    sim, tl = fresh(sc)
    aid = sc["alerts"][0]["id"]
    assert not act(sc, sim, tl, "triage_alert", aid, {"disposition": "monitor"})["ok"]
    act(sc, sim, tl, "select_alert", aid)
    for bad in (None, {}, {"disposition": "ignore"}, {"disposition": 5}):
        assert not act(sc, sim, tl, "triage_alert", aid, bad)["ok"]
    assert act(sc, sim, tl, "triage_alert", aid, {"disposition": "monitor"})["ok"]
    assert act(sc, sim, tl, "triage_alert", aid, {"disposition": "close_benign"})["ok"]    # revisable
    assert sim["triage"][aid] == "close_benign"


def _triage_all(sc, sim, tl, disposition_for):
    for a in sc["alerts"]:
        act(sc, sim, tl, "select_alert", a["id"])
        act(sc, sim, tl, "triage_alert", a["id"], {"disposition": disposition_for(a)})


def test_prioritisation_rewards_correct_triage_and_penalises_dismissing_the_real_alert():
    sc = by_arch("credential_compromise")
    truth = sc["ground_truth"]["alert_truth"]

    right, tl = fresh(sc)
    _triage_all(sc, right, tl, lambda a: truth[a["id"]])
    assert next(c for c in engine.compute_score(sc, right)["categories"]
                if c["id"] == "prioritization")["earned"] == 60

    wrong, tl = fresh(sc)
    _triage_all(sc, wrong, tl, lambda a: "close_benign" if a["is_primary"] else "investigate_now")
    score = engine.compute_score(sc, wrong)
    assert next(c for c in score["categories"] if c["id"] == "prioritization")["earned"] == 0
    assert any(p["code"] == "dismissed_real_alert" for p in score["penalties"])

    # changing your mind removes the penalty (it is derived from the final decision)
    pid = primary_alert_id(sc)
    act(sc, wrong, tl, "triage_alert", pid, {"disposition": "investigate_now"})
    assert not any(p["code"] == "dismissed_real_alert"
                   for p in engine.compute_score(sc, wrong)["penalties"])


def test_decoys_triaged_as_investigate_now_earn_nothing():
    sc = by_arch("no_compromise")
    sim, tl = fresh(sc)
    _triage_all(sc, sim, tl, lambda a: "investigate_now")
    rows = engine._triage_points(sc, sim)
    assert [pts for a, _, _, pts in rows if a["is_primary"]] == [1.0]
    assert all(pts == 0.0 for a, _, _, pts in rows if not a["is_primary"])


# ================================================================ hidden information

LEAK_KEYS = ("ground_truth", "critical_evidence", "required_response", "simulated_events",
             "kill_chain", "malicious_indicator_ids", "required_preservation", "alert_truth",
             "session_active", "endpoint_malware", "evidence_catalog", "evidence_map",
             "destructive_guard", "root_cause", "affected_assets", '"crit"',
             '"truth"', '"malicious"')


def test_initial_view_hides_ground_truth(scenario):
    sim, timeline = fresh(scenario)
    blob = json.dumps(engine.public_view(scenario, sim, timeline))
    for key in LEAK_KEYS:
        assert key not in blob
    assert scenario["attack_objective"] not in blob and scenario["title"] not in blob
    for ind in scenario["indicators"]:
        assert ind["value"] not in blob
    assert json.loads(blob)["evidence"] == []


def test_view_never_leaks_at_any_point_of_a_run(scenario):
    sim, timeline = fresh(scenario)
    pending = expert_steps(scenario)
    from helpers import _valid_now
    for _ in range(3):
        for s in list(pending):
            if _valid_now(scenario, sim, s):
                engine.apply_action(scenario, sim, timeline, s["action"], s["target"],
                                    s["params"], elapsed_seconds=5)
                pending.remove(s)
                view = engine.public_view(scenario, sim, timeline)
                blob = json.dumps(view)
                for key in LEAK_KEYS:
                    assert key not in blob, (s["action"], key)
                assert not any("is_primary" in a for a in view["alerts"])
                if not sim["closed"]:
                    assert scenario["attack_objective"] not in blob


def test_email_body_hidden_until_opened(scenario):
    sc, sim, tl = started(scenario)
    before = engine.public_view(sc, sim, tl)["email"]
    assert before["opened"] is False and "paragraphs" not in before and "sender_email" not in before
    act(sc, sim, tl, "open_email")
    after = engine.public_view(sc, sim, tl)["email"]
    assert after["opened"] and after["paragraphs"] and after["links"]
    assert "sha256" not in json.dumps(after)           # hash only after attachment analysis


def test_evidence_only_appears_after_the_right_action(scenario):
    sc, sim, tl = started(scenario)
    act(sc, sim, tl, "open_email")
    assert [e["id"] for e in engine.public_view(sc, sim, tl)["evidence"]] == ["EV-EMAIL"]
    act(sc, sim, tl, "analyze_headers")
    ids = [e["id"] for e in engine.public_view(sc, sim, tl)["evidence"]]
    assert "EV-HEADERS" in ids and "EV-AUTH-u1" not in ids


# ================================================================ evidence model

def test_evidence_carries_provenance_and_metadata(scenario):
    sc, sim, tl = started(scenario)
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "view_raw_headers")
    view = {e["id"]: e for e in engine.public_view(sc, sim, tl)["evidence"]}
    ev = view["EV-RAWHEADERS"]
    assert ev["provenance"] == {"action": "view_raw_headers", "target": None, "tick": 2}
    assert ev["discovered_at"] and ev["source_artifact"] and ev["category"] == "header"
    assert "EV-EMAIL" in ev["related"]                                  # only discovered items are linked
    assert all(r in view for r in ev["related"])


def test_related_evidence_never_points_to_undiscovered_items(scenario):
    sc, sim, tl = started(scenario)
    act(sc, sim, tl, "open_email")
    ev = engine.public_view(sc, sim, tl)["evidence"][0]
    assert ev["id"] == "EV-EMAIL" and "EV-HEADERS" not in ev["related"]


def test_repeated_actions_do_not_create_new_evidence(scenario):
    sc, sim, tl = started(scenario)
    act(sc, sim, tl, "open_email")
    n = len(sim["discovered_evidence"])
    assert act(sc, sim, tl, "open_email")["http"] == 409
    assert len(sim["discovered_evidence"]) == n


def test_evidence_differs_between_scenarios():
    a, b = by_arch("credential_compromise"), by_arch("no_compromise")
    assert a["evidence_catalog"]["EV-AUTH-u1"]["content"]["verdict"] != \
        b["evidence_catalog"]["EV-AUTH-u1"]["content"]["verdict"]


# ================================================================ email client

def test_raw_headers_and_each_header_field_are_inspectable(scenario):
    sc, sim, tl = started(scenario)
    assert not act(sc, sim, tl, "view_raw_headers")["ok"]                 # email not opened
    act(sc, sim, tl, "open_email")
    assert act(sc, sim, tl, "view_raw_headers")["ok"]
    for field in ("from", "reply_to", "return_path", "received"):
        assert act(sc, sim, tl, "inspect_header_field", field)["ok"], field
    assert not act(sc, sim, tl, "inspect_header_field", "x_secret")["ok"]
    assert "EV-FIELD-reply_to" in sim["discovered_evidence"]


def test_received_field_reveals_the_originating_server():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    assert "IND-SENDER-IP" not in sim["known_indicators"]
    act(sc, sim, tl, "inspect_header_field", "received")
    assert "IND-SENDER-IP" in sim["known_indicators"]


def test_spoofed_internal_sender_uses_the_company_domain_but_fails_dmarc():
    sc = by_arch("spoofed_internal")
    assert sc["email"]["sender_email"].endswith("@" + sc["company"]["domain"])
    assert sc["email"]["return_path"].split("@")[1] != sc["company"]["domain"]
    assert "DMARC" in sc["evidence_catalog"]["EV-HEADERS"]["content"]["fields"][4][0]
    assert "FAIL" in sc["evidence_catalog"]["EV-HEADERS"]["content"]["fields"][4][1]


def test_link_target_is_revealed_without_visiting_it(scenario):
    sc, sim, tl = started(scenario)
    act(sc, sim, tl, "open_email")
    res = act(sc, sim, tl, "reveal_link", "LINK-1")
    assert res["ok"] and {"IND-LURE-DOMAIN", "IND-URL-LURE"} <= set(res["new_indicators"])
    fields = dict(map(tuple, sc["evidence_catalog"]["EV-LINKTARGET-LINK-1"]["content"]["fields"]))
    assert fields["Actual target"].startswith("https://") and "Displayed as" in fields
    assert not act(sc, sim, tl, "reveal_link", "LINK-9")["ok"]


# ================================================================ IOC lab

def _known_iocs(name="credential_compromise"):
    sc, sim, tl = started(name)
    for s in ("open_email", ("reveal_link", "LINK-1"), ("inspect_url", "LINK-1"),
              ("inspect_header_field", "received")):
        action, target = (s, None) if isinstance(s, str) else s
        act(sc, sim, tl, action, target)
    return sc, sim, tl


def test_ioc_lookup_needs_a_known_indicator_and_a_valid_tool():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    assert not act(sc, sim, tl, "ioc_lookup", "IND-LURE-IP:ip_reputation")["ok"]      # not yet identified
    assert act(sc, sim, tl, "ioc_lookup", "IND-SENDER:domain_reputation")["ok"]
    for bad in ("IND-SENDER", "IND-SENDER:hash_lookup", "IND-SENDER:nope", ":domain_reputation",
                "IND-SENDER:url_reputation", 5, None):
        assert not act(sc, sim, tl, "ioc_lookup", bad)["ok"], bad


def test_ioc_results_are_scenario_and_indicator_specific():
    sc, sim, tl = _known_iocs()
    act(sc, sim, tl, "ioc_lookup", "IND-LURE-DOMAIN:domain_reputation")
    act(sc, sim, tl, "ioc_lookup", "IND-BRAND:domain_reputation")
    act(sc, sim, tl, "ioc_lookup", "IND-LURE-IP:ip_reputation")
    ev = {e["id"]: e for e in engine.public_view(sc, sim, tl)["evidence"]}
    bad = dict(map(tuple, ev["EV-IOC-IND-LURE-DOMAIN-domain_reputation"]["content"]["fields"]))
    good = dict(map(tuple, ev["EV-IOC-IND-BRAND-domain_reputation"]["content"]["fields"]))
    assert bad["Reputation"] == "MALICIOUS" and good["Reputation"] == "CLEAN"
    assert dict(map(tuple, ev["EV-IOC-IND-LURE-IP-ip_reputation"]["content"]["fields"]))["Reputation"] == "MALICIOUS"
    other = by_arch("multi_user_campaign")
    assert other["indicators"][0]["value"] != sc["indicators"][0]["value"]


def test_dns_analysis_and_related_search_reveal_more_infrastructure():
    sc, sim, tl = _known_iocs()
    assert act(sc, sim, tl, "ioc_lookup", "IND-LURE-DOMAIN:dns_analysis")["ok"]
    rel = act(sc, sim, tl, "ioc_lookup", "IND-SENDER:related_search")
    assert rel["ok"] and "IND-SENDER-IP" in sim["known_indicators"]
    rows = sc["evidence_catalog"]["EV-IOC-IND-SENDER-related_search"]["content"]["rows"]
    assert any(r[1] == sc["indicators"][0]["value"] or r[0] for r in rows)


def test_hash_lookup_only_applies_to_hashes_and_reveals_c2_for_malware():
    sc, sim, tl = started("malicious_attachment")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "inspect_attachment", "ATT-1")
    assert "IND-ATTACH-HASH" in sim["known_indicators"] and "IND-C2" in sim["known_indicators"]
    res = act(sc, sim, tl, "ioc_lookup", "IND-ATTACH-HASH:hash_lookup")
    assert res["ok"]
    fields = dict(map(tuple, sc["evidence_catalog"]["EV-IOC-IND-ATTACH-HASH-hash_lookup"]["content"]["fields"]))
    assert "dropper" in fields["Family"]
    assert not act(sc, sim, tl, "ioc_lookup", "IND-ATTACH-HASH:domain_reputation")["ok"]


def test_blocking_without_a_lookup_loses_indicator_verification_points():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "reveal_link", "LINK-1")
    base = next(c for c in engine.compute_score(sc, sim)["categories"] if c["id"] == "indicators")["earned"]
    act(sc, sim, tl, "ioc_lookup", "IND-LURE-DOMAIN:domain_reputation")
    after = next(c for c in engine.compute_score(sc, sim)["categories"] if c["id"] == "indicators")["earned"]
    assert after > base


# ================================================================ log viewer

def _logs_ready(name="credential_compromise"):
    sc, sim, tl = started(name)
    return sc, sim, tl


def test_logs_are_hidden_for_unidentified_users():
    sc = by_arch("multi_user_campaign")
    sim, tl = fresh(sc)
    assert engine.query_logs(sc, sim)["total"] == 0 or all(
        r["user_id"] is None for r in engine.query_logs(sc, sim)["rows"])
    open_incident(sc, sim, tl)
    ids = {r["user_id"] for r in engine.query_logs(sc, sim)["rows"]}
    assert ids <= {None, "u1"}
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "search_siem", "mail_delivery")
    assert {"u2", "u3"} <= {r["user_id"] for r in engine.query_logs(sc, sim)["rows"]}


def test_log_queries_change_the_displayed_results():
    sc, sim, tl = _logs_ready()
    everything = engine.query_logs(sc, sim)
    assert everything["total"] >= 10
    auth = engine.query_logs(sc, sim, source="auth")
    assert 0 < auth["total"] < everything["total"] and {r["source"] for r in auth["rows"]} == {"auth"}
    failures = engine.query_logs(sc, sim, source="auth", filters={"outcome": "failure"})
    assert 0 < failures["total"] < auth["total"]
    ip = sc["indicators"][-1]["value"]
    by_ip = engine.query_logs(sc, sim, filters={"source_ip": ip})
    assert by_ip["total"] >= 1 and all(r["src_ip"] == ip for r in by_ip["rows"])
    inbox = engine.query_logs(sc, sim, filters={"event_type": "InboxRuleCreated"})
    assert inbox["total"] == 1 and inbox["rows"][0]["src_ip"] == ip
    assert engine.query_logs(sc, sim, filters={"search": "forwards all mail"})["total"] == 1
    assert engine.query_logs(sc, sim, filters={"search": "zzzzzz"})["total"] == 0
    assert engine.query_logs(sc, sim, filters={"device": "unknown browser"})["total"] >= 2
    day = everything["rows"][0]["ts"][:10]
    assert engine.query_logs(sc, sim, filters={"from": day + " 00:00:00", "to": day + " 23:59:59"})["total"] >= 1
    assert engine.query_logs(sc, sim, filters={"from": "2999-01-01 00:00:00"})["total"] == 0
    assert engine.query_logs(sc, sim, filters={"user": "u1"})["total"] >= 5


def test_log_rows_are_sorted_and_omit_hidden_fields():
    sc, sim, tl = _logs_ready()
    rows = engine.query_logs(sc, sim)["rows"]
    assert [r["ts"] for r in rows] == sorted(r["ts"] for r in rows)
    assert "crit" not in json.dumps(rows) and set(rows[0]) >= {"id", "ts", "source", "user", "detail"}


def test_log_query_validation():
    sc, sim, tl = _logs_ready()
    with pytest.raises(ValueError):
        engine.query_logs(sc, sim, source="registry")
    with pytest.raises(ValueError):
        engine.query_logs(sc, sim, filters={"user": {"$ne": ""}})
    with pytest.raises(ValueError):
        engine.query_logs(sc, sim, filters={"search": "x" * 500})
    assert engine.query_logs(sc, sim, filters="not-a-dict")["total"] > 0


def test_querying_logs_does_not_change_state_or_score():
    sc, sim, tl = _logs_ready()
    before = (sim["tick"], engine.compute_score(sc, sim)["total"], len(tl),
              list(sim["discovered_evidence"]))
    for _ in range(5):
        engine.query_logs(sc, sim, filters={"search": "sign"})
    assert before == (sim["tick"], engine.compute_score(sc, sim)["total"], len(tl),
                      list(sim["discovered_evidence"]))


def test_collecting_a_log_record_creates_evidence_once():
    sc, sim, tl = _logs_ready()
    row = engine.query_logs(sc, sim, filters={"event_type": "InboxRuleCreated"})["rows"][0]
    assert row["collected"] is False
    res = act(sc, sim, tl, "collect_log", row["id"])
    assert res["ok"] and res["new_evidence"] == [f"EV-{row['id']}"]
    ev = next(e for e in engine.public_view(sc, sim, tl)["evidence"] if e["id"] == f"EV-{row['id']}")
    assert ev["provenance"]["action"] == "collect_log" and ev["category"] == "log"
    assert engine.query_logs(sc, sim, filters={"event_type": "InboxRuleCreated"})["rows"][0]["collected"]
    assert act(sc, sim, tl, "collect_log", row["id"])["http"] == 409


def test_cannot_collect_unknown_or_hidden_log_records():
    sc = by_arch("multi_user_campaign")
    sim, tl = fresh(sc)
    open_incident(sc, sim, tl)
    hidden = next(r for r in sc["logs"].values() if r["user_id"] == "u2")
    assert not act(sc, sim, tl, "collect_log", hidden["id"])["ok"]
    assert not act(sc, sim, tl, "collect_log", "LOG-9999")["ok"]
    assert not act(sc, sim, tl, "collect_log", None)["ok"]


def test_critical_log_records_count_towards_evidence_coverage():
    sc, sim, tl = _logs_ready()
    ev = lambda: next(c for c in engine.compute_score(sc, sim)["categories"] if c["id"] == "evidence")["earned"]  # noqa: E731
    before = ev()
    crit = [r for r in sc["logs"].values() if r["crit"]]
    assert crit
    act(sc, sim, tl, "collect_log", crit[0]["id"])
    assert ev() > before


# ================================================================ validation of actions

def test_unknown_action_is_rejected(scenario):
    sim, tl = fresh(scenario)
    for bad in ("drop_database", "", None, 5, ["open_email"], "OPEN_EMAIL"):
        res = act(scenario, sim, tl, bad)
        assert not res["ok"] and res["http"] == 400 and not res["persist"]
    assert sim["tick"] == 0


def test_action_not_offered_in_scenario_is_rejected():
    sc, sim, tl = started("no_compromise")
    res = act(sc, sim, tl, "isolate_endpoint", "u1", CONFIRM)
    assert not res["ok"] and res["http"] == 400
    offered = [a["action"] for a in engine.public_view(sc, sim, tl)["available_actions"]]
    assert "isolate_endpoint" not in offered and "endpoint_cleanup" not in offered
    assert "inspect_attachment" not in offered


def test_scenario_types_offer_different_tools():
    offered = {name: {a["action"] for a in engine.public_view(*[by_arch(name)] + list(fresh(by_arch(name))))["available_actions"]}
               for name in ("no_compromise", "malicious_attachment")}
    assert "endpoint_cleanup" in offered["malicious_attachment"]
    assert "endpoint_cleanup" not in offered["no_compromise"]


def test_bad_targets_are_rejected(scenario):
    sc, sim, tl = started(scenario)
    act(sc, sim, tl, "open_email")
    for action, target in [("inspect_url", "LINK-99"), ("inspect_url", None), ("search_siem", "everything"),
                           ("analyze_auth_logs", "u99"), ("block_indicator", "IND-NOPE"),
                           ("preserve_evidence", "EV-NOPE"), ("inspect_url", {"x": 1}),
                           ("quarantine_email", "../u1"), ("select_alert", "ALR-0"),
                           ("collect_log", "LOG-0")]:
        res = act(sc, sim, tl, action, target, CONFIRM)
        assert not res["ok"] and res["http"] == 400, (action, target)


def test_unidentified_user_cannot_be_targeted():
    sc, sim, tl = started("multi_user_campaign")
    act(sc, sim, tl, "open_email")
    res = act(sc, sim, tl, "analyze_auth_logs", "u3")
    assert not res["ok"] and res["http"] == 400
    assert res["error"] == act(sc, sim, tl, "analyze_auth_logs", "u99")["error"]       # no information leak


def test_users_are_revealed_by_siem_mail_search():
    sc, sim, tl = started("multi_user_campaign")
    act(sc, sim, tl, "open_email")
    assert sim["known_users"] == ["u1"]
    res = act(sc, sim, tl, "search_siem", "mail_delivery")
    assert res["ok"] and set(sim["known_users"]) == {"u1", "u2", "u3"} and set(res["new_users"]) == {"u2", "u3"}


def test_duplicate_actions_are_rejected_without_score_change(scenario):
    sc, sim, tl = started(scenario)
    act(sc, sim, tl, "open_email")
    score, tick = engine.compute_score(sc, sim)["total"], sim["tick"]
    res = act(sc, sim, tl, "open_email")
    assert not res["ok"] and res["http"] == 409 and not res["persist"]
    assert engine.compute_score(sc, sim)["total"] == score and sim["tick"] == tick


def test_investigation_prerequisites(scenario):
    sc, sim, tl = started(scenario)
    for action, target in [("analyze_headers", None), ("inspect_url", "LINK-1"), ("reveal_link", "LINK-1"),
                           ("view_raw_headers", None), ("set_assessment", None)]:
        res = act(sc, sim, tl, action, target, {"classification": "false_positive", "severity": "low"})
        assert not res["ok"] and res["http"] == 400 and not res["persist"]
    assert sim["penalties"] == []
    act(sc, sim, tl, "open_email")
    assert not act(sc, sim, tl, "search_siem", "proxy_dns")["ok"]              # needs the URL first
    assert act(sc, sim, tl, "inspect_url", "LINK-1")["ok"]
    assert act(sc, sim, tl, "search_siem", "proxy_dns")["ok"]


# ================================================================ confirmation and response

def test_consequential_actions_require_confirmation(scenario):
    sc, sim, tl = started(scenario)
    act(sc, sim, tl, "open_email")
    tick = sim["tick"]
    for params in (None, {}, {"confirm": False}, {"confirm": "yes"}, {"confirm": 1}):
        res = act(sc, sim, tl, "quarantine_email", "u1", params)
        assert not res["ok"] and res["confirmation_required"] and not res["persist"]
    assert sim["tick"] == tick and sim["env"]["users"]["u1"]["mailbox"] == "delivered"
    assert act(sc, sim, tl, "quarantine_email", "u1", CONFIRM)["ok"]


def test_confirmation_metadata_is_offered_for_every_consequential_action(scenario):
    sc, sim, tl = started(scenario)
    for a in engine.public_view(sc, sim, tl)["available_actions"]:
        if a["action"] in engine.RESPONSE_ACTIONS:
            assert a["confirm"] is True and a["impact"], a["action"]
        elif a["action"] not in ("close_incident",):
            assert a["confirm"] is False


def test_premature_response_is_blocked_and_penalised_once():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    res = act(sc, sim, tl, "revoke_sessions", "u1", CONFIRM)          # no auth analysis yet
    assert not res["ok"] and res["persist"] and res["penalty_points"] == 10
    assert sim["env"]["users"]["u1"]["session"] == "unknown"
    assert act(sc, sim, tl, "revoke_sessions", "u1", CONFIRM)["penalty_points"] == 0
    assert engine.compute_score(sc, sim)["penalty_total"] == 10


def test_premature_penalties_are_capped():
    sc, sim, tl = started("multi_user_campaign")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "search_siem", "mail_delivery")
    for uid in ("u1", "u2", "u3"):
        for action in ("revoke_sessions", "reset_account", "isolate_endpoint", "enforce_mfa",
                       "remove_mailbox_rule", "endpoint_cleanup"):
            act(sc, sim, tl, action, uid, CONFIRM)
    premature = sum(p["points"] for p in sim["penalties"] if p["code"] == "premature_action")
    assert premature == engine.SCORE_RULES["premature_penalty_cap"]


def test_state_transitions_are_observable():
    sc, sim, tl = started("multi_user_campaign")
    steps = [("open_email", None), ("inspect_url", "LINK-1"), ("search_siem", "proxy_dns"),
             ("search_siem", "mail_delivery"), ("analyze_auth_logs", "u1")]
    for action, target in steps:
        act(sc, sim, tl, action, target)
    users = lambda: {u["id"]: u for u in engine.public_view(sc, sim, tl)["users"]}  # noqa: E731
    assert users()["u1"]["session"] == "suspicious" and users()["u3"]["mailbox"] == "delivered"
    act(sc, sim, tl, "quarantine_email", "u2", CONFIRM)
    assert users()["u2"]["mailbox"] == "quarantined" and users()["u1"]["mailbox"] == "delivered"
    act(sc, sim, tl, "revoke_sessions", "u1", CONFIRM)
    assert users()["u1"]["session"] == "revoked"
    act(sc, sim, tl, "enforce_mfa", "u1", CONFIRM)
    assert users()["u1"]["mfa"] == "enforced"
    act(sc, sim, tl, "remove_mailbox_rule", "u1", CONFIRM)
    assert users()["u1"]["mailbox_rule"] == "removed"


def test_quarantining_one_mailbox_does_not_resolve_another_users_compromise():
    sc, sim, tl = started("credential_compromise")
    for s in ("open_email",):
        act(sc, sim, tl, s)
    act(sc, sim, tl, "quarantine_email", "u1", CONFIRM)
    assert not engine.containment_complete(sc, sim)
    remaining = [r for r in engine.required_status(sc, sim) if not r["done"]]
    assert any(r["action"] == "revoke_sessions" for r in remaining)


def test_blocking_marks_indicator_blocked_and_unknown_indicators_cannot_be_blocked():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    assert not act(sc, sim, tl, "block_indicator", "IND-ATTACKER-IP", CONFIRM)["ok"]
    act(sc, sim, tl, "reveal_link", "LINK-1")
    assert act(sc, sim, tl, "block_indicator", "IND-LURE-DOMAIN", CONFIRM)["ok"]
    assert [i for i in engine.public_view(sc, sim, tl)["indicators"] if i["id"] == "IND-LURE-DOMAIN"][0]["blocked"]
    assert act(sc, sim, tl, "block_indicator", "IND-URL-LURE", CONFIRM)["ok"]        # URLs can be blocked too


def test_endpoint_cleanup_requires_isolation_first():
    sc, sim, tl = started("malicious_attachment")
    for action, target in [("open_email", None), ("inspect_url", "LINK-1"), ("search_siem", "proxy_dns"),
                           ("investigate_endpoint", "u1")]:
        act(sc, sim, tl, action, target)
    assert not act(sc, sim, tl, "endpoint_cleanup", "u1", CONFIRM)["ok"]
    assert act(sc, sim, tl, "isolate_endpoint", "u1", CONFIRM)["ok"]
    assert act(sc, sim, tl, "endpoint_cleanup", "u1", CONFIRM)["ok"]
    assert engine.public_view(sc, sim, tl)["users"][0]["endpoint_state"] == "cleaned"


# ================================================================ false positives and destructive steps

def test_blocking_legitimate_vendor_domain_is_penalised():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    res = act(sc, sim, tl, "block_indicator", "IND-BRAND", CONFIRM)
    assert res["ok"] and res["penalty_points"] == 50 and res["feedback"]
    assert any(p["code"] == "blocked_legitimate" for p in sim["penalties"])


def test_unnecessary_disruption_in_no_compromise_scenarios():
    for name in ("no_compromise", "blocked_campaign", "spoofed_internal"):
        sc, sim, tl = started(name)
        act(sc, sim, tl, "open_email")
        act(sc, sim, tl, "analyze_auth_logs", "u1")
        for action in ("reset_account", "revoke_sessions"):
            res = act(sc, sim, tl, action, "u1", CONFIRM)
            assert res["ok"] and res["penalty_points"] == 30, (name, action)


def test_isolating_or_cleaning_a_clean_endpoint_is_penalised():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "investigate_endpoint", "u1")
    res = act(sc, sim, tl, "isolate_endpoint", "u1", CONFIRM)
    assert res["ok"] and res["penalty_points"] == 40
    assert "endpoint_cleanup" not in sc["allowed_actions"]


def test_enforcing_mfa_on_an_uncompromised_account_is_harmless_but_not_credited():
    sc, sim, tl = started("no_compromise")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "analyze_auth_logs", "u1")
    res = act(sc, sim, tl, "enforce_mfa", "u1", CONFIRM)
    assert res["ok"] and res["penalty_points"] == 0 and res["feedback"]


def test_removing_a_rule_that_does_not_exist_is_a_noop():
    sc, sim, tl = started("no_compromise")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "analyze_auth_logs", "u1")
    res = act(sc, sim, tl, "remove_mailbox_rule", "u1", CONFIRM)
    assert res["ok"] and "No suspicious" in res["message"] and res["penalty_points"] == 0


def test_removing_the_forwarding_rule_before_preserving_evidence_is_penalised():
    sc, sim, tl = started("credential_compromise")
    for action, target in [("open_email", None), ("inspect_url", "LINK-1"), ("search_siem", "proxy_dns"),
                           ("analyze_auth_logs", "u1")]:
        act(sc, sim, tl, action, target)
    res = act(sc, sim, tl, "remove_mailbox_rule", "u1", CONFIRM)
    assert res["ok"] and res["penalty_points"] == 30
    assert any(p["code"] == "destructive_before_preservation" for p in sim["penalties"])


def test_cleaning_an_endpoint_before_preserving_telemetry_is_penalised():
    sc, sim, tl = started("malicious_attachment")
    for action, target in [("open_email", None), ("inspect_url", "LINK-1"), ("search_siem", "proxy_dns"),
                           ("investigate_endpoint", "u1")]:
        act(sc, sim, tl, action, target)
    act(sc, sim, tl, "isolate_endpoint", "u1", CONFIRM)
    res = act(sc, sim, tl, "endpoint_cleanup", "u1", CONFIRM)
    assert res["penalty_points"] == 30 and "preserve" in res["feedback"][0].lower()


def test_preserving_first_avoids_the_destructive_penalty():
    sc, sim, tl = started("malicious_attachment")
    for action, target in [("open_email", None), ("inspect_url", "LINK-1"), ("search_siem", "proxy_dns"),
                           ("investigate_endpoint", "u1"), ("preserve_evidence", "EV-ENDPT-u1")]:
        act(sc, sim, tl, action, target)
    act(sc, sim, tl, "isolate_endpoint", "u1", CONFIRM)
    assert act(sc, sim, tl, "endpoint_cleanup", "u1", CONFIRM)["penalty_points"] == 0


def test_penalties_reduce_score_but_never_below_zero(scenario):
    sim, tl = fresh(scenario)
    sim["penalties"] = [{"code": "x", "points": 999, "message": "", "tick": 0, "key": None}]
    assert engine.compute_score(scenario, sim)["total"] == 0


# ================================================================ attacker progression

def _investigate_without_containing(sc, sim, tl, count=14):
    queue = [("open_email", None), ("reveal_link", "LINK-1"), ("inspect_url", "LINK-1"),
             ("search_siem", "proxy_dns"), ("search_siem", "mail_delivery"),
             ("analyze_auth_logs", "u1"), ("investigate_user", "u1"), ("investigate_endpoint", "u1"),
             ("analyze_headers", None), ("view_raw_headers", None), ("inspect_header_field", "from"),
             ("inspect_header_field", "reply_to"), ("inspect_header_field", "received"),
             ("inspect_header_field", "return_path"), ("ioc_lookup", "IND-SENDER:domain_reputation"),
             ("ioc_lookup", "IND-LURE-DOMAIN:domain_reputation"), ("inspect_url", "LINK-2"),
             ("reveal_link", "LINK-2")]
    alerts = []
    for action, target in queue[:count + 4]:
        alerts += act(sc, sim, tl, action, target)["alerts"]
    return alerts


def test_attacker_progresses_when_analyst_does_not_contain():
    sc, sim, tl = started("credential_compromise")
    alerts = _investigate_without_containing(sc, sim, tl)
    assert sim["impact"] >= 1 and any("forwarded" in a for a in alerts)
    assert "EV-LATE-RULE" in sim["discovered_evidence"] and any(t["kind"] == "attacker" for t in tl)
    assert any(p["code"] == "attack_progressed" for p in sim["penalties"])


def test_progression_is_averted_by_timely_containment():
    sc, sim, tl = started("credential_compromise")
    for action, target, params in [("open_email", None, None), ("inspect_url", "LINK-1", None),
                                   ("search_siem", "proxy_dns", None), ("analyze_auth_logs", "u1", None),
                                   ("preserve_evidence", "EV-AUTH-u1", None),
                                   ("revoke_sessions", "u1", CONFIRM), ("remove_mailbox_rule", "u1", CONFIRM),
                                   ("reset_account", "u1", CONFIRM)]:
        assert act(sc, sim, tl, action, target, params)["ok"]
    _investigate_without_containing.__globals__  # noqa: B018
    for action, target in [("analyze_headers", None), ("view_raw_headers", None),
                           ("inspect_header_field", "from"), ("inspect_header_field", "reply_to"),
                           ("inspect_header_field", "received"), ("reveal_link", "LINK-1"),
                           ("investigate_user", "u1"), ("investigate_endpoint", "u1")]:
        act(sc, sim, tl, action, target)
    assert sim["impact"] == 0 and sim["fired_events"] == []


def test_session_revocation_alone_does_not_stop_the_forwarding_rule():
    sc, sim, tl = started("credential_compromise")
    for action, target, params in [("open_email", None, None), ("inspect_url", "LINK-1", None),
                                   ("search_siem", "proxy_dns", None), ("analyze_auth_logs", "u1", None),
                                   ("revoke_sessions", "u1", CONFIRM)]:
        act(sc, sim, tl, action, target, params)
    alerts = []
    for action, target in [("analyze_headers", None), ("view_raw_headers", None),
                           ("inspect_header_field", "from"), ("inspect_header_field", "reply_to"),
                           ("inspect_header_field", "received"), ("reveal_link", "LINK-1"),
                           ("investigate_user", "u1"), ("investigate_endpoint", "u1"),
                           ("ioc_lookup", "IND-SENDER:domain_reputation")]:
        alerts += act(sc, sim, tl, action, target)["alerts"]
    assert any("forwarded" in a for a in alerts)


def test_infected_endpoints_attempt_lateral_movement_until_isolated():
    sc, sim, tl = started("malicious_attachment")
    alerts = []
    for action, target in [("open_email", None), ("inspect_url", "LINK-1"), ("search_siem", "proxy_dns"),
                           ("investigate_endpoint", "u1"), ("analyze_headers", None), ("view_raw_headers", None),
                           ("inspect_header_field", "from"), ("inspect_header_field", "reply_to"),
                           ("inspect_header_field", "received"), ("reveal_link", "LINK-1"),
                           ("analyze_auth_logs", "u1"), ("investigate_user", "u1"),
                           ("inspect_attachment", "ATT-1"), ("inspect_header_field", "return_path")]:
        alerts += act(sc, sim, tl, action, target)["alerts"]
    assert any("lateral" in a.lower() for a in alerts)


def test_progression_is_deterministic():
    runs = []
    for _ in range(2):
        sc = by_arch("credential_compromise")
        sim, tl = fresh(sc)
        open_incident(sc, sim, tl)
        _investigate_without_containing(sc, sim, tl)
        runs.append((sim["fired_events"], sim["impact"], engine.compute_score(sc, sim)["total"]))
    assert runs[0] == runs[1]


# ================================================================ verification and closure

def _ready_to_close(name="credential_compromise", skip=()):
    sc = by_arch(name)
    steps = [s for s in expert_steps(sc, include_close=False)
             if not (s["action"] in skip or (s["action"], s["target"]) in skip)]
    sim, tl, _, _ = solve(sc, steps)
    return sc, sim, tl


def test_verification_reports_gaps_then_success():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "quarantine_email", "u1", CONFIRM)
    res = act(sc, sim, tl, "verify_containment")
    assert res["ok"] and res["verification"]["complete"] is False and res["verification"]["lines"]
    rem = act(sc, sim, tl, "verify_remediation")
    assert rem["ok"] and rem["verification"]["complete"] is False
    assert act(sc, sim, tl, "verify_containment")["ok"]                          # repeatable
    good, gsim, gtl = _ready_to_close()
    assert gsim["verify_log"][-1]["complete"] and gsim["verify_rem_log"][-1]["complete"]


def test_verification_needs_at_least_one_response_action():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    assert not act(sc, sim, tl, "verify_containment")["ok"]
    assert not act(sc, sim, tl, "verify_remediation")["ok"]


def test_closing_requires_both_verifications():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "quarantine_email", "u1", CONFIRM)
    act(sc, sim, tl, "verify_containment")
    res = act(sc, sim, tl, "close_incident", None, closure_params(sc))
    assert not res["ok"] and "remediation" in res["error"].lower() and not sim["closed"]


@pytest.mark.parametrize("mutation", [
    {"classification": "alien"}, {"severity": "apocalyptic"}, {"root_cause": "bad luck"},
    {"residual_risk": "some"}, {"evidence_preserved": "yes"}, {"summary": "short"},
    {"summary": "x" * 3000}, {"affected_user_ids": ["u99"]}, {"affected_user_ids": "u1"},
    {"affected_asset_ids": ["NOT-AN-ASSET"]}, {"supporting_evidence_ids": ["EV-NOPE"]},
    {"supporting_evidence_ids": ["EV-AUTH-u1"] * 1 + ["x"] * 40},
])
def test_closure_submission_is_validated(mutation):
    sc, sim, tl = _ready_to_close()
    res = act(sc, sim, tl, "close_incident", None, closure_params(sc, **mutation))
    assert not res["ok"] and not sim["closed"]


def test_closure_cannot_cite_evidence_that_was_never_collected():
    sc, sim, tl = _ready_to_close()
    undiscovered = next(e for e in sc["evidence_catalog"] if e not in sim["discovered_evidence"])
    res = act(sc, sim, tl, "close_incident", None, closure_params(sc, supporting_evidence_ids=[undiscovered]))
    assert not res["ok"] and "collected" in res["error"]


def test_a_correct_closure_is_contained_and_scores_in_full():
    sc, sim, tl = _ready_to_close()
    res = act(sc, sim, tl, "close_incident", None, closure_params(sc))
    assert res["ok"] and sim["closed"] and sim["outcome"] == "contained"
    assert engine.compute_score(sc, sim, 10)["total"] == 1000
    assert not act(sc, sim, tl, "open_email")["ok"] and act(sc, sim, tl, "open_email")["http"] == 409


def test_closing_with_gaps_fails_and_is_penalised():
    sc, sim, tl = _ready_to_close(skip=(("reset_account", "u1"),))
    res = act(sc, sim, tl, "close_incident", None, closure_params(sc, residual_risk="none"))
    assert res["ok"] and sim["outcome"] == "failed" and res["penalty_points"] >= 50
    assert any(p["code"] == "closed_with_gaps" for p in sim["penalties"])
    report = engine.build_report(sc, sim, tl, 100)
    assert report["result"] == "failure" and report["evaluation"]["remaining_risks"]
    assert report["evaluation"]["residual_risk"]["expected"] == "medium"


def test_residual_risk_must_match_the_actual_exposure():
    sc, sim, tl = _ready_to_close(skip=(("reset_account", "u1"),))
    act(sc, sim, tl, "close_incident", None, closure_params(sc, residual_risk="medium"))
    right = next(c for c in engine.compute_score(sc, sim)["categories"] if c["id"] == "report")["earned"]
    sc2, sim2, tl2 = _ready_to_close(skip=(("reset_account", "u1"),))
    act(sc2, sim2, tl2, "close_incident", None, closure_params(sc2, residual_risk="none"))
    wrong = next(c for c in engine.compute_score(sc2, sim2)["categories"] if c["id"] == "report")["earned"]
    assert right - wrong == engine.SCORE_RULES["residual_risk_points"]


def test_report_accuracy_scores_root_cause_users_and_assets():
    sc, sim, tl = _ready_to_close("multi_user_campaign")
    act(sc, sim, tl, "close_incident", None, closure_params(
        sc, root_cause="no_user_interaction", affected_user_ids=["u1"], affected_asset_ids=[]))
    report = next(c for c in engine.compute_score(sc, sim)["categories"] if c["id"] == "report")
    assert 0 < report["earned"] < report["max"] and "root cause wrong" in report["detail"].lower()


def test_false_preservation_claim_is_penalised():
    sc, sim, tl = _ready_to_close(skip=("preserve_evidence",))
    res = act(sc, sim, tl, "close_incident", None, closure_params(sc, evidence_preserved=True))
    assert res["ok"] and any(p["code"] == "false_preservation_claim" for p in sim["penalties"])


def test_honest_preservation_answer_is_not_penalised():
    sc, sim, tl = _ready_to_close(skip=("preserve_evidence",))
    act(sc, sim, tl, "close_incident", None, closure_params(sc, evidence_preserved=False))
    assert not any(p["code"] == "false_preservation_claim" for p in sim["penalties"])


def test_citing_irrelevant_evidence_scores_less_than_citing_critical_evidence():
    results = {}
    for label, picker in (("critical", lambda sc, sim: sc["ground_truth"]["critical_evidence"][:6]),
                          ("benign", lambda sc, sim: [e for e in sim["discovered_evidence"]
                                                      if e not in sc["ground_truth"]["critical_evidence"]][:6])):
        sc, sim, tl = _ready_to_close()
        ids = picker(sc, sim)
        act(sc, sim, tl, "close_incident", None, closure_params(sc, supporting_evidence_ids=ids))
        results[label] = next(c for c in engine.compute_score(sc, sim)["categories"]
                              if c["id"] == "correlation")["earned"]
    assert results["critical"] > results["benign"]


def test_wrong_classification_loses_assessment_points():
    sc, sim, tl = _ready_to_close()
    act(sc, sim, tl, "close_incident", None, closure_params(sc, classification="false_positive", severity="low"))
    cat = next(c for c in engine.compute_score(sc, sim)["categories"] if c["id"] == "assessment")
    assert cat["earned"] == 0 and "incorrect" in cat["detail"]


def test_working_assessment_is_scored_until_closure_replaces_it():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    assert not act(sc, sim, tl, "set_assessment", None, {"classification": "alien", "severity": "high"})["ok"]
    assert act(sc, sim, tl, "set_assessment", None,
               {"classification": "credential_compromise", "severity": "medium"})["ok"]
    cat = lambda: next(c for c in engine.compute_score(sc, sim)["categories"] if c["id"] == "assessment")["earned"]  # noqa: E731
    assert cat() == 80
    act(sc, sim, tl, "set_assessment", None, {"classification": "credential_compromise", "severity": "high"})
    assert cat() == 100


# ================================================================ evidence preservation

def test_evidence_preservation_scoring():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    assert not act(sc, sim, tl, "preserve_evidence", "EV-HEADERS")["ok"]            # not collected
    assert act(sc, sim, tl, "preserve_evidence", "EV-EMAIL")["ok"]
    assert not act(sc, sim, tl, "preserve_evidence", "EV-EMAIL")["ok"]              # duplicate
    cat = next(c for c in engine.compute_score(sc, sim)["categories"] if c["id"] == "preservation")
    assert 0 < cat["earned"] < cat["max"]
    act(sc, sim, tl, "inspect_url", "LINK-1")
    assert not act(sc, sim, tl, "preserve_evidence", "EV-URL-LINK-1")["ok"]          # not a forensic artifact


# ================================================================ report

def test_report_has_every_required_section():
    sc = by_arch("multi_user_campaign")
    sim, tl, _, _ = solve(sc)
    report = engine.build_report(sc, sim, tl, 90)
    for key in ("score_breakdown", "evaluation", "findings", "evidence_collected", "indicators_discovered",
                "original_alerts", "debrief", "timeline", "duration_seconds", "log_lines"):
        assert key in report, key
    ev = report["evaluation"]
    for key in ("classification", "severity", "root_cause", "affected_users", "affected_assets",
                "residual_risk", "triage", "containment", "remediation", "preservation",
                "missed_evidence", "incorrect_decisions", "remaining_risks", "supporting_evidence"):
        assert key in ev, key
    assert report["score"] == 1000 and report["result"] == "success"
    assert report["debrief"]["ground_truth_timeline"] and report["debrief"]["lessons_learned"]
    assert all(e["provenance"] and e["discovered_at"] for e in report["evidence_collected"])
    assert {f["finding"] for f in report["findings"]} >= {"compromised account", "infected endpoint"}
    assert all(c["detail"] for c in report["score_breakdown"]["categories"])


def test_report_explains_missed_evidence_and_mistakes():
    sc, sim, tl = started("credential_compromise")
    act(sc, sim, tl, "open_email")
    act(sc, sim, tl, "block_indicator", "IND-BRAND", CONFIRM)
    for action, target in [("inspect_url", "LINK-1"), ("analyze_auth_logs", "u1"), ("search_siem", "proxy_dns")]:
        act(sc, sim, tl, action, target)
    act(sc, sim, tl, "quarantine_email", "u1", CONFIRM)
    act(sc, sim, tl, "verify_containment")
    act(sc, sim, tl, "verify_remediation")
    act(sc, sim, tl, "close_incident", None, closure_params(sc, supporting_evidence_ids=["EV-EMAIL"]))
    report = engine.build_report(sc, sim, tl, 100)
    ev = report["evaluation"]
    assert ev["missed_evidence"] and ev["containment"]["missing"]
    assert any(d["code"] == "blocked_legitimate" for d in ev["incorrect_decisions"])
    assert any("Verify" in r or "verify" in r for r in report["debrief"]["recommendations"])
    assert report["score"] < 500


def test_dismissed_alert_and_triage_appear_in_the_report():
    sc, sim, tl = started("no_compromise")
    pid = primary_alert_id(sc)
    act(sc, sim, tl, "triage_alert", pid, {"disposition": "close_benign"})
    report = engine.build_report(sc, sim, tl, 10)
    row = next(r for r in report["evaluation"]["triage"] if r["alert_id"] == pid)
    assert row["correct"] is False and row["expected"] == "investigate_now"
    assert any(d["code"] == "dismissed_real_alert" for d in report["evaluation"]["incorrect_decisions"])


# ================================================================ scenario variety

def test_scenario_types_have_different_ground_truth():
    gts = {a: by_arch(a)["ground_truth"] for a in template_archetypes()}
    assert gts["blocked_campaign"]["affected_users"] == [] and gts["no_compromise"]["affected_users"] == []
    assert gts["malicious_attachment"]["classification"] == "malware_infection"
    assert gts["malicious_attachment"]["affected_assets"]
    assert gts["spoofed_internal"]["root_cause"] == "spoofed_sender_social_engineering"
    assert gts["multi_user_campaign"]["root_cause"] == "multiple_vectors"
    assert len({g["classification"] for g in gts.values()}) >= 4


def test_blocked_campaign_has_several_recipients_and_no_impact():
    sc = by_arch("blocked_campaign")
    assert len(sc["target"]["users"]) == 3
    assert not any(g["opened"] or g["clicked"] for g in sc["ground_truth"]["users"].values())
    required = {(r["action"]) for r in sc["ground_truth"]["required_response"]}
    assert required == {"quarantine_email", "block_indicator"}


def test_malicious_attachment_needs_isolation_cleanup_and_c2_blocking():
    sc = by_arch("malicious_attachment")
    req = {(r["action"], r["target"]) for r in sc["ground_truth"]["required_response"]}
    assert ("isolate_endpoint", "u1") in req and ("endpoint_cleanup", "u1") in req
    assert ("block_indicator", "IND-C2") in req and ("reset_account", "u1") in req


def test_compromised_users_need_session_rule_reset_and_mfa():
    sc = by_arch("credential_compromise")
    req = {r["action"] for r in sc["ground_truth"]["required_response"]}
    assert {"revoke_sessions", "remove_mailbox_rule", "reset_account", "enforce_mfa"} <= req


def test_remediation_is_tracked_separately_from_containment():
    sc, sim, tl = started("credential_compromise")
    for action, target in [("open_email", None), ("inspect_url", "LINK-1"), ("search_siem", "proxy_dns"),
                           ("analyze_auth_logs", "u1")]:
        act(sc, sim, tl, action, target)
    act(sc, sim, tl, "quarantine_email", "u1", CONFIRM)
    cats = {c["id"]: c["earned"] for c in engine.compute_score(sc, sim)["categories"]}
    assert cats["containment"] > 0 and cats["remediation"] == 0


def test_objectives_progress_without_revealing_answers():
    sc = by_arch("credential_compromise")
    sim, tl = fresh(sc)
    labels = [o["label"] for o in engine.public_view(sc, sim, tl)["objectives"]]
    assert len(labels) == 8 and not any(o["done"] for o in engine.public_view(sc, sim, tl)["objectives"])
    open_incident(sc, sim, tl)
    assert next(o for o in engine.public_view(sc, sim, tl)["objectives"] if o["id"] == "open")["done"]
    sim2, tl2, _, _ = solve(sc)
    assert all(o["done"] for o in engine.public_view(sc, sim2, tl2)["objectives"])

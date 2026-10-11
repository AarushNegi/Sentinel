"""Flask API + MongoDB persistence for the Blue phishing simulation."""
import json
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from helpers import closure_params, confirmed, solve_sequence, step  # noqa: E402

GT_LEAKS = ("ground_truth", "critical_evidence", "required_response", "simulated_events",
            "kill_chain", "evidence_catalog", "malicious_indicator_ids", "session_active",
            "alert_truth", "destructive_guard", "required_preservation", '"crit"', '"truth"')


def post(client, url, headers, body=None):
    return client.post(url, headers=headers, data=json.dumps(body or {}),
                       content_type="application/json")


def start(client, headers, **body):
    return post(client, "/api/blue-phishing/start", headers, {"generator": "template", **body})


def send(client, headers, sid, s):
    body = {"action": s["action"]}
    if s["target"]:
        body["target"] = s["target"]
    if s["params"]:
        body["params"] = s["params"]
    return post(client, f"/api/blue-phishing/{sid}/action", headers, body)


def replay(client, headers, sid, steps):
    last = None
    for s in steps:
        last = send(client, headers, sid, s)
        assert last.status_code == 200, (s["action"], s["target"], last.get_json().get("error"))
    return last


def stored_scenario(db):
    return db.blue_phishing_sessions.find_one({}, sort=[("started_at", -1)])["scenario"]


def finish(client, h, db, archetype="credential_compromise"):
    sid = start(client, h, archetype=archetype).get_json()["session_id"]
    sc = stored_scenario(db)
    return sid, sc, replay(client, h, sid, solve_sequence(sc))


# ---------------------------------------------------------------- auth & ownership

def test_requires_authentication(app_client):
    client, _, _, _ = app_client
    for method, url in [("post", "/api/blue-phishing/start"),
                        ("post", "/api/blue-phishing/abc/action"),
                        ("post", "/api/blue-phishing/abc/query"),
                        ("post", "/api/blue-phishing/abc/complete"),
                        ("get", "/api/blue-phishing/abc/report"),
                        ("get", "/api/blue-phishing/ai-status")]:
        assert getattr(client, method)(url).status_code == 401, url


def test_invalid_session_id_is_rejected(app_client):
    client, token_for, _, _ = app_client
    h = token_for("alice")
    assert post(client, "/api/blue-phishing/not-an-id/action", h, {"action": "open_email"}).status_code == 400
    assert post(client, "/api/blue-phishing/not-an-id/query", h, {}).status_code == 400
    assert client.get("/api/blue-phishing/not-an-id/report", headers=h).status_code == 400
    assert post(client, "/api/blue-phishing/507f1f77bcf86cd799439011/action", h,
                {"action": "open_email"}).status_code == 404


def test_users_cannot_touch_each_others_sessions(app_client):
    client, token_for, db, _ = app_client
    alice, bob = token_for("alice"), token_for("bob")
    sid = start(client, alice).get_json()["session_id"]
    assert post(client, f"/api/blue-phishing/{sid}/action", bob, {"action": "select_alert", "target": "x"}).status_code == 404
    assert post(client, f"/api/blue-phishing/{sid}/query", bob, {"source": "auth"}).status_code == 404
    assert post(client, f"/api/blue-phishing/{sid}/complete", bob).status_code == 404
    assert client.get(f"/api/blue-phishing/{sid}/report", headers=bob).status_code == 404
    assert start(client, bob).get_json()["session_id"] != sid


# ---------------------------------------------------------------- start / resume

def test_start_returns_an_alert_queue_and_nothing_else(app_client):
    client, token_for, db, _ = app_client
    r = start(client, token_for("alice"))
    assert r.status_code == 201
    data = r.get_json()
    blob = json.dumps(data)
    assert data["success"] and data["resumed"] is False and data["status"] == "in_progress"
    assert len(data["alerts"]) >= 3 and data["incident"]["open"] is False
    assert data["evidence"] == [] and data["users"] == [] and data["score"] == 0
    assert data["email"] == {"opened": False, "available": False}
    for leak in GT_LEAKS:
        assert leak not in blob
    for a in data["alerts"]:
        assert "is_primary" not in a and "detail" not in a
    assert data["generation"] == {"source": "template", "model": None, "fallback": False,
                                  "fallback_reason": "template_requested", "duration_ms": data["generation"]["duration_ms"]}
    stored = db.blue_phishing_sessions.find_one({})
    assert "ground_truth" in stored["scenario"] and stored["version"] == 0 and stored["schema_version"] == 2


def test_ai_request_falls_back_when_ollama_is_down_and_says_so(app_client):
    client, token_for, db, _ = app_client
    r = post(client, "/api/blue-phishing/start", token_for("alice"), {"generator": "ai"})
    assert r.status_code == 201
    gen = r.get_json()["generation"]
    assert gen["source"] == "template" and gen["fallback"] is True
    assert gen["fallback_reason"] in ("ollama_unavailable", "timeout")
    assert db.blue_phishing_sessions.find_one({})["generation"]["fallback"] is True


def test_start_resumes_unfinished_session_with_all_progress(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    first = start(client, h).get_json()
    sc = stored_scenario(db)
    pid = next(a for a in sc["alerts"] if a["is_primary"])["id"]
    post(client, f"/api/blue-phishing/{first['session_id']}/action", h, {"action": "select_alert", "target": pid})
    post(client, f"/api/blue-phishing/{first['session_id']}/action", h,
         {"action": "triage_alert", "target": pid, "params": {"disposition": "investigate_now"}})
    post(client, f"/api/blue-phishing/{first['session_id']}/action", h, {"action": "open_email"})
    again = start(client, h)
    assert again.status_code == 200
    data = again.get_json()
    assert data["resumed"] is True and data["session_id"] == first["session_id"]
    assert data["email"]["opened"] and len(data["evidence"]) == 1 and data["users"]
    assert next(a for a in data["alerts"] if a["id"] == pid)["triage"] == "investigate_now"
    assert db.blue_phishing_sessions.count_documents({}) == 1


def test_evidence_timestamps_survive_a_resume(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h).get_json()["session_id"]
    sc = stored_scenario(db)
    pid = next(a for a in sc["alerts"] if a["is_primary"])["id"]
    post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "select_alert", "target": pid})
    live = post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "open_email"}).get_json()
    resumed = start(client, h).get_json()
    assert resumed["evidence"] == live["evidence"] and resumed["evidence"][0]["discovered_at"]


def test_restart_abandons_the_old_session(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    a = start(client, h).get_json()["session_id"]
    b = start(client, h, restart=True).get_json()["session_id"]
    assert a != b
    assert db.blue_phishing_sessions.find_one({"_id": __import__("bson").ObjectId(a)})["status"] == "abandoned"


def test_legacy_session_is_replaced_not_resumed(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    legacy = db.blue_phishing_sessions.insert_one({
        "user_id": "alice", "mode": "blue", "attack": "phishing", "status": "in_progress",
        "state": {}, "score": 50, "updated_at": datetime.now(timezone.utc)})
    r = post(client, f"/api/blue-phishing/{legacy.inserted_id}/action", h, {"action": "open_email"})
    assert r.status_code == 409 and r.get_json()["restart_required"] is True
    assert post(client, f"/api/blue-phishing/{legacy.inserted_id}/query", h, {}).status_code == 409
    new = start(client, h)
    assert new.status_code == 201 and new.get_json()["session_id"] != str(legacy.inserted_id)
    assert db.blue_phishing_sessions.find_one({"_id": legacy.inserted_id})["status"] == "abandoned"


def test_start_input_validation(app_client):
    client, token_for, _, _ = app_client
    h = token_for("alice")
    assert post(client, "/api/blue-phishing/start", h, {"generator": "gpt-cloud"}).status_code == 400
    assert post(client, "/api/blue-phishing/start", h, {"archetype": "ransomware"}).status_code == 400
    for archetype in ("multi_user_campaign", "blocked_campaign", "malicious_attachment", "spoofed_internal"):
        assert start(client, h, archetype=archetype, restart=True).status_code == 201


def test_database_failure_on_start_leaves_no_session_and_hides_details(app_client):
    client, token_for, db, server = app_client
    original = server.db.blue_phishing_sessions.insert_one
    server.db.blue_phishing_sessions.insert_one = lambda *_a, **_k: (_ for _ in ()).throw(
        RuntimeError("mongodb://user:secret@cluster is down"))
    try:
        r = start(client, token_for("alice"))
    finally:
        server.db.blue_phishing_sessions.insert_one = original
    assert r.status_code == 500
    body = r.get_data(as_text=True)
    assert "secret" not in body and "mongodb" not in body
    assert db.blue_phishing_sessions.count_documents({}) == 0


# ---------------------------------------------------------------- alert selection and actions

def test_selecting_an_alert_opens_the_matching_incident(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h).get_json()["session_id"]
    sc = stored_scenario(db)
    primary = next(a for a in sc["alerts"] if a["is_primary"])
    decoy = next(a for a in sc["alerts"] if not a["is_primary"])
    d = post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "select_alert", "target": decoy["id"]}).get_json()
    assert d["incident"]["open"] is False and d["users"] == []
    assert next(a for a in d["alerts"] if a["id"] == decoy["id"])["detail"]
    assert post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "open_email"}).status_code == 400
    d = post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "select_alert", "target": primary["id"]}).get_json()
    assert d["incident"]["open"] is True and d["email"]["available"] and len(d["users"]) == 1
    assert "paragraphs" not in d["email"]                      # opened, but not yet read


def test_action_updates_state_and_persists(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h).get_json()["session_id"]
    sc = stored_scenario(db)
    pid = next(a for a in sc["alerts"] if a["is_primary"])["id"]
    post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "select_alert", "target": pid})
    r = post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "open_email"})
    d = r.get_json()
    assert r.status_code == 200 and d["success"] and d["state"]["emailInspected"] is True
    assert [e["id"] for e in d["new_evidence"]] == ["EV-EMAIL"]
    assert d["score"] > 0 and d["score_delta"] == d["score"] and d["stage"] == "email"
    stored = db.blue_phishing_sessions.find_one({})
    assert stored["version"] == 2 and len(stored["actions"]) == 2
    assert stored["sim"]["discovered_evidence"] == ["EV-EMAIL"]
    assert stored["sim"]["evidence_log"]["EV-EMAIL"]["action"] == "open_email"


def test_invalid_and_duplicate_actions(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h).get_json()["session_id"]
    sc = stored_scenario(db)
    pid = next(a for a in sc["alerts"] if a["is_primary"])["id"]
    url = f"/api/blue-phishing/{sid}/action"
    assert post(client, url, h, {"action": "format_c"}).status_code == 400
    assert post(client, url, h, {}).status_code == 400
    assert client.post(url, headers=h, data="[1,2]", content_type="application/json").status_code == 400
    assert client.post(url, headers=h, data="not json", content_type="application/json").status_code == 400
    assert post(client, url, h, {"action": "analyze_headers"}).status_code == 400
    assert post(client, url, h, {"action": "select_alert", "target": pid}).status_code == 200
    dup = post(client, url, h, {"action": "select_alert", "target": pid})
    assert dup.status_code == 409 and dup.get_json()["success"] is False
    assert db.blue_phishing_sessions.find_one({})["version"] == 1


def test_confirmation_is_enforced_by_the_server(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h, archetype="credential_compromise").get_json()["session_id"]
    sc = stored_scenario(db)
    pid = next(a for a in sc["alerts"] if a["is_primary"])["id"]
    url = f"/api/blue-phishing/{sid}/action"
    post(client, url, h, {"action": "select_alert", "target": pid})
    post(client, url, h, {"action": "open_email"})
    version = db.blue_phishing_sessions.find_one({})["version"]
    r = post(client, url, h, {"action": "quarantine_email", "target": "u1"})
    assert r.status_code == 400 and r.get_json()["confirmation_required"] is True
    assert db.blue_phishing_sessions.find_one({})["version"] == version          # nothing saved
    r = post(client, url, h, {"action": "quarantine_email", "target": "u1", "params": {"confirm": True}})
    assert r.status_code == 200 and [u for u in r.get_json()["users"] if u["id"] == "u1"][0]["mailbox"] == "quarantined"


def test_browser_supplied_score_and_state_are_ignored(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h).get_json()["session_id"]
    sc = stored_scenario(db)
    pid = next(a for a in sc["alerts"] if a["is_primary"])["id"]
    r = post(client, f"/api/blue-phishing/{sid}/action", h, {
        "action": "select_alert", "target": pid, "score": 1000, "state": {"incidentClosed": True},
        "success": True, "ground_truth": {"x": 1}})
    d = r.get_json()
    assert d["score"] < 1000 and d["state"]["incidentClosed"] is False and d["status"] == "in_progress"


def test_premature_response_penalty_is_persisted(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h, archetype="credential_compromise").get_json()["session_id"]
    sc = stored_scenario(db)
    pid = next(a for a in sc["alerts"] if a["is_primary"])["id"]
    url = f"/api/blue-phishing/{sid}/action"
    post(client, url, h, {"action": "select_alert", "target": pid})
    post(client, url, h, {"action": "open_email"})
    r = post(client, url, h, {"action": "revoke_sessions", "target": "u1", "params": {"confirm": True}})
    assert r.status_code == 400 and r.get_json()["penalty_points"] == 10
    stored = db.blue_phishing_sessions.find_one({})
    assert stored["sim"]["penalties"][0]["code"] == "premature_action"
    assert stored["sim"]["env"]["users"]["u1"]["session"] == "unknown"
    assert len(stored["actions"]) == 2                                              # failed action not logged as done


def test_concurrent_modification_is_detected(app_client, monkeypatch):
    client, token_for, db, server = app_client
    h = token_for("alice")
    sid = start(client, h).get_json()["session_id"]
    pid = next(a for a in stored_scenario(db)["alerts"] if a["is_primary"])["id"]
    real = server.blue_engine.apply_action

    def racing(*a, **k):
        db.blue_phishing_sessions.update_one({}, {"$inc": {"version": 1}})
        return real(*a, **k)

    monkeypatch.setattr(server.blue_engine, "apply_action", racing)
    r = post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "select_alert", "target": pid})
    assert r.status_code == 409
    assert db.blue_phishing_sessions.find_one({})["sim"]["selected_alerts"] == []


def test_multi_target_state_persists_between_requests(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h, archetype="multi_user_campaign").get_json()["session_id"]
    pid = next(a for a in stored_scenario(db)["alerts"] if a["is_primary"])["id"]
    url = f"/api/blue-phishing/{sid}/action"
    post(client, url, h, {"action": "select_alert", "target": pid})
    post(client, url, h, {"action": "open_email"})
    d = post(client, url, h, {"action": "search_siem", "target": "mail_delivery"}).get_json()
    assert {u["id"] for u in d["users"]} == {"u1", "u2", "u3"}
    d = post(client, url, h, {"action": "quarantine_email", "target": "u2", "params": {"confirm": True}}).get_json()
    assert {u["id"]: u["mailbox"] for u in d["users"]} == {"u1": "delivered", "u2": "quarantined", "u3": "delivered"}


# ---------------------------------------------------------------- log queries

def _opened(client, h, db, archetype="credential_compromise"):
    sid = start(client, h, archetype=archetype).get_json()["session_id"]
    pid = next(a for a in stored_scenario(db)["alerts"] if a["is_primary"])["id"]
    post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "select_alert", "target": pid})
    return sid


def test_log_query_filters_and_changes_results(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = _opened(client, h, db)
    q = lambda **body: post(client, f"/api/blue-phishing/{sid}/query", h, body).get_json()  # noqa: E731
    everything = q()
    auth = q(source="auth")
    failures = q(source="auth", filters={"outcome": "failure"})
    assert everything["success"] and everything["total"] > auth["total"] > failures["total"] > 0
    assert q(filters={"search": "forwards all mail"})["total"] == 1
    assert q(filters={"search": "nothing-matches-this"})["total"] == 0
    assert q(filters={"event_type": "SignIn", "user": "u1"})["total"] >= 3


def test_log_query_does_not_change_the_session(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = _opened(client, h, db)
    before = db.blue_phishing_sessions.find_one({})
    for _ in range(3):
        post(client, f"/api/blue-phishing/{sid}/query", h, {"source": "proxy"})
    after = db.blue_phishing_sessions.find_one({})
    assert before["version"] == after["version"] and before["sim"] == after["sim"]


def test_log_query_never_returns_hidden_fields_or_unidentified_users(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = _opened(client, h, db, "multi_user_campaign")
    d = post(client, f"/api/blue-phishing/{sid}/query", h, {}).get_json()
    assert "crit" not in json.dumps(d) and {r["user_id"] for r in d["rows"]} <= {None, "u1"}


def test_log_query_validation(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = _opened(client, h, db)
    url = f"/api/blue-phishing/{sid}/query"
    assert post(client, url, h, {"source": "registry"}).status_code == 400
    assert post(client, url, h, {"filters": {"user": {"$ne": 1}}}).status_code == 400
    assert client.post(url, headers=h, data="[]", content_type="application/json").status_code == 400


def test_collecting_a_log_record_over_the_api(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = _opened(client, h, db)
    row = post(client, f"/api/blue-phishing/{sid}/query", h,
               {"filters": {"event_type": "InboxRuleCreated"}}).get_json()["rows"][0]
    r = post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "collect_log", "target": row["id"]})
    d = r.get_json()
    assert r.status_code == 200 and d["new_evidence"][0]["category"] == "log"
    again = post(client, f"/api/blue-phishing/{sid}/query", h, {"filters": {"event_type": "InboxRuleCreated"}}).get_json()
    assert again["rows"][0]["collected"] is True


# ---------------------------------------------------------------- completion & report

def test_full_workflow_to_report(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid, sc, final = finish(client, h, db)
    d = final.get_json()
    assert d["status"] == "completed" and d["closed"] and d["outcome"] == "contained" and d["score"] == 1000
    assert all(o["done"] for o in d["objectives"])
    assert db.blue_phishing_sessions.find_one({})["completed_at"] is not None

    rep = post(client, f"/api/blue-phishing/{sid}/complete", h)
    assert rep.status_code == 200
    body = rep.get_json()
    report = body["report"]
    assert report["score"] == 1000 and report["result"] == "success"
    assert report["mode"] == "blue" and report["attack"] == "phishing"
    assert report["evaluation"]["classification"]["correct"] and report["evaluation"]["root_cause"]["correct"]
    assert report["debrief"]["ground_truth_timeline"]                    # truth revealed only now
    assert report["evidence_collected"] and report["original_alerts"] and report["indicators_discovered"]
    assert report["target"]["name"] and report["log_lines"] and report["stages_completed"]
    assert "scenario" not in report and "ground_truth" not in report
    post(client, f"/api/blue-phishing/{sid}/complete", h)
    assert db.blue_phishing_reports.count_documents({}) == 1
    got = client.get(f"/api/blue-phishing/{sid}/report", headers=h).get_json()["report"]
    assert got["score"] == 1000 and got["session_id"] == sid and body["report_id"] == got["report_id"]


@pytest.mark.parametrize("archetype", ["no_compromise", "blocked_campaign", "spoofed_internal",
                                       "credential_compromise", "malicious_attachment", "multi_user_campaign"])
def test_every_scenario_type_completes_over_the_api(app_client, archetype):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    _, _, final = finish(client, h, db, archetype)
    assert final.get_json()["outcome"] == "contained" and final.get_json()["score"] == 1000


def test_report_and_complete_unavailable_before_closure(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h).get_json()["session_id"]
    assert post(client, f"/api/blue-phishing/{sid}/complete", h).status_code == 400
    assert client.get(f"/api/blue-phishing/{sid}/report", headers=h).status_code == 400
    assert db.blue_phishing_reports.count_documents({}) == 0


def test_partially_contained_incident_closes_as_a_failure(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h, archetype="credential_compromise").get_json()["session_id"]
    sc = stored_scenario(db)
    skip = {("reset_account", "u1"), ("enforce_mfa", "u1")}
    steps = [s for s in solve_sequence(sc, include_close=False) if (s["action"], s["target"]) not in skip]
    steps.append(step("close_incident", None, closure_params(sc, residual_risk="medium")))
    # re-run locally so verification reflects the skipped steps, then replay what is valid
    from helpers import solve
    seq = []
    import copy
    sim_steps = solve_sequence(sc, steps=steps)
    last = replay(client, h, sid, sim_steps).get_json()
    assert last["outcome"] == "failed" and last["score"] < 900
    report = post(client, f"/api/blue-phishing/{sid}/complete", h).get_json()["report"]
    assert report["result"] == "failure" and report["evaluation"]["remaining_risks"]
    assert report["evaluation"]["residual_risk"]["expected"] == "medium"
    assert report["evaluation"]["residual_risk"]["analyst"] == "medium"


def test_report_is_saved_as_soon_as_the_incident_closes(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid, *_ = finish(client, h, db)
    assert db.blue_phishing_reports.count_documents({"user_id": "alice"}) == 1
    got = client.get(f"/api/blue-phishing/{sid}/report", headers=h).get_json()["report"]
    assert got["score"] == 1000 and got["evaluation"]["classification"]["correct"]
    post(client, f"/api/blue-phishing/{sid}/complete", h)
    assert db.blue_phishing_reports.count_documents({"user_id": "alice"}) == 1


def test_closed_session_rejects_further_actions(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid, *_ = finish(client, h, db)
    assert post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "open_email"}).status_code == 400


def test_abandoned_session_rejects_actions(app_client):
    client, token_for, db, _ = app_client
    h = token_for("alice")
    old = start(client, h).get_json()["session_id"]
    start(client, h, restart=True)
    r = post(client, f"/api/blue-phishing/{old}/action", h, {"action": "open_email"})
    assert r.status_code == 409 and r.get_json()["restart_required"] is True


def test_report_is_stored_for_the_existing_reports_listing(app_client):
    client, token_for, db, server = app_client
    h = token_for("alice")
    sid, *_ = finish(client, h, db)
    post(client, f"/api/blue-phishing/{sid}/complete", h)
    assert any("reports" in r.rule for r in server.app.url_map.iter_rules())
    stored = db.blue_phishing_reports.find_one({"user_id": "alice"})
    assert stored["mode"] == "blue" and stored["attack"] == "phishing" and stored["score"] == 1000


def test_ai_status_does_not_expose_infrastructure(app_client):
    client, token_for, _, _ = app_client
    d = client.get("/api/blue-phishing/ai-status", headers=token_for("alice")).get_json()
    assert d["success"] and "base_url" not in d and d["reachable"] is False


# ---------------------------------------------------------------- regression

def test_existing_routes_are_still_registered(app_client):
    _, _, _, server = app_client
    rules = {r.rule for r in server.app.url_map.iter_rules()}
    for expected in ("/api/red-phishing/complete", "/api/auth/register", "/api/auth/login",
                     "/api/blue-phishing/start", "/api/blue-phishing/<session_id>/action",
                     "/api/blue-phishing/<session_id>/complete", "/api/blue-phishing/<session_id>/report"):
        assert expected in rules, expected


def test_red_phishing_still_works(app_client):
    client, token_for, db, _ = app_client
    assert client.post("/api/red-phishing/complete", json={}).status_code == 401
    r = post(client, "/api/red-phishing/complete", token_for("alice"), {
        "target": {"id": "t1", "name": "Test Target", "role": "Analyst", "department": "Finance",
                   "email": "t@x.test"},
        "campaign": {"simulatedLink": "https://x.test/l"}, "credentialSubmitted": True,
        "targetAccount": "train.user", "score": 500, "stages": []})
    assert r.status_code == 201 and r.get_json()["success"] is True
    assert db.simulation_reports.count_documents({"user_id": "alice", "mode": "red"}) == 1


def test_session_from_an_older_scenario_format_is_replaced_not_crashed(app_client):
    """A saved session without the current schema (e.g. no alert queue) must be
    abandoned and replaced rather than causing a server error."""
    client, token_for, db, _ = app_client
    h = token_for("alice")
    sid = start(client, h).get_json()["session_id"]
    doc = db.blue_phishing_sessions.find_one({})
    scenario = dict(doc["scenario"])
    scenario.pop("alerts")
    db.blue_phishing_sessions.update_one({}, {"$set": {"scenario": scenario, "schema_version": 1}})
    r = start(client, h)
    assert r.status_code == 201 and r.get_json()["session_id"] != sid
    assert db.blue_phishing_sessions.find_one({"_id": doc["_id"]})["status"] == "abandoned"
    assert post(client, f"/api/blue-phishing/{sid}/action", h, {"action": "open_email"}).status_code == 409


# ---------------------------------------------------------------- AI hints

def test_hint_endpoint_is_owner_only_and_validates_level(app_client):
    client, token_for, _, _ = app_client
    alice, bob = token_for("alice"), token_for("bob")
    sid = start(client, alice).get_json()["session_id"]
    assert post(client, f"/api/blue-phishing/{sid}/hint", bob, {"level": 1}).status_code == 404
    assert post(client, f"/api/blue-phishing/{sid}/hint", alice, {"level": 9}).status_code == 400
    assert post(client, f"/api/blue-phishing/{sid}/hint", alice).status_code == 400


def test_hint_falls_back_to_builtin_when_the_model_is_unavailable(app_client):
    client, token_for, _, _ = app_client
    alice = token_for("alice")
    sid = start(client, alice).get_json()["session_id"]
    res = post(client, f"/api/blue-phishing/{sid}/hint", alice, {"level": 1, "title": "Inspect the email"})
    assert res.status_code == 200
    assert res.get_json() == {"success": True, "hint": None, "source": "builtin"}


def test_ai_hint_context_contains_only_what_the_analyst_can_see(app_client, monkeypatch):
    import server
    client, token_for, db, _ = app_client
    alice = token_for("alice")
    sid = start(client, alice, archetype="credential_compromise").get_json()["session_id"]
    seen = {}

    def fake(context, level, **_):
        seen["context"] = context
        return "Look closely at the part of the message that tells you who sent it."

    monkeypatch.setattr(server.blue_ai, "generate_hint", fake)
    res = post(client, f"/api/blue-phishing/{sid}/hint", alice, {"level": 2, "title": "Inspect the email"})
    assert res.get_json()["source"] == "ai"
    blob = json.dumps(seen["context"])
    sc = stored_scenario(db)
    assert seen["context"]["clues_found"] == []                 # nothing discovered yet
    assert seen["context"]["email_subject"] is None             # email not opened
    for leak in GT_LEAKS + (sc["email"]["sender_email"], sc["email"]["links"][0]["display_url"]):
        assert leak not in blob

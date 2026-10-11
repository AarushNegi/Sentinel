"""Deterministic Blue Team investigation engine.

Pure functions over plain dicts: no Flask, MongoDB or language-model access.
The caller owns persistence. Nothing a model or browser says can change an
outcome here: action success, evidence disclosure, attacker progression and
scoring are all decided by the rules below and the scenario's hidden ground
truth.
"""

import copy
from datetime import datetime, timezone

from .scenario_schema import (
    CLASSIFICATIONS,
    HEADER_FIELDS,
    IOC_TOOLS,
    KNOWN_ACTIONS,
    LOG_SOURCES,
    RESIDUAL_RISKS,
    ROOT_CAUSES,
    SEVERITIES,
    SIEM_QUERIES,
    TRIAGE_DISPOSITIONS,
)

MAX_SCORE = 1000
MAX_SUMMARY = 1500
MAX_SUPPORTING = 30

STAGES = ["alert", "email", "ioc", "user", "containment", "remediation", "closure"]

# --- configurable scoring rules ---------------------------------------
SCORE_RULES = {
    "categories": {
        "prioritization": {"label": "Alert prioritisation",         "max": 60},
        "evidence":       {"label": "Evidence collection",          "max": 200},
        "indicators":     {"label": "Indicator analysis",           "max": 60},
        "assessment":     {"label": "Classification & severity",    "max": 100},
        "correlation":    {"label": "Evidence correlation",         "max": 60},
        "containment":    {"label": "Containment",                  "max": 150},
        "remediation":    {"label": "Remediation & recovery",       "max": 100},
        "verification":   {"label": "Verification",                 "max": 50},
        "preservation":   {"label": "Evidence preservation",        "max": 80},
        "report":         {"label": "Report accuracy",              "max": 90},
        "speed":          {"label": "Response time",                "max": 30},
        "closure":        {"label": "Incident outcome",             "max": 20},
    },
    "classification_points": 60,
    "severity_exact_points": 40,
    "severity_adjacent_points": 20,
    "correlation_target_hits": 6,
    "correlation_miss_cost": 5,
    "root_cause_points": 30,
    "affected_users_points": 25,
    "affected_assets_points": 15,
    "residual_risk_points": 20,
    "par_seconds": {"easy": 600, "medium": 900, "hard": 1200},
    "penalties": {
        "premature_action": 10,
        "unnecessary_disruption_user": 30,
        "unnecessary_isolation": 40,
        "unnecessary_cleanup": 40,
        "blocked_legitimate": 50,
        "destructive_before_preservation": 30,
        "closed_with_gaps": 50,
        "false_preservation_claim": 30,
        "dismissed_real_alert": 80,
    },
    "premature_penalty_cap": 50,
    "penalty_cap": 300,
}

# Consequential actions: need confirmation and are never free of cost.
RESPONSE_ACTIONS = (
    "quarantine_email", "block_indicator", "revoke_sessions", "reset_account",
    "isolate_endpoint", "enforce_mfa", "remove_mailbox_rule", "endpoint_cleanup",
)
USER_TARGET_ACTIONS = (
    "analyze_auth_logs", "investigate_user", "investigate_endpoint",
    "quarantine_email", "revoke_sessions", "reset_account", "isolate_endpoint",
    "enforce_mfa", "remove_mailbox_rule", "endpoint_cleanup",
)
NO_TARGET_ACTIONS = (
    "open_email", "analyze_headers", "view_raw_headers", "set_assessment",
    "verify_containment", "verify_remediation", "close_incident",
)
REPEATABLE_ACTIONS = ("set_assessment", "verify_containment", "verify_remediation", "triage_alert")
NO_TICK_ACTIONS = ("select_alert", "triage_alert")

ACTION_LABELS = {
    "select_alert": "Open alert",
    "triage_alert": "Triage alert",
    "open_email": "Open email",
    "view_raw_headers": "View raw headers",
    "inspect_header_field": "Inspect header field",
    "analyze_headers": "Authentication analysis",
    "reveal_link": "Reveal link target",
    "inspect_url": "Analyse link destination",
    "inspect_attachment": "Analyse attachment",
    "ioc_lookup": "Run IOC lookup",
    "search_siem": "Search SIEM",
    "collect_log": "Collect log record",
    "analyze_auth_logs": "Analyse sign-in logs",
    "investigate_user": "Investigate user",
    "investigate_endpoint": "Investigate endpoint",
    "set_assessment": "Record assessment",
    "preserve_evidence": "Preserve evidence",
    "quarantine_email": "Quarantine email",
    "block_indicator": "Block indicator",
    "revoke_sessions": "Revoke sessions",
    "isolate_endpoint": "Isolate endpoint",
    "reset_account": "Reset credentials",
    "enforce_mfa": "Enforce MFA",
    "remove_mailbox_rule": "Remove malicious mailbox rule",
    "endpoint_cleanup": "Clean endpoint",
    "verify_containment": "Verify containment",
    "verify_remediation": "Verify remediation",
    "close_incident": "Close incident",
}
ACTION_GROUP = {
    "select_alert": "triage", "triage_alert": "triage",
    "open_email": "investigation", "view_raw_headers": "investigation",
    "inspect_header_field": "investigation", "analyze_headers": "investigation",
    "reveal_link": "investigation", "inspect_url": "investigation",
    "inspect_attachment": "investigation", "ioc_lookup": "investigation",
    "search_siem": "investigation", "collect_log": "investigation",
    "analyze_auth_logs": "investigation", "investigate_user": "investigation",
    "investigate_endpoint": "investigation", "set_assessment": "assessment",
    "preserve_evidence": "evidence",
    "quarantine_email": "containment", "block_indicator": "containment",
    "revoke_sessions": "containment", "isolate_endpoint": "containment",
    "reset_account": "remediation", "enforce_mfa": "remediation",
    "remove_mailbox_rule": "remediation", "endpoint_cleanup": "remediation",
    "verify_containment": "verification", "verify_remediation": "verification",
    "close_incident": "closure",
}
# Shown in the confirmation dialog before a consequential action.
ACTION_IMPACT = {
    "quarantine_email": "Removes the message from this mailbox and stores it in quarantine. The user can no longer open it.",
    "block_indicator": "Blocks this indicator at the email, DNS and web gateways for everyone. Only block confirmed malicious indicators; blocking legitimate infrastructure disrupts the business.",
    "revoke_sessions": "Signs the user out of every active session and token. The user must sign in again; an attacker's session is terminated.",
    "reset_account": "Forces a password reset and invalidates all tokens. The user is locked out until they set a new password.",
    "isolate_endpoint": "Cuts the endpoint off from the network except the EDR channel. The user cannot work on it.",
    "enforce_mfa": "Requires multi-factor authentication for this account and disables legacy protocols.",
    "remove_mailbox_rule": "Deletes the user's inbox rules that forward mail externally. Preserve the evidence first - this removes the artifact.",
    "endpoint_cleanup": "Removes malware and persistence from the isolated endpoint. Volatile evidence is lost; preserve the endpoint telemetry first.",
}
SIEM_LABELS = {
    "proxy_dns": "DNS and web proxy activity",
    "mail_delivery": "Mail delivery to recipients",
}
IOC_TOOL_LABELS = {
    "domain_reputation": "Domain reputation",
    "url_reputation": "URL reputation",
    "ip_reputation": "IP reputation",
    "dns_analysis": "DNS analysis",
    "hash_lookup": "File hash lookup",
    "related_search": "Related indicators",
}
HEADER_FIELD_LABELS = {
    "from": "From (display name vs address)",
    "reply_to": "Reply-To (compare domains)",
    "return_path": "Return-Path (envelope)",
    "received": "Received chain (origin)",
}

_TOKEN_MESSAGES = {
    "done:open_email": "Open the suspicious email first.",
    "done:inspect_url": "Analyse the link in the email first so you know what to search for.",
    "done:set_assessment": "Record your classification and severity assessment first.",
    "done:verify_containment": "Verify containment before closing the incident.",
    "done:verify_remediation": "Verify remediation before closing the incident.",
    "done:analyze_auth_logs@target": "Analyse this user's sign-in logs before acting on their account.",
    "done:investigate_endpoint@target": "Investigate the endpoint before isolating it.",
    "done:isolate_endpoint@target": "Isolate the endpoint before cleaning it.",
    "done:select_alert@target": "Open the alert before triaging it.",
    "known_user": "That user has not been identified in this investigation yet.",
    "indicator_known": "That indicator has not been identified in this investigation yet.",
    "evidence_discovered": "That evidence has not been collected yet.",
    "has_attachment": "This message has no attachment.",
    "any_response": "Take at least one response action before verifying.",
}


# ------------------------------------------------------------------
#  State helpers
# ------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc)


def _stamp(now):
    return (now or _now()).strftime("%H:%M:%S")


def _log(timeline, now, tick, kind, message, evidence_id=None):
    entry = {
        "ts": (now or _now()).isoformat(),
        "clock": _stamp(now),
        "tick": tick,
        "kind": kind,
        "message": message,
    }
    if evidence_id:
        entry["evidence_id"] = evidence_id
    timeline.append(entry)


def new_sim(scenario, now=None):
    """Create the initial simulation state and timeline for a scenario."""
    sim = {
        "tick": 0,
        "done": [],
        "known_users": list(scenario["initial_state"]["known_users"]),
        "known_indicators": [],
        "discovered_evidence": [],
        "evidence_log": {},
        "preserved": [],
        "selected_alerts": [],
        "triage": {},
        "env": {
            "users": {
                u["id"]: {"mailbox": "delivered", "session": "unknown", "account": "normal",
                          "endpoint": "online", "mfa": "default", "mailbox_rule": "unknown"}
                for u in scenario["target"]["users"]
            },
            "indicators": {i["id"]: {"blocked": False} for i in scenario["indicators"]},
        },
        "assessment": None,
        "closure": None,
        "penalties": [],
        "impact": 0,
        "fired_events": [],
        "averted_events": [],
        "verify_log": [],
        "verify_rem_log": [],
        "closed": False,
        "outcome": None,
        "justification": "",
    }
    timeline = []
    _log(timeline, now, 0, "system", "Email gateway generated phishing alert")
    _log(timeline, now, 0, "system", f"{len(scenario['alerts'])} alerts are waiting in the queue")
    return sim, timeline


def _user(scenario, uid):
    for u in scenario["target"]["users"]:
        if u["id"] == uid:
            return u
    return None


def _indicator(scenario, iid):
    for i in scenario["indicators"]:
        if i["id"] == iid:
            return i
    return None


def _alert(scenario, aid):
    for a in scenario["alerts"]:
        if a["id"] == aid:
            return a
    return None


def _primary_alert(scenario):
    return next(a for a in scenario["alerts"] if a["is_primary"])


def done_key(action, target=None):
    return f"{action}@{target}" if target else action


def done_keys(sim):
    return {done_key(d["action"], d.get("target")) for d in sim["done"]}


def _done_actions(sim):
    return {d["action"] for d in sim["done"]}


def _subject(action, target):
    """The part of a target that prerequisites refer to."""
    if action == "ioc_lookup" and isinstance(target, str):
        return target.split(":", 1)[0]
    return target


def _token_ok(scenario, sim, token, target):
    keys = done_keys(sim)
    if token.startswith("done:"):
        spec = token[5:]
        if "@" in spec:
            action, who = spec.split("@", 1)
            who = target if who == "target" else who
            return done_key(action, who) in keys
        return spec in _done_actions(sim)
    if token == "has_attachment":
        return bool(scenario["email"].get("attachment"))
    if token == "known_user":
        return target in sim["known_users"]
    if token == "indicator_known":
        return target in sim["known_indicators"]
    if token == "evidence_discovered":
        return target in sim["discovered_evidence"]
    if token == "any_response":
        return any(a in _done_actions(sim) for a in RESPONSE_ACTIONS)
    return False


def _prereq_failures(scenario, sim, action, target):
    prereqs = scenario["action_prerequisites"]
    tokens = prereqs.get(f"{action}:{target}") or prereqs.get(action, [])
    subject = _subject(action, target)
    return [t for t in tokens if not _token_ok(scenario, sim, t, subject)]


def _token_message(token):
    if token in _TOKEN_MESSAGES:
        return _TOKEN_MESSAGES[token]
    if token.startswith("done:select_alert@"):
        return "Select the reported alert in the queue and open the incident first."
    return "A prerequisite for this action has not been met."


def parse_ioc_target(target):
    """Return (indicator_id, tool) or (None, None)."""
    if not isinstance(target, str) or ":" not in target:
        return None, None
    iid, tool = target.split(":", 1)
    return iid, tool


# ------------------------------------------------------------------
#  Target validation
# ------------------------------------------------------------------

def _log_visible(scenario, sim, row):
    return row["user_id"] is None or row["user_id"] in sim["known_users"]


def _validate_target(scenario, sim, action, target):
    """Return an error string, or None if the target is acceptable."""
    if action in NO_TARGET_ACTIONS:
        return None
    if not isinstance(target, str) or not target or len(target) > 96:
        return "This action needs a valid target."
    if action in ("select_alert", "triage_alert"):
        if _alert(scenario, target) is None:
            return "Unknown alert."
    elif action == "inspect_header_field":
        if target not in HEADER_FIELDS:
            return "Unknown header field."
    elif action in ("reveal_link", "inspect_url"):
        if target not in [l["id"] for l in scenario["email"]["links"]]:
            return "Unknown link."
        if "open_email" not in _done_actions(sim):
            return _token_message("done:open_email")
    elif action == "inspect_attachment":
        att = scenario["email"].get("attachment")
        if not att or target != att["id"]:
            return "Unknown attachment."
    elif action == "ioc_lookup":
        iid, tool = parse_ioc_target(target)
        ind = _indicator(scenario, iid) if iid else None
        if ind is None or iid not in sim["known_indicators"]:
            return _token_message("indicator_known")
        if tool not in IOC_TOOLS:
            return "Unknown IOC tool."
        if ind["type"] not in IOC_TOOLS[tool]:
            return f"{IOC_TOOL_LABELS[tool]} does not apply to a {ind['type'].replace('_', ' ')}."
    elif action == "search_siem":
        if target not in SIEM_QUERIES:
            return "Unknown SIEM search."
    elif action == "collect_log":
        row = scenario["logs"].get(target)
        if row is None or not _log_visible(scenario, sim, row):
            return "Unknown log record."
    elif action in USER_TARGET_ACTIONS:
        if _user(scenario, target) is None or target not in sim["known_users"]:
            return _token_message("known_user")
    elif action == "block_indicator":
        if _indicator(scenario, target) is None or target not in sim["known_indicators"]:
            return _token_message("indicator_known")
    elif action == "preserve_evidence":
        ev = scenario["evidence_catalog"].get(target)
        if ev is None or target not in sim["discovered_evidence"]:
            return _token_message("evidence_discovered")
        if not ev.get("preservable"):
            return "That evidence cannot be preserved as a forensic artifact."
    return None


# ------------------------------------------------------------------
#  Required response / completion
# ------------------------------------------------------------------

def required_status(scenario, sim):
    keys = done_keys(sim)
    return [{**req, "done": done_key(req["action"], req["target"]) in keys}
            for req in scenario["ground_truth"]["required_response"]]


def containment_complete(scenario, sim):
    return all(i["done"] for i in required_status(scenario, sim))


def expected_residual_risk(scenario, sim):
    missing = [s for s in required_status(scenario, sim) if not s["done"]]
    if not missing:
        return "none"
    if any(m["category"] == "containment" for m in missing):
        return "high"
    return "medium"


# ------------------------------------------------------------------
#  Scoring
# ------------------------------------------------------------------

def _triage_points(scenario, sim):
    """Per-alert correctness: (alert, analyst disposition, expected, points 0..1)."""
    rows = []
    truth = scenario["ground_truth"]["alert_truth"]
    for a in scenario["alerts"]:
        expected, got = truth[a["id"]], sim["triage"].get(a["id"])
        if got is None:
            pts = 0.0
        elif got == expected:
            pts = 1.0
        elif a["is_primary"]:
            pts = 0.0
        elif got == "investigate_now":
            pts = 0.0
        else:  # monitor <-> close_benign on a low-priority decoy
            pts = 0.5
        rows.append((a, got, expected, pts))
    return rows


def _jaccard(a, b):
    a, b = set(a), set(b)
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def compute_score(scenario, sim, elapsed_seconds=0):
    rules = SCORE_RULES
    gt = scenario["ground_truth"]
    cats = {k: {"label": v["label"], "max": v["max"], "earned": 0, "detail": ""}
            for k, v in rules["categories"].items()}

    # prioritisation ------------------------------------------------
    tri = _triage_points(scenario, sim)
    done_tri = sum(1 for _, got, _, _ in tri if got)
    cats["prioritization"]["earned"] = round(
        cats["prioritization"]["max"] * sum(p for *_, p in tri) / max(1, len(tri)))
    cats["prioritization"]["detail"] = (
        f"{sum(1 for *_, p in tri if p == 1.0)} of {len(tri)} alerts triaged correctly "
        f"({done_tri} triaged).")

    # evidence ------------------------------------------------------
    critical = gt["critical_evidence"]
    found = [e for e in critical if e in sim["discovered_evidence"]]
    cats["evidence"]["earned"] = round(cats["evidence"]["max"] * len(found) / max(1, len(critical)))
    cats["evidence"]["detail"] = f"{len(found)} of {len(critical)} critical evidence items collected."

    # indicators ----------------------------------------------------
    mal = gt["malicious_indicator_ids"]
    known_mal = [i for i in mal if i in sim["known_indicators"]]
    block_targets = [r["target"] for r in gt["required_response"] if r["action"] == "block_indicator"]
    looked = {parse_ioc_target(d["target"])[0] for d in sim["done"] if d["action"] == "ioc_lookup"}
    verified = [t for t in block_targets if t in looked]
    half = cats["indicators"]["max"] / 2
    cats["indicators"]["earned"] = round(
        half * len(known_mal) / max(1, len(mal)) + half * len(verified) / max(1, len(block_targets)))
    cats["indicators"]["detail"] = (
        f"{len(known_mal)} of {len(mal)} malicious indicators identified; "
        f"{len(verified)} of {len(block_targets)} blocked-worthy indicators verified with an IOC lookup.")

    # assessment ----------------------------------------------------
    final = sim["closure"] or sim["assessment"]
    if final:
        pts = rules["classification_points"] if final["classification"] == gt["classification"] else 0
        diff = abs(SEVERITIES.index(final["severity"]) - SEVERITIES.index(gt["true_severity"]))
        pts += (rules["severity_exact_points"] if diff == 0
                else rules["severity_adjacent_points"] if diff == 1 else 0)
        cats["assessment"]["earned"] = pts
        cats["assessment"]["detail"] = (
            f"Classification {'correct' if final['classification'] == gt['classification'] else 'incorrect'}; "
            f"severity {'exact' if diff == 0 else 'one level off' if diff == 1 else 'off by more than one level'}.")
    else:
        cats["assessment"]["detail"] = "No assessment recorded."

    # correlation ---------------------------------------------------
    closure = sim["closure"]
    if closure:
        support = [e for e in closure["supporting_evidence_ids"] if e in sim["discovered_evidence"]]
        hits = [e for e in support if e in critical]
        misses = len(support) - len(hits)
        raw = (rules["categories"]["correlation"]["max"]
               * min(1.0, len(hits) / rules["correlation_target_hits"])
               - rules["correlation_miss_cost"] * misses)
        cats["correlation"]["earned"] = max(0, round(raw))
        cats["correlation"]["detail"] = (
            f"Cited {len(hits)} critical and {misses} non-critical evidence items to support the conclusion.")
    else:
        cats["correlation"]["detail"] = "Cite supporting evidence when closing."

    # containment / remediation ------------------------------------
    status = required_status(scenario, sim)
    for cat in ("containment", "remediation"):
        group = [s for s in status if s["category"] == cat]
        if group:
            n_done = sum(1 for s in group if s["done"])
            cats[cat]["earned"] = round(cats[cat]["max"] * n_done / len(group))
            cats[cat]["detail"] = f"{n_done} of {len(group)} required {cat} steps completed."
        elif sim["closed"]:
            cats[cat]["earned"] = cats[cat]["max"]
            cats[cat]["detail"] = f"No {cat} was required, and none was needlessly applied."
        else:
            cats[cat]["detail"] = "Awarded when the incident is closed."

    # verification --------------------------------------------------
    half = cats["verification"]["max"] / 2
    parts = []
    for log_, label in ((sim["verify_log"], "containment"), (sim["verify_rem_log"], "remediation")):
        if log_:
            if log_[-1]["complete"]:
                cats["verification"]["earned"] += half
                parts.append(f"{label} verified clean")
            else:
                cats["verification"]["earned"] += round(half * 0.4)
                parts.append(f"{label} verified but gaps remained")
        else:
            parts.append(f"{label} never verified")
    cats["verification"]["earned"] = round(cats["verification"]["earned"])
    cats["verification"]["detail"] = "; ".join(parts).capitalize() + "."

    # preservation --------------------------------------------------
    req_pres = gt["required_preservation"]
    kept = [e for e in req_pres if e in sim["preserved"]]
    cats["preservation"]["earned"] = round(
        cats["preservation"]["max"] * len(kept) / max(1, len(req_pres)))
    cats["preservation"]["detail"] = f"{len(kept)} of {len(req_pres)} required forensic artifacts preserved."

    # report accuracy -----------------------------------------------
    if closure:
        pts = 0
        notes = []
        if closure["root_cause"] == gt["root_cause"]:
            pts += rules["root_cause_points"]
            notes.append("root cause correct")
        else:
            notes.append("root cause wrong")
        ju = _jaccard(closure["affected_user_ids"], gt["affected_users"])
        pts += rules["affected_users_points"] * ju
        notes.append(f"affected users {round(ju * 100)}% accurate")
        truth_assets = gt["affected_assets"]
        ja = _jaccard(closure["affected_asset_ids"], truth_assets)
        pts += rules["affected_assets_points"] * ja
        notes.append(f"affected assets {round(ja * 100)}% accurate")
        if closure["residual_risk"] == expected_residual_risk(scenario, sim):
            pts += rules["residual_risk_points"]
            notes.append("residual risk correct")
        else:
            notes.append("residual risk misjudged")
        cats["report"]["earned"] = round(pts)
        cats["report"]["detail"] = "; ".join(notes).capitalize() + "."
    else:
        cats["report"]["detail"] = "Scored when you submit the closure."

    # speed / outcome ----------------------------------------------
    if sim["closed"]:
        par = rules["par_seconds"][scenario["difficulty"]]
        frac = 1.0 if elapsed_seconds <= par else max(0.0, 1.0 - (elapsed_seconds - par) / (2 * par))
        cats["speed"]["earned"] = round(cats["speed"]["max"] * frac)
        cats["speed"]["detail"] = f"Closed in {int(elapsed_seconds)}s against a target of {par}s."
        if sim["outcome"] == "contained":
            cats["closure"]["earned"] = cats["closure"]["max"]
            cats["closure"]["detail"] = "Every required control was in place at closure."
        else:
            cats["closure"]["detail"] = "Closed while required controls were still missing."
    else:
        cats["speed"]["detail"] = "Scored when the incident is closed."
        cats["closure"]["detail"] = "Scored when the incident is closed."

    # dynamic penalties (derived from final state, so never double-counted)
    penalties = list(sim["penalties"])
    primary = _primary_alert(scenario)
    final_disp = sim["triage"].get(primary["id"])
    if final_disp in ("monitor", "close_benign"):
        penalties.append({
            "code": "dismissed_real_alert", "points": rules["penalties"]["dismissed_real_alert"],
            "message": "The alert for the real incident was triaged as low priority or benign.",
            "tick": sim["tick"], "key": f"triage:{primary['id']}"})
    for c in cats.values():
        c["earned"] = int(c["earned"])
    gross = sum(c["earned"] for c in cats.values())
    penalty_total = min(rules["penalty_cap"], sum(p["points"] for p in penalties))
    total = max(0, min(MAX_SCORE, gross - penalty_total))
    return {
        "total": total, "max": MAX_SCORE, "gross": gross, "penalty_total": penalty_total,
        "categories": [{"id": k, **v} for k, v in cats.items()],
        "penalties": penalties,
    }


# ------------------------------------------------------------------
#  Stage / legacy flags / objectives
# ------------------------------------------------------------------

def compute_stage(scenario, sim):
    acts = _done_actions(sim)
    if sim["closed"]:
        return "closure"
    remediation_actions = {"reset_account", "enforce_mfa", "remove_mailbox_rule", "endpoint_cleanup"}
    if acts & remediation_actions or (any(a in acts for a in RESPONSE_ACTIONS)
                                      and containment_complete(scenario, sim)):
        return "remediation"
    if any(a in acts for a in RESPONSE_ACTIONS):
        return "containment"
    if acts & {"search_siem", "analyze_auth_logs", "investigate_user", "investigate_endpoint", "collect_log"}:
        return "user"
    if acts & {"analyze_headers", "inspect_url", "inspect_attachment", "ioc_lookup"}:
        return "ioc"
    if "open_email" in acts:
        return "email"
    return "alert"


def legacy_state(scenario, sim):
    """Boolean flags kept for compatibility with existing report/dashboard code."""
    acts = _done_actions(sim)
    blocked_domain = any(
        sim["env"]["indicators"][i]["blocked"]
        for i in sim["env"]["indicators"]
        if (_indicator(scenario, i) or {}).get("type") in ("domain", "sender_domain"))
    return {
        "emailInspected": "open_email" in acts,
        "headersInspected": bool(acts & {"analyze_headers", "view_raw_headers"}),
        "urlInspected": bool(acts & {"inspect_url", "reveal_link"}),
        "siemSearched": "search_siem" in acts,
        "userInvestigated": bool(acts & {"investigate_user", "analyze_auth_logs"}),
        "endpointInvestigated": "investigate_endpoint" in acts,
        "emailQuarantined": "quarantine_email" in acts,
        "domainBlocked": blocked_domain,
        "sessionRevoked": "revoke_sessions" in acts,
        "endpointIsolated": "isolate_endpoint" in acts,
        "accountReset": "reset_account" in acts,
        "incidentClosed": bool(sim["closed"]),
    }


def objectives(scenario, sim):
    acts = _done_actions(sim)
    primary = _primary_alert(scenario)["id"]
    all_triaged = all(a["id"] in sim["triage"] for a in scenario["alerts"])
    return [
        {"id": "triage", "label": "Triage every alert in the queue", "done": all_triaged},
        {"id": "open", "label": "Open the reported phishing incident",
         "done": primary in sim["selected_alerts"]},
        {"id": "email", "label": "Inspect the email, headers and links",
         "done": "open_email" in acts and bool(acts & {"analyze_headers", "view_raw_headers", "inspect_header_field"})},
        {"id": "ioc", "label": "Analyse indicators with the IOC tools", "done": "ioc_lookup" in acts},
        {"id": "users", "label": "Investigate users, endpoints and logs",
         "done": bool(acts & {"analyze_auth_logs", "investigate_user", "investigate_endpoint", "collect_log"})},
        {"id": "contain", "label": "Contain the threat and verify it",
         "done": bool(sim["verify_log"]) and sim["verify_log"][-1]["complete"]},
        {"id": "remediate", "label": "Remediate and verify recovery",
         "done": bool(sim["verify_rem_log"]) and sim["verify_rem_log"][-1]["complete"]},
        {"id": "close", "label": "Submit the closure decision", "done": bool(sim["closed"])},
    ]


# ------------------------------------------------------------------
#  Applying an action
# ------------------------------------------------------------------

def _result(ok, http=200, message="", error=None, persist=False, **extra):
    base = {
        "ok": ok, "http": http, "message": message, "error": error,
        "persist": persist, "new_evidence": [], "new_indicators": [],
        "new_users": [], "feedback": [], "alerts": [], "penalty_points": 0,
    }
    base.update(extra)
    return base


def _add_penalty(sim, code, points, message, key=None):
    sim["penalties"].append(
        {"code": code, "points": points, "message": message, "tick": sim["tick"], "key": key})


def _record_evidence(sim, ev_id, action, target, now):
    sim["discovered_evidence"].append(ev_id)
    sim["evidence_log"][ev_id] = {
        "at": (now or _now()).isoformat(), "action": action, "target": target, "tick": sim["tick"]}


def _discover(scenario, sim, timeline, now, action, target, res):
    key = done_key(action, target)
    for ev_id in scenario["evidence_map"].get(key, []):
        if ev_id not in sim["discovered_evidence"]:
            _record_evidence(sim, ev_id, action, target, now)
            res["new_evidence"].append(ev_id)
            _log(timeline, now, sim["tick"], "evidence",
                 f"Evidence collected: {scenario['evidence_catalog'][ev_id]['title']}", ev_id)
    info = scenario["reveals"].get(key, {})
    for iid in info.get("indicators", []):
        if iid not in sim["known_indicators"]:
            sim["known_indicators"].append(iid)
            res["new_indicators"].append(iid)
            _log(timeline, now, sim["tick"], "system",
                 f"Indicator identified: {_indicator(scenario, iid)['value']}")
    for uid in info.get("users", []):
        if uid not in sim["known_users"]:
            sim["known_users"].append(uid)
            res["new_users"].append(uid)
            _log(timeline, now, sim["tick"], "system",
                 f"Affected user identified: {_user(scenario, uid)['name']}")


def _verify_lines(scenario, sim, categories, groups):
    status = [s for s in required_status(scenario, sim) if s["category"] in categories]
    lines = []
    for action, label in groups:
        group = [s for s in status if s["action"] == action]
        if group:
            lines.append(f"{label}: {sum(1 for s in group if s['done'])}/{len(group)}")
    return lines


def _fire_events(scenario, sim, timeline, now, res):
    for ev in scenario["simulated_events"]:
        if ev["id"] in sim["fired_events"] or ev["id"] in sim["averted_events"]:
            continue
        if sim["tick"] < ev["trigger_tick"]:
            continue
        if any(_token_ok(scenario, sim, tok, None) for tok in ev["unless"]):
            sim["averted_events"].append(ev["id"])
            continue
        sim["fired_events"].append(ev["id"])
        sim["impact"] += ev["impact"]
        _log(timeline, now, sim["tick"], "attacker", ev["message"], ev.get("evidence_id"))
        if ev.get("evidence_id") and ev["evidence_id"] not in sim["discovered_evidence"]:
            _record_evidence(sim, ev["evidence_id"], "attacker_activity", None, now)
            res["new_evidence"].append(ev["evidence_id"])
        if ev.get("penalty"):
            _add_penalty(sim, "attack_progressed", ev["penalty"], ev["message"], key=ev["id"])
            res["penalty_points"] += ev["penalty"]
        res["alerts"].append(ev["message"])


def _validate_closure(scenario, sim, params):
    """Return (clean, error) for the structured closure decision."""
    def lst(value, field):
        if not isinstance(value, list) or len(value) > MAX_SUPPORTING or not all(
                isinstance(x, str) and len(x) <= 96 for x in value):
            raise ValueError(f"{field} must be a list of identifiers.")
        return list(dict.fromkeys(value))
    try:
        classification, severity = params.get("classification"), params.get("severity")
        if classification not in CLASSIFICATIONS or severity not in SEVERITIES:
            raise ValueError("Choose a valid classification and severity.")
        root_cause = params.get("root_cause")
        if root_cause not in ROOT_CAUSES:
            raise ValueError("Choose a root cause.")
        risk = params.get("residual_risk")
        if risk not in RESIDUAL_RISKS:
            raise ValueError("Choose a residual risk level.")
        users = lst(params.get("affected_user_ids", []), "affected_user_ids")
        assets = lst(params.get("affected_asset_ids", []), "affected_asset_ids")
        support = lst(params.get("supporting_evidence_ids", []), "supporting_evidence_ids")
        if any(u not in sim["known_users"] for u in users):
            raise ValueError("Affected users must be users you have identified.")
        known_assets = {_user(scenario, u)["endpoint"] for u in sim["known_users"]}
        if any(a not in known_assets for a in assets):
            raise ValueError("Affected assets must be assets you have identified.")
        if any(e not in sim["discovered_evidence"] for e in support):
            raise ValueError("You can only cite evidence you have collected.")
        preserved_claim = params.get("evidence_preserved")
        if not isinstance(preserved_claim, bool):
            raise ValueError("Confirm whether forensic evidence was preserved.")
        summary = params.get("summary")
        if not isinstance(summary, str) or not 20 <= len(summary.strip()) <= MAX_SUMMARY:
            raise ValueError("Write an incident summary of at least 20 characters.")
    except ValueError as exc:
        return None, str(exc)
    return {
        "classification": classification, "severity": severity, "root_cause": root_cause,
        "residual_risk": risk, "affected_user_ids": users, "affected_asset_ids": assets,
        "supporting_evidence_ids": support, "evidence_preserved": preserved_claim,
        "summary": summary.strip(),
    }, None


def apply_action(scenario, sim, timeline, action, target=None, params=None,
                 now=None, elapsed_seconds=0):
    """Apply one analyst action, mutating ``sim`` and ``timeline`` in place.

    Returns a result dict. ``result['persist']`` says whether the (mutated)
    state must be saved -- true for accepted actions and for rejected
    response actions that cost a penalty.
    """
    params = params if isinstance(params, dict) else {}
    if not isinstance(action, str) or action not in KNOWN_ACTIONS:
        return _result(False, 400, error="Unknown Blue Team action.")
    if action not in scenario["allowed_actions"]:
        return _result(False, 400, error="That action is not available in this incident.")
    if sim["closed"]:
        return _result(False, 409, error="This incident is already closed.")
    if target is not None and not isinstance(target, str):
        return _result(False, 400, error="Invalid target.")
    if action in NO_TARGET_ACTIONS:
        target = None

    err = _validate_target(scenario, sim, action, target)
    if err:
        return _result(False, 400, error=err)

    key = done_key(action, target)
    if action not in REPEATABLE_ACTIONS and key in done_keys(sim):
        return _result(False, 409, error="This action has already been completed.")

    failures = _prereq_failures(scenario, sim, action, target)
    if failures:
        message = _token_message(failures[0])
        res = _result(False, 400, error=message)
        if action in RESPONSE_ACTIONS:
            rules = SCORE_RULES
            already = sum(p["points"] for p in sim["penalties"] if p["code"] == "premature_action")
            marker = f"premature:{key}"
            if (already < rules["premature_penalty_cap"]
                    and not any(p.get("key") == marker for p in sim["penalties"])):
                pts = rules["penalties"]["premature_action"]
                _add_penalty(sim, "premature_action", pts,
                             f"Attempted '{ACTION_LABELS[action]}' before establishing the facts: {message}",
                             key=marker)
                _log(timeline, now, sim["tick"], "analyst",
                     f"Premature action blocked: {ACTION_LABELS[action]}")
                res.update(persist=True, penalty_points=pts)
        return res

    if action in RESPONSE_ACTIONS and params.get("confirm") is not True:
        return _result(False, 400, error="Confirm this action before it is carried out.",
                       confirmation_required=True)

    gt = scenario["ground_truth"]
    res = _result(True, 200, persist=True)
    pen = SCORE_RULES["penalties"]
    user = _user(scenario, target) if action in USER_TARGET_ACTIONS else None
    ticks = action not in NO_TICK_ACTIONS
    if ticks:
        sim["tick"] += 1

    def undo_and_fail(message):
        if ticks:
            sim["tick"] -= 1
        return _result(False, 400, error=message)

    if action == "select_alert":
        alert = _alert(scenario, target)
        if target not in sim["selected_alerts"]:
            sim["selected_alerts"].append(target)
        _log(timeline, now, sim["tick"], "analyst", f"Opened alert {target}: {alert['title']}")
        if alert["is_primary"]:
            _discover(scenario, sim, timeline, now, action, target, res)
            _log(timeline, now, sim["tick"], "system",
                 "Incident workspace opened for the reported email")
        res["message"] = f"Opened alert {target}."

    elif action == "triage_alert":
        disposition = params.get("disposition")
        if disposition not in TRIAGE_DISPOSITIONS:
            return undo_and_fail("Choose a triage disposition.")
        sim["triage"][target] = disposition
        _log(timeline, now, sim["tick"], "analyst",
             f"Triaged {target} as {disposition.replace('_', ' ')}")
        res["message"] = f"{target} marked {disposition.replace('_', ' ')}."

    elif action == "set_assessment":
        classification, severity = params.get("classification"), params.get("severity")
        if classification not in CLASSIFICATIONS or severity not in SEVERITIES:
            return undo_and_fail("Choose a valid classification and severity.")
        sim["assessment"] = {"classification": classification, "severity": severity, "tick": sim["tick"]}
        _log(timeline, now, sim["tick"], "analyst",
             f"Working assessment: {classification.replace('_', ' ')}, severity {severity}")
        res["message"] = "Assessment recorded. You can update it as new evidence arrives."

    elif action in ("open_email", "analyze_headers", "view_raw_headers", "inspect_header_field",
                    "reveal_link", "inspect_url", "inspect_attachment", "ioc_lookup", "search_siem",
                    "collect_log", "analyze_auth_logs", "investigate_user", "investigate_endpoint"):
        _discover(scenario, sim, timeline, now, action, target, res)
        if action == "ioc_lookup":
            iid, tool = parse_ioc_target(target)
            what = f"{IOC_TOOL_LABELS[tool]}: {_indicator(scenario, iid)['value']}"
        elif action == "search_siem":
            what = f"SIEM search: {SIEM_LABELS.get(target, target)}"
        elif action == "collect_log":
            what = f"Collected log record {target}"
        elif action == "inspect_header_field":
            what = f"Inspected header field: {HEADER_FIELD_LABELS[target]}"
        elif user:
            what = f"{ACTION_LABELS[action]}: {user['name']}"
        else:
            what = ACTION_LABELS[action] + (f" ({target})" if target else "")
        if action == "analyze_auth_logs":
            g = gt["users"][target]
            sim["env"]["users"][target]["session"] = "suspicious" if g.get("session_active") else "normal"
            sim["env"]["users"][target]["mailbox_rule"] = "present" if g.get("mailbox_rule") else "none"
        _log(timeline, now, sim["tick"], "analyst", what)
        res["message"] = what

    elif action == "preserve_evidence":
        sim["preserved"].append(target)
        title = scenario["evidence_catalog"][target]["title"]
        _log(timeline, now, sim["tick"], "analyst", f"Evidence preserved: {title}")
        res["message"] = f"Preserved a forensic copy of: {title}"

    elif action == "quarantine_email":
        sim["env"]["users"][target]["mailbox"] = "quarantined"
        _log(timeline, now, sim["tick"], "analyst", f"Message quarantined from {user['email']}")
        res["message"] = f"Message removed from {user['name']}'s mailbox and quarantined."

    elif action == "block_indicator":
        ind = _indicator(scenario, target)
        sim["env"]["indicators"][target]["blocked"] = True
        _log(timeline, now, sim["tick"], "analyst", f"Blocked {ind['type'].replace('_', ' ')}: {ind['value']}")
        res["message"] = f"{ind['value']} is now blocked."
        if not ind["malicious"]:
            _add_penalty(sim, "blocked_legitimate", pen["blocked_legitimate"],
                         f"Blocked {ind['value']}, which is legitimate vendor infrastructure.",
                         key=f"block:{target}")
            res["penalty_points"] += pen["blocked_legitimate"]
            res["feedback"].append(
                f"{ind['value']} belongs to the real vendor. Blocking it disrupts legitimate business (-{pen['blocked_legitimate']}).")

    elif action == "revoke_sessions":
        sim["env"]["users"][target]["session"] = "revoked"
        _log(timeline, now, sim["tick"], "analyst", f"Sessions revoked for {user['email']}")
        if gt["users"][target].get("session_active"):
            res["message"] = f"Attacker session for {user['name']} terminated."
        else:
            _add_penalty(sim, "unnecessary_disruption", pen["unnecessary_disruption_user"],
                         f"Revoked sessions for {user['name']} without evidence of attacker access.",
                         key=f"revoke:{target}")
            res["penalty_points"] += pen["unnecessary_disruption_user"]
            res["message"] = f"Sessions for {user['name']} revoked."
            res["feedback"].append(
                f"There was no evidence of attacker access for {user['name']}; signing them out was "
                f"unnecessary disruption (-{pen['unnecessary_disruption_user']}).")

    elif action == "reset_account":
        env = sim["env"]["users"][target]
        env["account"], env["session"] = "reset", "revoked"
        _log(timeline, now, sim["tick"], "analyst", f"Credentials reset for {user['email']}")
        g = gt["users"][target]
        if g.get("compromised") or g.get("endpoint_malware"):
            res["message"] = f"{user['name']}'s credentials reset and tokens invalidated."
        else:
            _add_penalty(sim, "unnecessary_disruption", pen["unnecessary_disruption_user"],
                         f"Reset the account of {user['name']}, who showed no sign of compromise.",
                         key=f"reset:{target}")
            res["penalty_points"] += pen["unnecessary_disruption_user"]
            res["message"] = f"{user['name']}'s credentials reset."
            res["feedback"].append(
                f"{user['name']} showed no sign of compromise; the reset was unnecessary (-{pen['unnecessary_disruption_user']}).")

    elif action == "enforce_mfa":
        sim["env"]["users"][target]["mfa"] = "enforced"
        _log(timeline, now, sim["tick"], "analyst", f"MFA enforced for {user['email']}")
        res["message"] = f"MFA is now required for {user['name']}."
        if not gt["users"][target].get("compromised"):
            res["feedback"].append("Good hygiene, but this account was not compromised, so it does not count as required remediation.")

    elif action == "remove_mailbox_rule":
        has_rule = gt["users"][target].get("mailbox_rule")
        guard = scenario.get("destructive_guard", {}).get(done_key(action, target), [])
        unsaved = [e for e in guard if e not in sim["preserved"]]
        if has_rule:
            sim["env"]["users"][target]["mailbox_rule"] = "removed"
            res["message"] = f"The malicious forwarding rule on {user['name']}'s mailbox was removed."
        else:
            res["message"] = f"No suspicious inbox rules were found on {user['name']}'s mailbox."
        _log(timeline, now, sim["tick"], "analyst", f"Mailbox rules reviewed and cleaned for {user['email']}")
        if has_rule and unsaved:
            _add_penalty(sim, "destructive_before_preservation", pen["destructive_before_preservation"],
                         "Removed the forwarding rule before preserving the authentication evidence that documents it.",
                         key=f"destructive:{key}")
            res["penalty_points"] += pen["destructive_before_preservation"]
            res["feedback"].append(
                f"The rule was the evidence. Preserve first, then remove (-{pen['destructive_before_preservation']}).")

    elif action == "isolate_endpoint":
        sim["env"]["users"][target]["endpoint"] = "isolated"
        _log(timeline, now, sim["tick"], "analyst", f"Endpoint isolated: {user['endpoint']}")
        if gt["users"][target].get("endpoint_malware"):
            res["message"] = f"{user['endpoint']} isolated from the network."
        else:
            _add_penalty(sim, "unnecessary_isolation", pen["unnecessary_isolation"],
                         f"Isolated {user['endpoint']} although telemetry showed no malware.",
                         key=f"isolate:{target}")
            res["penalty_points"] += pen["unnecessary_isolation"]
            res["message"] = f"{user['endpoint']} isolated."
            res["feedback"].append(
                f"{user['endpoint']} had no malicious activity; isolating it disrupted "
                f"{user['name']}'s work for no benefit (-{pen['unnecessary_isolation']}).")

    elif action == "endpoint_cleanup":
        guard = scenario.get("destructive_guard", {}).get(done_key(action, target), [])
        unsaved = [e for e in guard if e not in sim["preserved"]]
        sim["env"]["users"][target]["endpoint"] = "cleaned"
        _log(timeline, now, sim["tick"], "analyst", f"Endpoint cleaned: {user['endpoint']}")
        if gt["users"][target].get("endpoint_malware"):
            res["message"] = f"Malware and persistence removed from {user['endpoint']}."
            if unsaved:
                _add_penalty(sim, "destructive_before_preservation", pen["destructive_before_preservation"],
                             f"Cleaned {user['endpoint']} before preserving its endpoint telemetry.",
                             key=f"destructive:{key}")
                res["penalty_points"] += pen["destructive_before_preservation"]
                res["feedback"].append(
                    f"Volatile evidence was destroyed. Preserve first, then clean (-{pen['destructive_before_preservation']}).")
        else:
            _add_penalty(sim, "unnecessary_cleanup", pen["unnecessary_cleanup"],
                         f"Cleaned {user['endpoint']}, which was not infected.", key=f"cleanup:{target}")
            res["penalty_points"] += pen["unnecessary_cleanup"]
            res["message"] = f"{user['endpoint']} cleaned."
            res["feedback"].append(f"{user['endpoint']} was not infected (-{pen['unnecessary_cleanup']}).")

    elif action == "verify_containment":
        status = required_status(scenario, sim)
        complete = all(s["done"] for s in status if s["category"] == "containment")
        sim["verify_log"].append({"tick": sim["tick"], "complete": complete})
        lines = _verify_lines(scenario, sim, ("containment",), (
            ("quarantine_email", "Mailboxes cleared of the message"),
            ("block_indicator", "Malicious indicators blocked"),
            ("revoke_sessions", "Attacker sessions terminated"),
            ("isolate_endpoint", "Infected endpoints isolated")))
        res["verification"] = {"kind": "containment", "complete": complete, "lines": lines}
        res["message"] = ("Containment verified: every required control is in place." if complete
                          else "Verification found gaps: containment is not complete.")
        _log(timeline, now, sim["tick"], "analyst",
             "Containment verified" if complete else "Containment verification found gaps")

    elif action == "verify_remediation":
        status = required_status(scenario, sim)
        complete = all(s["done"] for s in status if s["category"] == "remediation")
        sim["verify_rem_log"].append({"tick": sim["tick"], "complete": complete})
        lines = _verify_lines(scenario, sim, ("remediation",), (
            ("remove_mailbox_rule", "Malicious mailbox rules removed"),
            ("reset_account", "Affected accounts reset"),
            ("enforce_mfa", "MFA enforced on compromised accounts"),
            ("endpoint_cleanup", "Infected endpoints cleaned")))
        if not lines:
            lines = ["No remediation steps were required for this incident."]
        res["verification"] = {"kind": "remediation", "complete": complete, "lines": lines}
        res["message"] = ("Recovery verified: no residual exposure found." if complete
                          else "Residual exposure remains: remediation is incomplete.")
        _log(timeline, now, sim["tick"], "analyst",
             "Remediation verified" if complete else "Remediation verification found residual exposure")

    elif action == "close_incident":
        clean, error = _validate_closure(scenario, sim, params)
        if error:
            return undo_and_fail(error)
        complete = containment_complete(scenario, sim)
        sim["closed"] = True
        sim["closure"] = clean
        sim["justification"] = clean["summary"]
        sim["assessment"] = {"classification": clean["classification"],
                             "severity": clean["severity"], "tick": sim["tick"]}
        sim["outcome"] = "contained" if complete else "failed"
        if not complete:
            _add_penalty(sim, "closed_with_gaps", pen["closed_with_gaps"],
                         "Closed the incident while required containment or remediation was still incomplete.",
                         key="closure")
            res["penalty_points"] += pen["closed_with_gaps"]
        preserved_ok = all(e in sim["preserved"] for e in gt["required_preservation"])
        if clean["evidence_preserved"] and not preserved_ok:
            _add_penalty(sim, "false_preservation_claim", pen["false_preservation_claim"],
                         "Confirmed that forensic evidence was preserved, but required artifacts were not.",
                         key="preservation-claim")
            res["penalty_points"] += pen["false_preservation_claim"]
        _log(timeline, now, sim["tick"], "analyst",
             "Incident closed: threat contained" if complete else "Incident closed with unresolved exposure")
        res["message"] = ("Incident closed. The threat was contained." if complete
                          else "Incident closed, but required containment or remediation was incomplete.")

    sim["done"].append({"action": action, "target": target, "tick": sim["tick"],
                        "at": (now or _now()).isoformat()})
    if ticks and action != "close_incident":
        _fire_events(scenario, sim, timeline, now, res)
    return res


# ------------------------------------------------------------------
#  Log queries (read-only, no state change)
# ------------------------------------------------------------------

def query_logs(scenario, sim, source=None, filters=None, limit=200):
    """Filter the simulated log dataset. Rows for users the analyst has not
    identified are not returned. The query itself never changes state."""
    filters = filters if isinstance(filters, dict) else {}
    if source not in (None, "") and source not in LOG_SOURCES:
        raise ValueError("Unknown log source.")

    def text(name):
        value = filters.get(name)
        if value in (None, ""):
            return None
        if not isinstance(value, str) or len(value) > 120:
            raise ValueError(f"Invalid filter: {name}")
        return value.strip().lower()

    user_f, ev_f, ip_f = text("user"), text("event_type"), text("source_ip")
    out_f, dev_f, search = text("outcome"), text("device"), text("search")
    start, end = text("from"), text("to")
    rows = []
    for row in scenario["logs"].values():
        if not _log_visible(scenario, sim, row):
            continue
        if source and row["source"] != source:
            continue
        if user_f and user_f not in (row["user_id"] or "").lower() and user_f not in row["user"].lower():
            continue
        if ev_f and ev_f != row["event_type"].lower():
            continue
        if ip_f and not (row["src_ip"] or "").startswith(ip_f):
            continue
        if out_f and out_f != row["outcome"].lower():
            continue
        if dev_f and dev_f not in row["device"].lower():
            continue
        if start and row["ts"].lower() < start:
            continue
        if end and row["ts"].lower() > end:
            continue
        if search:
            hay = " ".join([row["detail"], row["user"], row["event_type"], row["src_ip"] or "",
                            row["device"], row["outcome"]]).lower()
            if search not in hay:
                continue
        rows.append(row)
    rows.sort(key=lambda r: r["ts"])
    total = len(rows)
    out = []
    for r in rows[:limit]:
        out.append({
            "id": r["id"], "ts": r["ts"], "source": r["source"], "user_id": r["user_id"],
            "user": r["user"], "event_type": r["event_type"], "src_ip": r["src_ip"],
            "outcome": r["outcome"], "device": r["device"], "detail": r["detail"],
            "collected": f"EV-{r['id']}" in sim["discovered_evidence"],
        })
    return {"rows": out, "total": total, "truncated": total > limit}


# ------------------------------------------------------------------
#  Public (analyst-visible) view
# ------------------------------------------------------------------

def _incident_open(scenario, sim):
    return _primary_alert(scenario)["id"] in sim["selected_alerts"]


def _public_email(scenario, sim):
    e = scenario["email"]
    primary = _user(scenario, scenario["target"]["primary_user_id"])
    opened = "open_email" in _done_actions(sim)
    view = {
        "opened": opened,
        "available": _incident_open(scenario, sim),
        "sender_name": e["sender_name"],
        "recipient": primary["email"],
        "subject": e["subject"],
        "sent_at": e["sent_at"],
        "gateway": e["gateway"],
        "has_attachment": bool(e.get("attachment")),
    }
    if not view["available"]:
        return {"opened": False, "available": False}
    if opened:
        att = e.get("attachment")
        view.update({
            "sender_email": e["sender_email"],
            "message_id": e["message_id"],
            "greeting": e["greeting"],
            "paragraphs": e["paragraphs"],
            "signature": e["signature"],
            "links": [{"id": l["id"], "label": l["label"], "display_url": l["display_url"]}
                      for l in e["links"]],
            "attachment": ({"id": att["id"], "filename": att["filename"], "kind": att["kind"],
                            "size_kb": att["size_kb"]} if att else None),
        })
    return view


def _public_users(scenario, sim):
    acts = done_keys(sim)
    users = []
    for uid in sim["known_users"]:
        u = _user(scenario, uid)
        env = sim["env"]["users"][uid]
        users.append({
            **{k: u[k] for k in ("id", "name", "role", "department", "email", "endpoint")},
            "is_primary": uid == scenario["target"]["primary_user_id"],
            "mailbox": env["mailbox"], "session": env["session"], "account": env["account"],
            "endpoint_state": env["endpoint"], "mfa": env["mfa"], "mailbox_rule": env["mailbox_rule"],
            "auth_analyzed": done_key("analyze_auth_logs", uid) in acts,
            "user_investigated": done_key("investigate_user", uid) in acts,
            "endpoint_investigated": done_key("investigate_endpoint", uid) in acts,
        })
    return users


def _targets_for(scenario, sim, action):
    acts = _done_actions(sim)
    if action in ("select_alert", "triage_alert"):
        out = []
        for a in scenario["alerts"]:
            if action == "triage_alert" and a["id"] not in sim["selected_alerts"]:
                continue
            out.append((a["id"], a["title"]))
        return out
    if action == "inspect_header_field":
        return [(f, HEADER_FIELD_LABELS[f]) for f in HEADER_FIELDS] if "open_email" in acts else []
    if action in ("inspect_url", "reveal_link"):
        if "open_email" not in acts:
            return []
        return [(l["id"], f"{l['label']} ({l['display_url']})") for l in scenario["email"]["links"]]
    if action == "inspect_attachment":
        att = scenario["email"].get("attachment")
        return [(att["id"], att["filename"])] if att and "open_email" in acts else []
    if action == "ioc_lookup":
        out = []
        for iid in sim["known_indicators"]:
            ind = _indicator(scenario, iid)
            for tool, types in IOC_TOOLS.items():
                if ind["type"] in types:
                    out.append((f"{iid}:{tool}", f"{IOC_TOOL_LABELS[tool]} · {ind['value'][:48]}"))
        return out
    if action == "search_siem":
        return [(q, SIEM_LABELS[q]) for q in SIEM_QUERIES]
    if action == "collect_log":
        return None  # driven from the log viewer
    if action in USER_TARGET_ACTIONS:
        return [(uid, _user(scenario, uid)["name"]) for uid in sim["known_users"]]
    if action == "block_indicator":
        return [(i, _indicator(scenario, i)["value"]) for i in sim["known_indicators"]]
    if action == "preserve_evidence":
        return [(e, scenario["evidence_catalog"][e]["title"]) for e in sim["discovered_evidence"]
                if scenario["evidence_catalog"][e].get("preservable")]
    return None


def available_actions(scenario, sim):
    keys = done_keys(sim)
    out = []
    for action in KNOWN_ACTIONS:
        if action not in scenario["allowed_actions"]:
            continue
        entry = {"action": action, "label": ACTION_LABELS[action], "group": ACTION_GROUP[action],
                 "targets": None, "confirm": action in RESPONSE_ACTIONS,
                 "impact": ACTION_IMPACT.get(action)}
        targets = _targets_for(scenario, sim, action)
        if targets is None:
            if action == "collect_log":
                entry.update(enabled=not sim["closed"], done=False, reason=None)
            else:
                failures = _prereq_failures(scenario, sim, action, None)
                entry["enabled"] = not failures and not sim["closed"] and (
                    action in REPEATABLE_ACTIONS or action not in keys)
                entry["done"] = action in keys
                entry["reason"] = _token_message(failures[0]) if failures else None
        else:
            entry["targets"] = []
            repeatable = action in REPEATABLE_ACTIONS
            for tid, label in targets:
                failures = _prereq_failures(scenario, sim, action, tid)
                done = done_key(action, tid) in keys
                entry["targets"].append({
                    "id": tid, "label": label, "done": done,
                    "enabled": not failures and (repeatable or not done) and not sim["closed"],
                    "reason": _token_message(failures[0]) if failures else None,
                })
            entry["enabled"] = any(t["enabled"] for t in entry["targets"])
            entry["done"] = bool(entry["targets"]) and all(t["done"] for t in entry["targets"])
            entry["reason"] = None if entry["targets"] else "Nothing to act on yet."
        out.append(entry)
    return out


def events_as_text(timeline):
    return [f"[{t['clock']}] {t['message']}" for t in timeline]


def _public_alerts(scenario, sim):
    out = []
    for a in scenario["alerts"]:
        selected = a["id"] in sim["selected_alerts"]
        item = {k: a[k] for k in ("id", "title", "severity", "confidence", "source", "rule",
                                  "entity", "detected_at", "description")}
        item.update(selected=selected, triage=sim["triage"].get(a["id"]),
                    status=("closed" if sim["triage"].get(a["id"]) == "close_benign"
                            else "investigating" if sim["triage"].get(a["id"]) == "investigate_now"
                            else "monitoring" if sim["triage"].get(a["id"]) == "monitor" else "new"))
        if selected:
            item["detail"] = a["detail"]
            if a["is_primary"]:
                item["incident_alert"] = True      # selecting it is what opened the workspace
        out.append(item)
    return out


def _public_evidence(scenario, sim):
    catalog = scenario["evidence_catalog"]
    found = set(sim["discovered_evidence"])
    out = []
    for e in sim["discovered_evidence"]:
        info = sim["evidence_log"].get(e, {})
        out.append({
            "id": e, "title": catalog[e]["title"], "category": catalog[e]["category"],
            "source_artifact": catalog[e].get("source_artifact"),
            "entity": catalog[e].get("entity"),
            "related": [r for r in catalog[e].get("related", []) if r in found],
            "content": catalog[e]["content"],
            "preservable": bool(catalog[e].get("preservable")),
            "preserved": e in sim["preserved"],
            "discovered_at": info.get("at"),
            "provenance": {"action": info.get("action"), "target": info.get("target"),
                           "tick": info.get("tick")},
        })
    return out


def public_view(scenario, sim, timeline, elapsed_seconds=0):
    """Everything the analyst is allowed to see right now. Never includes
    ground truth, undiscovered evidence, event schedules or required actions."""
    score = compute_score(scenario, sim, elapsed_seconds)
    primary = _user(scenario, scenario["target"]["primary_user_id"])
    stage = compute_stage(scenario, sim)
    assess = sim["assessment"]
    opened = _incident_open(scenario, sim)
    incident = {
        "id": scenario["incident_id"],
        "open": opened,
        "title": (f"Suspicious email: {scenario['email']['subject']}" if opened
                  else "No incident selected"),
        "severity": (assess["severity"] if assess else scenario["alert"]["reported_severity"]).upper(),
        "severity_source": "analyst" if assess else "gateway",
        "type": ("Phishing incident" if not assess
                 else assess["classification"].replace("_", " ").title()),
        "status": "closed" if sim["closed"] else ("open" if opened else "triage"),
        "detected_at": scenario["alert"]["detected_at"],
        "summary": scenario["alert"]["summary"] if opened else "Select an alert in the queue to begin.",
        "difficulty": scenario["difficulty"],
        "affected_user_count": len(sim["known_users"]),
    }
    if opened:
        incident["target"] = {k: primary[k] for k in ("name", "role", "department", "email", "endpoint")}
    return {
        "incident": incident,
        "alerts": _public_alerts(scenario, sim),
        "email": _public_email(scenario, sim),
        "users": _public_users(scenario, sim),
        "indicators": [
            {"id": i, "type": _indicator(scenario, i)["type"], "value": _indicator(scenario, i)["value"],
             "label": _indicator(scenario, i)["label"],
             "blocked": sim["env"]["indicators"][i]["blocked"]}
            for i in sim["known_indicators"]
        ],
        "evidence": _public_evidence(scenario, sim),
        "timeline": [
            {k: t[k] for k in ("clock", "tick", "kind", "message")} | (
                {"evidence_id": t["evidence_id"]} if t.get("evidence_id") else {})
            for t in timeline
        ],
        "events": events_as_text(timeline),
        "assessment": assess,
        "objectives": objectives(scenario, sim),
        "available_actions": available_actions(scenario, sim),
        "log_sources": list(LOG_SOURCES),
        "state": legacy_state(scenario, sim),
        "stage": stage,
        "stages": STAGES,
        "score": score["total"],
        "max_score": score["max"],
        "score_breakdown": {
            "categories": [{k: c[k] for k in ("id", "label", "earned", "max")}
                           for c in score["categories"]],
            "penalty_total": score["penalty_total"],
            "penalties": [{"code": p["code"], "points": p["points"], "message": p["message"]}
                          for p in score["penalties"]],
        },
        "tick": sim["tick"],
        "status": "completed" if sim["closed"] else "in_progress",
        "closed": sim["closed"],
        "outcome": sim["outcome"] if sim["closed"] else None,
    }


# ------------------------------------------------------------------
#  Final report
# ------------------------------------------------------------------

_LESSONS = {
    "no_compromise": [
        "A delivered phishing email is not a compromise. Proxy, DNS and sign-in logs showed no interaction with the lure.",
        "Proportionate response matters: quarantining the message and blocking the infrastructure was enough; resetting accounts or isolating hosts would only disrupt users.",
    ],
    "blocked_campaign": [
        "A campaign can be stopped before anyone is affected. Scope every recipient, remove the message from all mailboxes and block the infrastructure.",
        "Absence of evidence has to be shown: proxy, DNS and sign-in logs proved none of the three recipients interacted.",
    ],
    "spoofed_internal": [
        "A familiar internal From address proves nothing. Compare the envelope sender, the Received chain and DMARC.",
        "Even when no credentials were stolen, report the impersonation and block the real sending domain.",
    ],
    "credential_compromise": [
        "Credential phishing is only contained once the stolen credentials are useless: revoke the session, remove persistence such as forwarding rules, reset the password and enforce MFA.",
        "A sign-in from an unfamiliar location shortly after a click is the key correlation between email, proxy and identity logs.",
    ],
    "malicious_attachment": [
        "A malicious macro makes the endpoint the priority: isolate, preserve telemetry, then clean. Cleaning first destroys the evidence.",
        "Hash lookups and sandbox results turn a suspicious file into a confirmed threat and reveal command-and-control infrastructure to block.",
    ],
    "multi_user_campaign": [
        "Scope first: one reported email was part of a campaign against several mailboxes, and each user ended in a different state.",
        "Different victims need different responses: credential theft needs session revocation, rule removal, a reset and MFA; an infected endpoint needs isolation and cleanup; an untouched mailbox only needs the message removed.",
    ],
}

_PENALTY_ADVICE = {
    "premature_action": "Establish the facts (evidence) before taking a response action.",
    "unnecessary_disruption": "Match the response to the evidence; unnecessary resets and sign-outs disrupt users.",
    "unnecessary_isolation": "Isolate an endpoint only when telemetry shows it is compromised.",
    "unnecessary_cleanup": "Only clean an endpoint that is confirmed infected.",
    "blocked_legitimate": "Verify an indicator with the IOC tools before blocking it; the vendor's real domain was not the threat.",
    "attack_progressed": "Act faster on confirmed compromise: the attacker progressed while controls were missing.",
    "destructive_before_preservation": "Preserve forensic artifacts before any action that removes them.",
    "closed_with_gaps": "Verify containment and remediation, and do not close while exposure remains.",
    "false_preservation_claim": "Only confirm evidence preservation when the required artifacts are actually preserved.",
    "dismissed_real_alert": "Prioritise by evidence, not by raw severity: the low-severity email alert was the real incident.",
}


def build_report(scenario, sim, timeline, elapsed_seconds=0, generation=None):
    """Authoritative end-of-incident report built from recorded events and
    the scenario's ground truth. This is the only place ground truth is
    revealed, and only once the incident is closed."""
    gt = scenario["ground_truth"]
    catalog = scenario["evidence_catalog"]
    score = compute_score(scenario, sim, elapsed_seconds)
    status = required_status(scenario, sim)
    missing_resp = [s for s in status if not s["done"]]
    closure = sim["closure"] or {}

    def label(item):
        if item["action"] == "block_indicator":
            return f"Block {_indicator(scenario, item['target'])['value']}"
        u = _user(scenario, item["target"])
        return f"{ACTION_LABELS[item['action']]}: {u['name']}"

    missed_evidence = [{"id": e, "title": catalog[e]["title"]}
                       for e in gt["critical_evidence"] if e not in sim["discovered_evidence"]]
    missed_pres = [{"id": e, "title": catalog[e]["title"]}
                   for e in gt["required_preservation"] if e not in sim["preserved"]]
    truth_class, truth_sev = gt["classification"], gt["true_severity"]
    assess = sim["assessment"]

    lessons = list(_LESSONS[scenario["archetype"]])
    for code in dict.fromkeys(p["code"] for p in score["penalties"]):
        if code in _PENALTY_ADVICE:
            lessons.append(_PENALTY_ADVICE[code])

    recs = []
    if missed_evidence:
        recs.append("Collect these next time: " + ", ".join(m["title"] for m in missed_evidence[:4])
                    + (" and more." if len(missed_evidence) > 4 else "."))
    if missing_resp:
        recs.append("Required controls that were never applied: "
                    + "; ".join(label(m) for m in missing_resp[:5]) + ".")
    if missed_pres:
        recs.append("Preserve forensic artifacts before remediation: "
                    + ", ".join(m["title"] for m in missed_pres[:4]) + ".")
    if closure and closure["classification"] != truth_class:
        recs.append(f"The incident classification was '{truth_class.replace('_', ' ')}'.")
    if closure and closure["root_cause"] != gt["root_cause"]:
        recs.append(f"The root cause was '{gt['root_cause'].replace('_', ' ')}'.")
    if not sim["verify_log"] or not sim["verify_log"][-1]["complete"]:
        recs.append("Verify containment after your last response action and before closing.")
    if not sim["verify_rem_log"] or not sim["verify_rem_log"][-1]["complete"]:
        recs.append("Verify remediation and look for residual exposure before closing.")
    if not recs:
        recs.append("Excellent response. Try the harder difficulty or a different scenario type.")

    tri_rows = [{
        "alert_id": a["id"], "title": a["title"], "analyst": got, "expected": expected,
        "correct": got == expected,
    } for a, got, expected, _ in _triage_points(scenario, sim)]

    wrongly = {p["key"].split(":", 1)[-1] for p in score["penalties"]
               if p.get("key") and p["code"] in ("unnecessary_disruption", "unnecessary_isolation",
                                                  "unnecessary_cleanup", "blocked_legitimate")}
    successful = [
        {"action": d["action"], "target": d.get("target"), "tick": d["tick"],
         "label": ACTION_LABELS[d["action"]]}
        for d in sim["done"]
        if d["action"] in RESPONSE_ACTIONS and d.get("target") not in wrongly
    ]

    critical = set(gt["critical_evidence"])
    evidence_collected = [{
        "id": e, "title": catalog[e]["title"], "type": catalog[e]["category"],
        "source": catalog[e].get("source_artifact"),
        "discovered_at": sim["evidence_log"].get(e, {}).get("at"),
        "provenance": sim["evidence_log"].get(e, {}),
        "critical": e in critical, "preserved": e in sim["preserved"],
    } for e in sim["discovered_evidence"]]

    contained = sim["outcome"] == "contained"
    user_truth = gt["users"]
    findings = []
    for u in scenario["target"]["users"]:
        g = user_truth[u["id"]]
        state = ("compromised account" if g["compromised"] else
                 "infected endpoint" if g["endpoint_malware"] else
                 "opened the message, no further impact" if g["opened"] else "no interaction")
        findings.append({"user": u["name"], "endpoint": u["endpoint"], "finding": state,
                         "identified": u["id"] in sim["known_users"]})

    return {
        "score": score["total"],
        "max_score": score["max"],
        "result": "success" if contained else "failure",
        "outcome": sim["outcome"],
        "score_breakdown": {
            "categories": score["categories"],
            "penalty_total": score["penalty_total"],
            "penalties": score["penalties"],
            "gross": score["gross"],
        },
        "evaluation": {
            "classification": {"analyst": closure.get("classification") or (assess or {}).get("classification"),
                               "truth": truth_class,
                               "correct": closure.get("classification") == truth_class},
            "severity": {"analyst": closure.get("severity") or (assess or {}).get("severity"),
                         "truth": truth_sev},
            "root_cause": {"analyst": closure.get("root_cause"), "truth": gt["root_cause"],
                           "correct": closure.get("root_cause") == gt["root_cause"]},
            "affected_users": {
                "analyst": [(_user(scenario, u) or {}).get("name") for u in closure.get("affected_user_ids", [])],
                "truth": [_user(scenario, u)["name"] for u in gt["affected_users"]]},
            "affected_assets": {"analyst": closure.get("affected_asset_ids", []),
                                "truth": gt["affected_assets"]},
            "residual_risk": {"analyst": closure.get("residual_risk"),
                              "expected": expected_residual_risk(scenario, sim)},
            "triage": tri_rows,
            "containment": {
                "outcome": sim["outcome"],
                "required_total": len(status),
                "completed": len(status) - len(missing_resp),
                "missing": [label(m) for m in missing_resp],
            },
            "remediation": {
                "required": sum(1 for s in status if s["category"] == "remediation"),
                "completed": sum(1 for s in status if s["category"] == "remediation" and s["done"]),
                "verified": bool(sim["verify_rem_log"]) and sim["verify_rem_log"][-1]["complete"],
            },
            "preservation": {
                "required": len(gt["required_preservation"]),
                "preserved": len(gt["required_preservation"]) - len(missed_pres),
                "missing": [m["title"] for m in missed_pres],
            },
            "missed_evidence": missed_evidence,
            "missed_indicators": [
                {"id": i["id"], "value": i["value"], "label": i["label"]}
                for i in scenario["indicators"]
                if i["malicious"] and i["id"] not in sim["known_indicators"]],
            "incorrect_decisions": [
                {"code": p["code"], "points": p["points"], "message": p["message"]}
                for p in score["penalties"]],
            "successful_actions": successful,
            "attack_progress": sim["impact"],
            "remaining_risks": [label(m) for m in missing_resp],
            "justification": sim["justification"],
            "supporting_evidence": [
                {"id": e, "title": catalog[e]["title"]}
                for e in closure.get("supporting_evidence_ids", []) if e in catalog],
            "evidence_preserved_claim": closure.get("evidence_preserved"),
        },
        "findings": findings,
        "evidence_collected": evidence_collected,
        "indicators_discovered": [
            {"value": _indicator(scenario, i)["value"], "type": _indicator(scenario, i)["type"],
             "label": _indicator(scenario, i)["label"],
             "blocked": sim["env"]["indicators"][i]["blocked"]}
            for i in sim["known_indicators"]],
        "original_alerts": [{k: a[k] for k in ("id", "title", "severity", "confidence", "source")}
                            for a in scenario["alerts"]],
        "debrief": {
            "scenario_title": scenario["title"],
            "attack_objective": scenario["attack_objective"],
            "ground_truth_timeline": gt["kill_chain"],
            "malicious_indicators": [
                {"value": i["value"], "type": i["type"], "label": i["label"]}
                for i in scenario["indicators"] if i["malicious"]],
            "lessons_learned": lessons,
            "recommendations": recs,
        },
        "generation": generation or {},
        "timeline": [{k: t[k] for k in ("clock", "tick", "kind", "message")} for t in timeline],
        "log_lines": events_as_text(timeline),
        "state": legacy_state(scenario, sim),
        "duration_seconds": int(elapsed_seconds),
    }


def clone(obj):
    return copy.deepcopy(obj)

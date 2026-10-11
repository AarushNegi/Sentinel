"""Versioned scenario schema, seed validation and cross-field consistency
checks for the Blue Team phishing simulation.

Two layers are validated here:

* the *seed* -- the small, narrative-only structure the language model is
  allowed to produce (names, email wording, attachment filename ...);
* the full *scenario* -- everything the engine needs, derived
  deterministically from a seed by ``composer.compose_scenario``.

Model output is never trusted: every string is length-limited, scanned for
anything that could be a live URL / address / markup, and every enumerated
value is checked against an allow-list.
"""

import ipaddress
import re

SCHEMA_VERSION = 2

DIFFICULTIES = ("easy", "medium", "hard")
SEVERITIES = ("low", "medium", "high", "critical")
ARCHETYPES = (
    "no_compromise",
    "blocked_campaign",
    "spoofed_internal",
    "credential_compromise",
    "malicious_attachment",
    "multi_user_campaign",
)
INCIDENT_TYPES = (
    "credential_phishing", "invoice_fraud", "phishing_campaign",
    "malicious_attachment", "business_email_compromise",
)
CLASSIFICATIONS = (
    "false_positive",
    "phishing_no_compromise",
    "credential_compromise",
    "malware_infection",
    "widespread_campaign",
)
ROOT_CAUSES = (
    "no_user_interaction",
    "phishing_link_credential_theft",
    "malicious_attachment_malware",
    "spoofed_sender_social_engineering",
    "multiple_vectors",
)
RESIDUAL_RISKS = ("none", "low", "medium", "high")
TRIAGE_DISPOSITIONS = ("investigate_now", "monitor", "close_benign")
HEADER_FIELDS = ("from", "reply_to", "return_path", "received")
IOC_TOOLS = {
    "domain_reputation": ("domain", "sender_domain"),
    "url_reputation": ("url",),
    "ip_reputation": ("ip",),
    "dns_analysis": ("domain", "sender_domain"),
    "hash_lookup": ("hash",),
    "related_search": ("domain", "sender_domain", "url", "ip", "hash"),
}
LOG_SOURCES = ("auth", "mailbox", "session", "endpoint", "proxy")
ATTACHMENT_KINDS = ("zip", "docx", "docm", "pdf", "html", "xlsx")

# Every action the engine understands. Anything else is rejected before it
# reaches the state machine.
KNOWN_ACTIONS = (
    "open_email",
    "analyze_headers",
    "inspect_url",
    "inspect_attachment",
    "search_siem",
    "select_alert",
    "triage_alert",
    "view_raw_headers",
    "inspect_header_field",
    "reveal_link",
    "ioc_lookup",
    "collect_log",
    "analyze_auth_logs",
    "investigate_user",
    "investigate_endpoint",
    "set_assessment",
    "preserve_evidence",
    "quarantine_email",
    "block_indicator",
    "revoke_sessions",
    "reset_account",
    "isolate_endpoint",
    "enforce_mfa",
    "remove_mailbox_rule",
    "endpoint_cleanup",
    "verify_containment",
    "verify_remediation",
    "close_incident",
)

SIEM_QUERIES = ("proxy_dns", "mail_delivery")

# Length limits (characters).
MAX_FIELD = 4000          # absolute ceiling for any string in a scenario
MAX_TITLE = 80
MAX_JUSTIFICATION = 1000

RESERVED_TLDS = (".test", ".example", ".invalid", ".localhost")
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
TEST_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("10.0.0.0/8"),
)

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z '\-]{0,29}$")
_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-. ]{2,58}$")
_FORBIDDEN_TEXT = re.compile(
    r"(https?:|ftp:|www\.|@|<|>|javascript:|data:|```|\{\{|\}\}|\\u00)",
    re.IGNORECASE,
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ScenarioValidationError(ValueError):
    """Raised when a seed or scenario fails validation."""


# ------------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------------

def is_reserved_domain(domain):
    domain = str(domain).lower().rstrip(".")
    if domain in RESERVED_DOMAINS or any(domain.endswith("." + d) for d in RESERVED_DOMAINS):
        return True
    return any(domain.endswith(tld) for tld in RESERVED_TLDS)


def is_safe_ip(value):
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return any(ip in net for net in TEST_NETS)


def clean_text(value, field, *, min_len=1, max_len=200):
    """Normalise one model-supplied string or raise ScenarioValidationError."""
    if not isinstance(value, str):
        raise ScenarioValidationError(f"{field} must be a string")
    value = _CONTROL_CHARS.sub("", value)
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) < min_len:
        raise ScenarioValidationError(f"{field} is too short")
    if len(value) > max_len:
        raise ScenarioValidationError(f"{field} is too long ({len(value)} > {max_len})")
    if _FORBIDDEN_TEXT.search(value):
        raise ScenarioValidationError(
            f"{field} contains a URL, address or markup, which is not allowed"
        )
    return value


def _require_keys(obj, keys, where):
    if not isinstance(obj, dict):
        raise ScenarioValidationError(f"{where} must be an object")
    for key in keys:
        if key not in obj:
            raise ScenarioValidationError(f"{where} is missing required field '{key}'")


def _enum(value, allowed, field):
    if value not in allowed:
        raise ScenarioValidationError(f"{field} must be one of {list(allowed)}")
    return value


# ------------------------------------------------------------------
#  Seed validation (language-model output)
# ------------------------------------------------------------------

def victim_count_for(archetype):
    return 3 if archetype in ("multi_user_campaign", "blocked_campaign") else 1


def attachment_required(archetype):
    return archetype in ("multi_user_campaign", "malicious_attachment")


def validate_seed(raw, *, expected_archetype=None, expected_difficulty=None):
    """Validate and normalise a seed. Returns a new, clean dict."""
    _require_keys(
        raw,
        ("title", "archetype", "difficulty", "company", "victims",
         "impersonated_brand", "sender_display_name", "email",
         "attacker_objective"),
        "scenario seed",
    )

    archetype = _enum(raw["archetype"], ARCHETYPES, "archetype")
    difficulty = _enum(raw["difficulty"], DIFFICULTIES, "difficulty")
    if expected_archetype and archetype != expected_archetype:
        raise ScenarioValidationError("archetype does not match the requested archetype")
    if expected_difficulty and difficulty != expected_difficulty:
        raise ScenarioValidationError("difficulty does not match the requested difficulty")

    seed = {
        "title": clean_text(raw["title"], "title", min_len=5, max_len=MAX_TITLE),
        "archetype": archetype,
        "difficulty": difficulty,
        "impersonated_brand": clean_text(
            raw["impersonated_brand"], "impersonated_brand", min_len=2, max_len=40),
        "sender_display_name": clean_text(
            raw["sender_display_name"], "sender_display_name", min_len=2, max_len=50),
        "attacker_objective": clean_text(
            raw["attacker_objective"], "attacker_objective", min_len=10, max_len=240),
    }

    _require_keys(raw["company"], ("name",), "company")
    seed["company"] = {
        "name": clean_text(raw["company"]["name"], "company.name", min_len=2, max_len=40)
    }

    victims = raw["victims"]
    if not isinstance(victims, list):
        raise ScenarioValidationError("victims must be a list")
    want = victim_count_for(archetype)
    if len(victims) != want:
        raise ScenarioValidationError(
            f"{archetype} needs exactly {want} victim(s), got {len(victims)}")
    seed["victims"] = []
    for i, v in enumerate(victims):
        _require_keys(v, ("first_name", "last_name", "role", "department"), f"victims[{i}]")
        for key in ("first_name", "last_name"):
            name = clean_text(v[key], f"victims[{i}].{key}", min_len=2, max_len=30)
            if not _NAME_RE.match(name):
                raise ScenarioValidationError(f"victims[{i}].{key} has invalid characters")
            v = {**v, key: name}
        seed["victims"].append({
            "first_name": v["first_name"],
            "last_name": v["last_name"],
            "role": clean_text(v["role"], f"victims[{i}].role", min_len=2, max_len=50),
            "department": clean_text(
                v["department"], f"victims[{i}].department", min_len=2, max_len=40),
        })

    email = raw["email"]
    _require_keys(email, ("subject", "paragraphs", "cta_label", "signature"), "email")
    paragraphs = email["paragraphs"]
    if not isinstance(paragraphs, list) or not 2 <= len(paragraphs) <= 4:
        raise ScenarioValidationError("email.paragraphs must contain 2 to 4 paragraphs")
    seed["email"] = {
        "subject": clean_text(email["subject"], "email.subject", min_len=5, max_len=120),
        "paragraphs": [
            clean_text(p, f"email.paragraphs[{i}]", min_len=10, max_len=400)
            for i, p in enumerate(paragraphs)
        ],
        "cta_label": clean_text(email["cta_label"], "email.cta_label", min_len=3, max_len=40),
        "signature": clean_text(email["signature"], "email.signature", min_len=2, max_len=60),
    }

    attachment = raw.get("attachment")
    if attachment in (None, {}):
        seed["attachment"] = None
    else:
        _require_keys(attachment, ("filename", "kind"), "attachment")
        kind = _enum(attachment["kind"], ATTACHMENT_KINDS, "attachment.kind")
        filename = attachment["filename"]
        if not isinstance(filename, str) or not _FILENAME_RE.match(filename.strip()):
            raise ScenarioValidationError("attachment.filename is not a safe file name")
        filename = filename.strip()
        if "/" in filename or "\\" in filename or ".." in filename:
            raise ScenarioValidationError("attachment.filename must not contain a path")
        if not filename.lower().endswith("." + kind):
            raise ScenarioValidationError("attachment.filename extension must match kind")
        seed["attachment"] = {"filename": filename, "kind": kind}

    return seed


# ------------------------------------------------------------------
#  Full scenario validation
# ------------------------------------------------------------------

_TOP_LEVEL = (
    "scenario_id", "schema_version", "title", "difficulty", "severity",
    "incident_type", "archetype", "target", "email", "indicators",
    "alerts", "logs", "evidence_catalog", "evidence_map", "reveals", "simulated_events",
    "attack_objective", "ground_truth", "initial_state", "allowed_actions",
    "action_prerequisites", "possible_transitions", "success_conditions",
    "failure_conditions",
)

_USER_GT_ORDER = ("delivered", "opened", "clicked", "submitted", "compromised")


def _walk_strings(node, path="scenario"):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            yield from _walk_strings(v, f"{path}[{i}]")


def validate_scenario(scenario):
    """Validate structure and cross-field consistency of a composed scenario.

    Returns the scenario unchanged if valid; raises ScenarioValidationError
    otherwise.
    """
    _require_keys(scenario, _TOP_LEVEL, "scenario")

    if scenario["schema_version"] != SCHEMA_VERSION:
        raise ScenarioValidationError("unsupported schema_version")
    _enum(scenario["difficulty"], DIFFICULTIES, "difficulty")
    _enum(scenario["severity"], SEVERITIES, "severity")
    _enum(scenario["incident_type"], INCIDENT_TYPES, "incident_type")
    _enum(scenario["archetype"], ARCHETYPES, "archetype")

    for path, text in _walk_strings(scenario):
        if len(text) > MAX_FIELD:
            raise ScenarioValidationError(f"{path} exceeds {MAX_FIELD} characters")

    # --- users ------------------------------------------------------
    target = scenario["target"]
    _require_keys(target, ("primary_user_id", "users"), "target")
    users = target["users"]
    if not isinstance(users, list) or not users:
        raise ScenarioValidationError("target.users must be a non-empty list")
    user_ids = []
    for u in users:
        _require_keys(u, ("id", "name", "role", "department", "email", "endpoint"), "user")
        user_ids.append(u["id"])
        if not is_reserved_domain(u["email"].split("@")[-1]):
            raise ScenarioValidationError("user e-mail must use a reserved example domain")
    if len(set(user_ids)) != len(user_ids):
        raise ScenarioValidationError("duplicate user id")
    if target["primary_user_id"] not in user_ids:
        raise ScenarioValidationError("primary_user_id is not a listed user")

    # --- email ------------------------------------------------------
    email = scenario["email"]
    _require_keys(
        email,
        ("sender_name", "sender_email", "subject", "sent_at", "paragraphs", "links"),
        "email",
    )
    if not is_reserved_domain(email["sender_email"].split("@")[-1]):
        raise ScenarioValidationError("sender must use a reserved example domain")
    link_ids = set()
    for link in email["links"]:
        _require_keys(link, ("id", "label", "display_url", "real_domain"), "email.link")
        link_ids.add(link["id"])
        if not is_reserved_domain(link["real_domain"]):
            raise ScenarioValidationError("link domain must be a reserved example domain")

    # --- indicators -------------------------------------------------
    indicator_ids = set()
    for ind in scenario["indicators"]:
        _require_keys(ind, ("id", "type", "value", "label", "malicious"), "indicator")
        if ind["id"] in indicator_ids:
            raise ScenarioValidationError("duplicate indicator id")
        indicator_ids.add(ind["id"])
        if ind["type"] in ("domain", "sender_domain"):
            if not is_reserved_domain(ind["value"]):
                raise ScenarioValidationError("indicator domain must be reserved")
        elif ind["type"] == "ip":
            if not is_safe_ip(ind["value"]):
                raise ScenarioValidationError("indicator IP must be a documentation address")
        elif ind["type"] == "url":
            host = str(ind["value"]).split("://", 1)[-1].split("/", 1)[0]
            if not str(ind["value"]).startswith("https://") or not is_reserved_domain(host):
                raise ScenarioValidationError("indicator URL must use a reserved domain")

    # --- actions ----------------------------------------------------
    for action in scenario["allowed_actions"]:
        if action not in KNOWN_ACTIONS:
            raise ScenarioValidationError(f"unknown allowed action '{action}'")
    for action in scenario["action_prerequisites"]:
        if action.split(":")[0] not in KNOWN_ACTIONS:
            raise ScenarioValidationError(f"prerequisite for unknown action '{action}'")

    # --- ground truth -----------------------------------------------
    gt = scenario["ground_truth"]
    _require_keys(
        gt,
        ("malicious", "classification", "true_severity", "users",
         "malicious_indicator_ids", "critical_evidence", "required_response",
         "required_preservation"),
        "ground_truth",
    )
    _enum(gt["classification"], CLASSIFICATIONS, "ground_truth.classification")
    _enum(gt["true_severity"], SEVERITIES, "ground_truth.true_severity")

    for uid, g in gt["users"].items():
        if uid not in user_ids:
            raise ScenarioValidationError(f"ground truth names unknown user '{uid}'")
        # Each stage of the kill chain needs the previous one.
        if g.get("submitted") and not g.get("clicked"):
            raise ScenarioValidationError("inconsistent ground truth: credentials submitted without a click")
        if g.get("clicked") and not g.get("opened"):
            raise ScenarioValidationError("inconsistent ground truth: link clicked without opening the email")
        if g.get("opened") and not g.get("delivered"):
            raise ScenarioValidationError("inconsistent ground truth: opened but not delivered")
        if g.get("compromised") and not g.get("submitted"):
            raise ScenarioValidationError("inconsistent ground truth: account compromised without credential submission")
        if g.get("session_active") and not g.get("compromised"):
            raise ScenarioValidationError("inconsistent ground truth: attacker session on an uncompromised account")
        if g.get("endpoint_malware") and not g.get("opened"):
            raise ScenarioValidationError("inconsistent ground truth: malware without opening the email")
    if set(gt["users"]) != set(user_ids):
        raise ScenarioValidationError("ground truth must describe every user")

    compromised = [u for u, g in gt["users"].items() if g.get("compromised")]
    infected = [u for u, g in gt["users"].items() if g.get("endpoint_malware")]
    clicked = [u for u, g in gt["users"].items() if g.get("clicked")]

    classification = gt["classification"]
    if classification in ("false_positive", "phishing_no_compromise"):
        if compromised or infected:
            raise ScenarioValidationError(
                f"ground truth says '{classification}' but also marks a user as compromised")
    if classification == "credential_compromise" and not compromised:
        raise ScenarioValidationError("credential_compromise needs a compromised user")
    if classification == "malware_infection" and not infected:
        raise ScenarioValidationError("malware_infection needs an infected endpoint")
    if classification in ("false_positive", "phishing_no_compromise") and clicked:
        raise ScenarioValidationError("a no-compromise scenario must not contain a click")
    if classification == "widespread_campaign":
        if len(user_ids) < 2 or not (compromised or infected):
            raise ScenarioValidationError("widespread_campaign needs several recipients and an impact")
    if classification == "false_positive" and gt["malicious"]:
        raise ScenarioValidationError("false_positive cannot be malicious")
    if classification != "false_positive" and not gt["malicious"]:
        raise ScenarioValidationError("a malicious classification requires malicious=true")
    if (compromised or infected) and gt["true_severity"] == "low":
        raise ScenarioValidationError("a compromise cannot have low true severity")
    if scenario["archetype"] in ("no_compromise", "blocked_campaign", "spoofed_internal") and clicked:
        raise ScenarioValidationError("this scenario type must not contain a click")
    _require_keys(gt, ("alert_truth", "root_cause", "affected_users", "affected_assets"), "ground_truth")
    if gt["root_cause"] not in ROOT_CAUSES:
        raise ScenarioValidationError("ground_truth.root_cause is invalid")
    for uid in gt["affected_users"]:
        if uid not in user_ids:
            raise ScenarioValidationError("affected_users names an unknown user")

    # --- alerts -----------------------------------------------------
    alert_ids = [a["id"] for a in scenario["alerts"]]
    if len(set(alert_ids)) != len(alert_ids) or not alert_ids:
        raise ScenarioValidationError("alerts must have unique ids")
    primaries = [a for a in scenario["alerts"] if a.get("is_primary")]
    if len(primaries) != 1:
        raise ScenarioValidationError("exactly one alert must be the primary incident")
    if set(gt["alert_truth"]) != set(alert_ids):
        raise ScenarioValidationError("alert_truth must describe every alert")
    for disp in gt["alert_truth"].values():
        _enum(disp, TRIAGE_DISPOSITIONS, "alert_truth")
    if gt["alert_truth"][primaries[0]["id"]] != "investigate_now":
        raise ScenarioValidationError("the primary alert must be investigate_now")

    # --- logs -------------------------------------------------------
    for lid, row in scenario["logs"].items():
        _require_keys(row, ("id", "ts", "source", "user_id", "user", "event_type",
                            "src_ip", "outcome", "device", "detail"), "log row")
        if row["source"] not in LOG_SOURCES:
            raise ScenarioValidationError("log row has an unknown source")
        if row["user_id"] is not None and row["user_id"] not in user_ids:
            raise ScenarioValidationError("log row names an unknown user")
        if row["src_ip"] and not is_safe_ip(row["src_ip"]):
            raise ScenarioValidationError("log source IP must be a documentation or private address")

    for ind_id in gt["malicious_indicator_ids"]:
        if ind_id not in indicator_ids:
            raise ScenarioValidationError(f"malicious indicator '{ind_id}' is not defined")
    for ind in scenario["indicators"]:
        if ind["malicious"] != (ind["id"] in gt["malicious_indicator_ids"]):
            raise ScenarioValidationError("indicator malicious flag disagrees with ground truth")

    # --- evidence ---------------------------------------------------
    catalog = scenario["evidence_catalog"]
    reachable = set()
    for key, ids in scenario["evidence_map"].items():
        action = key.split("@")[0]
        if action not in KNOWN_ACTIONS:
            raise ScenarioValidationError(f"evidence_map references unknown action '{key}'")
        for ev in ids:
            if ev not in catalog:
                raise ScenarioValidationError(f"evidence_map references unknown evidence '{ev}'")
            reachable.add(ev)
    for ev in gt["critical_evidence"]:
        if ev not in catalog:
            raise ScenarioValidationError(f"critical evidence '{ev}' is not in the catalog")
        if ev not in reachable:
            raise ScenarioValidationError(f"critical evidence '{ev}' can never be discovered")
    for ev in gt["required_preservation"]:
        if ev not in catalog or not catalog[ev].get("preservable"):
            raise ScenarioValidationError(f"required preservation '{ev}' is not preservable evidence")
    for key, info in scenario["reveals"].items():
        for ind_id in info.get("indicators", []):
            if ind_id not in indicator_ids:
                raise ScenarioValidationError(f"reveals references unknown indicator '{ind_id}'")
        for uid in info.get("users", []):
            if uid not in user_ids:
                raise ScenarioValidationError(f"reveals references unknown user '{uid}'")

    # --- required response -----------------------------------------
    for req in gt["required_response"]:
        _require_keys(req, ("action", "target", "category"), "required_response")
        if req["action"] not in scenario["allowed_actions"]:
            raise ScenarioValidationError(
                f"required action '{req['action']}' is not allowed in this scenario")
        if req["category"] not in ("containment", "remediation"):
            raise ScenarioValidationError("required_response.category is invalid")
        if req["action"] == "block_indicator":
            if req["target"] not in indicator_ids:
                raise ScenarioValidationError("required block targets an unknown indicator")
        elif req["target"] not in user_ids:
            raise ScenarioValidationError("required response targets an unknown user")
    if classification != "false_positive" and not gt["required_response"]:
        raise ScenarioValidationError("a malicious scenario needs required responses")

    # --- simulated events ------------------------------------------
    seen = set()
    for ev in scenario["simulated_events"]:
        _require_keys(ev, ("id", "trigger_tick", "unless", "message", "impact"), "simulated_event")
        if ev["id"] in seen:
            raise ScenarioValidationError("duplicate simulated event id")
        seen.add(ev["id"])
        if not isinstance(ev["trigger_tick"], int) or ev["trigger_tick"] < 1:
            raise ScenarioValidationError("simulated event trigger_tick must be a positive integer")
        if ev.get("evidence_id") and ev["evidence_id"] not in catalog:
            raise ScenarioValidationError("simulated event references unknown evidence")

    return scenario

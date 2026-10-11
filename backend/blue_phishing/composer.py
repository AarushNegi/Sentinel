"""Deterministically turns a validated *seed* into a complete scenario.

The language model (or a built-in template) only supplies narrative content.
Everything that decides what is true -- the alert queue, indicators, log data,
ground truth, which evidence exists, which responses are required, how the
attack progresses -- is derived here by plain code from the seed's archetype
and difficulty.
"""

import hashlib
import random
import re
import uuid
from datetime import datetime, timedelta, timezone

from .scenario_schema import (
    IOC_TOOLS,
    KNOWN_ACTIONS,
    SCHEMA_VERSION,
    attachment_required,
    validate_scenario,
)

_DEFAULT_ATTACHMENT = {"kind": "docm"}

_ARCH_META = {
    # classification, true severity, incident type, root cause
    "no_compromise": ("phishing_no_compromise", "low", "invoice_fraud", "no_user_interaction"),
    "blocked_campaign": ("phishing_no_compromise", "medium", "phishing_campaign", "no_user_interaction"),
    "spoofed_internal": ("phishing_no_compromise", "medium", "business_email_compromise",
                         "spoofed_sender_social_engineering"),
    "credential_compromise": ("credential_compromise", "high", "credential_phishing",
                              "phishing_link_credential_theft"),
    "malicious_attachment": ("malware_infection", "high", "malicious_attachment",
                             "malicious_attachment_malware"),
    "multi_user_campaign": ("widespread_campaign", "critical", "phishing_campaign",
                            "multiple_vectors"),
}

# Benign / low-priority alerts that sit in the queue next to the real incident.
_DECOY_ALERTS = [
    {"title": "Impossible-travel sign-in (corporate VPN)", "severity": "high", "confidence": 45,
     "source": "Identity Protection", "rule": "Impossible travel",
     "entity": "neha.kapoor@{domain}",
     "description": "Two sign-ins from Mumbai and Singapore 40 minutes apart.",
     "detail": "The user is on the documented travel list (Mumbai to Singapore business trip) and connected through the corporate VPN exit node. MFA was satisfied on both sign-ins.",
     "truth": "close_benign"},
    {"title": "Internal port scan detected", "severity": "medium", "confidence": 88,
     "source": "Network IDS", "rule": "Horizontal port scan",
     "entity": "SEC-SCAN-01",
     "description": "One host probed many internal addresses.",
     "detail": "The source is the security team's scheduled authenticated vulnerability scanner; the scan is on the change calendar for tonight.",
     "truth": "close_benign"},
    {"title": "Bulk newsletter flagged by mail gateway", "severity": "low", "confidence": 30,
     "source": "Secure Email Gateway", "rule": "Tracking pixel heuristic",
     "entity": "updates@itnewsletter.example",
     "description": "A technology newsletter contained tracking pixels.",
     "detail": "The sender is an IT newsletter the employee subscribed to, with valid SPF, DKIM and DMARC. No links point to newly registered domains.",
     "truth": "close_benign"},
    {"title": "Repeated failed logons on a disabled service account", "severity": "medium", "confidence": 60,
     "source": "SIEM", "rule": "Brute-force threshold",
     "entity": "svc-legacy-print",
     "description": "Failed logons against a service account.",
     "detail": "The account is disabled and the attempts come from an internal printer subnet; there were no successful logons. Worth watching but not urgent.",
     "truth": "monitor"},
    {"title": "Login spike on the staff fee-collection portal", "severity": "medium", "confidence": 50,
     "source": "Web Application Firewall", "rule": "Request-rate anomaly",
     "entity": "fees-portal-01",
     "description": "Sign-in attempts to the fee-collection portal tripled in one hour.",
     "detail": "The last date for paying the semester fee is tomorrow. The attempts come from many ordinary student addresses and almost all succeeded on the first try.",
     "truth": "close_benign"},
    {"title": "Failed UPI settlement file upload", "severity": "low", "confidence": 35,
     "source": "SIEM", "rule": "Scheduled job failure",
     "entity": "FIN-SFTP-01",
     "description": "The nightly UPI settlement file failed to upload once.",
     "detail": "The bank's SFTP server was in a maintenance window. The retry at 02:10 succeeded and the reconciliation matches.",
     "truth": "close_benign"},
    {"title": "Nightly cloud-storage upload doubled", "severity": "medium", "confidence": 55,
     "source": "Web Proxy", "rule": "Egress volume anomaly",
     "entity": "BKP-SRV-02",
     "description": "Outbound volume to a cloud storage provider rose sharply.",
     "detail": "The backup server uploaded the quarterly GST and accounts archive in addition to the nightly delta. The destination is the approved backup provider.",
     "truth": "monitor"},
]

_RELATED = {
    "IND-SENDER": ["IND-LURE-DOMAIN", "IND-SENDER-IP"],
    "IND-LURE-DOMAIN": ["IND-SENDER", "IND-LURE-IP", "IND-URL-LURE"],
    "IND-URL-LURE": ["IND-LURE-DOMAIN"],
    "IND-LURE-IP": ["IND-LURE-DOMAIN"],
    "IND-SENDER-IP": ["IND-SENDER"],
    "IND-ATTACH-HASH": ["IND-C2"],
    "IND-C2": ["IND-ATTACH-HASH"],
    "IND-ATTACKER-IP": [],
    "IND-BRAND": [],
}


def _slug(text, default="vendor", limit=16):
    slug = re.sub(r"[^a-z0-9]", "", str(text).lower())[:limit]
    return slug or default


def _typosquat(slug):
    for src, dst in (("l", "1"), ("o", "0"), ("m", "rn")):
        if src in slug:
            return slug.replace(src, dst, 1)
    return slug + "x"


def _dt(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _t(value):
    return value.strftime("%H:%M:%S")


def _evidence(ev_id, title, category, summary, *, fields=None, columns=None,
              rows=None, verdict=None, preservable=False, source=None,
              entity=None, related=()):
    return {
        "id": ev_id,
        "title": title,
        "category": category,
        "preservable": preservable,
        "source_artifact": source or category,
        "entity": entity,
        "related": list(related),
        "content": {
            "summary": summary,
            "fields": [list(f) for f in (fields or [])],
            "columns": list(columns or []),
            "rows": [list(r) for r in (rows or [])],
            "verdict": verdict,
        },
    }


def _user_truth(archetype, user_ids, difficulty):
    base = {
        "delivered": True, "opened": False, "clicked": False,
        "submitted": False, "compromised": False, "session_active": False,
        "endpoint_malware": False, "mailbox_rule": False,
    }
    truth = {uid: dict(base) for uid in user_ids}
    first = user_ids[0]
    compromise = dict(opened=True, clicked=True, submitted=True, compromised=True,
                      session_active=True, mailbox_rule=True)
    if archetype == "no_compromise":
        truth[first]["opened"] = difficulty != "easy"
    elif archetype == "spoofed_internal":
        truth[first]["opened"] = True
    elif archetype == "credential_compromise":
        truth[first].update(compromise)
    elif archetype == "malicious_attachment":
        truth[first].update(opened=True, endpoint_malware=True)
    elif archetype == "multi_user_campaign":
        truth[first].update(compromise)
        truth[user_ids[1]].update(opened=True, endpoint_malware=True)
    # blocked_campaign: every recipient was delivered the mail and nothing more
    return truth


def compose_scenario(seed, *, source="template", now=None, scenario_id=None):
    """Build and validate a full scenario from a clean seed."""
    now = now or datetime.now(timezone.utc)
    scenario_id = scenario_id or f"SCN-{uuid.uuid4().hex[:12].upper()}"
    rng = random.Random(scenario_id)

    archetype = seed["archetype"]
    difficulty = seed["difficulty"]
    classification, true_severity, incident_type, root_cause = _ARCH_META[archetype]
    spoof = archetype == "spoofed_internal"

    # ---- people ----------------------------------------------------
    company_slug = _slug(seed["company"]["name"], "acme", 14)
    company_domain = f"{company_slug}.test"
    users, used = [], set()
    for i, v in enumerate(seed["victims"], start=1):
        local = f"{_slug(v['first_name'], 'user', 12)}.{_slug(v['last_name'], 'one', 14)}"
        if local in used:
            local = f"{local}{i}"
        used.add(local)
        users.append({
            "id": f"u{i}",
            "name": f"{v['first_name']} {v['last_name']}",
            "role": v["role"],
            "department": v["department"],
            "email": f"{local}@{company_domain}",
            "endpoint": f"{_slug(v['department'], 'org', 3).upper()}-WS-{rng.randint(10, 99):03d}",
        })
    user_ids = [u["id"] for u in users]
    by_id = {u["id"]: u for u in users}
    primary = users[0]
    truth = _user_truth(archetype, user_ids, difficulty)
    compromised = [u for u in user_ids if truth[u]["compromised"]]
    infected = [u for u in user_ids if truth[u]["endpoint_malware"]]
    affected = [u for u in user_ids if truth[u]["clicked"] or truth[u]["endpoint_malware"]]

    # ---- infrastructure (documentation ranges and reserved TLDs) ----
    brand_slug = _slug(seed["impersonated_brand"], "vendor", 14)
    legit_domain = f"{brand_slug}.test"
    if difficulty == "easy":
        sender_domain = f"secure-{brand_slug}-portal.test"
    elif difficulty == "medium":
        sender_domain = f"{brand_slug}-billing.test"
    else:
        sender_domain = f"{_typosquat(brand_slug)}.test"
    lure_domain = f"secure.{sender_domain}"
    lure_url = f"https://{lure_domain}/review"
    lure_ip = f"203.0.113.{rng.randint(10, 240)}"
    sender_ip = f"203.0.113.{rng.randint(10, 240)}"
    attacker_ip = f"198.51.100.{rng.randint(10, 240)}"
    c2_domain = f"cdn-update-{rng.randint(100, 999)}.example"
    c2_ip = f"192.0.2.{rng.randint(10, 240)}"
    domain_age_days = {"easy": 2, "medium": 5, "hard": 1}[difficulty]
    sender_local = rng.choice(["billing", "accounts", "payments", "support"])
    if spoof:
        words = re.findall(r"[a-z]+", seed["sender_display_name"].lower())
        sender_email = f"{'.'.join(words[:2]) or 'executive'}@{company_domain}"
        return_path = f"bounce@{sender_domain}"
    else:
        sender_email = f"{sender_local}@{sender_domain}"
        return_path = sender_email

    # ---- timeline anchors ------------------------------------------
    t_sent = now - timedelta(minutes=40)
    t_delivered = t_sent + timedelta(seconds=7)
    t_alert = t_sent + timedelta(minutes=2)
    t_open = t_sent + timedelta(minutes=9)
    t_click = t_sent + timedelta(minutes=10)
    t_submit = t_sent + timedelta(minutes=11)
    t_login = t_sent + timedelta(minutes=14)
    t_rule = t_sent + timedelta(minutes=16)

    # ---- attachment ------------------------------------------------
    attachment = seed.get("attachment")
    if attachment_required(archetype) and (not attachment or attachment["kind"] != "docm"):
        attachment = {"filename": f"Invoice_{rng.randint(10000, 99999)}.docm",
                      "kind": _DEFAULT_ATTACHMENT["kind"]}
    attachment_obj = None
    if attachment:
        sha = hashlib.sha256(f"{attachment['filename']}|{scenario_id}".encode()).hexdigest()
        attachment_obj = {
            "id": "ATT-1", "filename": attachment["filename"], "kind": attachment["kind"],
            "size_kb": rng.randint(18, 240), "sha256": sha,
        }

    # ---- email -----------------------------------------------------
    greeting = (f"Hello {seed['victims'][0]['first_name']},"
                if len(seed["victims"]) == 1 else "Hello team,")
    show_real = difficulty == "easy"
    links = [
        {"id": "LINK-1", "label": seed["email"]["cta_label"],
         "display_url": lure_url if show_real else f"https://{legit_domain}/review",
         "real_domain": lure_domain, "real_url": lure_url},
        {"id": "LINK-2", "label": "Privacy policy",
         "display_url": f"https://{legit_domain}/privacy",
         "real_domain": legit_domain, "real_url": f"https://{legit_domain}/privacy"},
    ]
    reply_to = (f"{sender_local}@{sender_domain}" if difficulty == "hard" and not spoof
                else f"collect-{sender_local}@{company_slug}-mail.example")
    email = {
        "message_id": f"<{uuid.UUID(int=rng.getrandbits(128)).hex[:20]}@{sender_domain}>",
        "sender_name": seed["sender_display_name"],
        "sender_email": sender_email,
        "return_path": return_path,
        "reply_to": reply_to,
        "subject": seed["email"]["subject"],
        "sent_at": _dt(t_sent),
        "greeting": greeting,
        "paragraphs": list(seed["email"]["paragraphs"]),
        "signature": seed["email"]["signature"],
        "links": links,
        "attachment": attachment_obj,
        "gateway": {"score": {"easy": 91, "medium": 78, "hard": 64}[difficulty],
                    "verdict": "Suspicious - delivered with warning"},
    }

    # ---- indicators ------------------------------------------------
    indicators = [
        {"id": "IND-SENDER", "type": "sender_domain", "value": sender_domain,
         "label": "Sender (envelope) domain", "malicious": True},
        {"id": "IND-SENDER-IP", "type": "ip", "value": sender_ip,
         "label": "Originating mail server", "malicious": True},
        {"id": "IND-BRAND", "type": "domain", "value": legit_domain,
         "label": "Domain shown in message links and footer", "malicious": False},
        {"id": "IND-LURE-DOMAIN", "type": "domain", "value": lure_domain,
         "label": "Destination of the primary call-to-action link", "malicious": True},
        {"id": "IND-URL-LURE", "type": "url", "value": lure_url,
         "label": "Full URL behind the call-to-action", "malicious": True},
        {"id": "IND-LURE-IP", "type": "ip", "value": lure_ip,
         "label": "Hosting IP of the destination site", "malicious": True},
    ]
    if attachment_obj:
        indicators.append({"id": "IND-ATTACH-HASH", "type": "hash", "value": attachment_obj["sha256"],
                           "label": "SHA-256 of the attachment", "malicious": True})
    if compromised:
        indicators.append({"id": "IND-ATTACKER-IP", "type": "ip", "value": attacker_ip,
                           "label": "Source of the unfamiliar sign-in", "malicious": True})
    if infected:
        indicators.append({"id": "IND-C2", "type": "domain", "value": c2_domain,
                           "label": "Outbound beaconing destination", "malicious": True})
    ind_by_id = {i["id"]: i for i in indicators}
    malicious_ids = [i["id"] for i in indicators if i["malicious"]]

    # ---- evidence catalog / disclosure map -------------------------
    catalog, evidence_map, reveals = {}, {}, {}

    def add(ev, key, reveal_indicators=(), reveal_users=()):
        catalog[ev["id"]] = ev
        evidence_map.setdefault(key, []).append(ev["id"])
        if reveal_indicators or reveal_users:
            slot = reveals.setdefault(key, {"indicators": [], "users": []})
            slot["indicators"] += [i for i in reveal_indicators if i in ind_by_id
                                   and i not in slot["indicators"]]
            slot["users"] += [u for u in reveal_users if u not in slot["users"]]

    from_domain = sender_email.split("@")[1]

    add(_evidence(
        "EV-EMAIL", "Original message captured from mail gateway", "email",
        "Raw message stored by the secure email gateway before delivery.",
        fields=[
            ("Message-ID", email["message_id"]),
            ("From", f"{seed['sender_display_name']} <{sender_email}>"),
            ("Subject", seed["email"]["subject"]),
            ("Sent", email["sent_at"]),
            ("Gateway score", f"{email['gateway']['score']} / 100"),
            ("Links in body", str(len(links))),
            ("Attachments", attachment_obj["filename"] if attachment_obj else "None"),
        ],
        verdict=("The From address uses our own domain, yet the message did not originate from our mail servers."
                 if spoof else
                 "Display name imitates a known vendor but the sender domain is not the vendor's."),
        preservable=True, source="Mail gateway", related=["EV-HEADERS"],
    ), "open_email", reveal_indicators=["IND-SENDER", "IND-BRAND"])

    # raw headers + per-field inspection ------------------------------
    raw_rows = [
        ["Return-Path", f"<{return_path}>"],
        ["Received", f"from mail.{sender_domain} ({sender_ip}) by mx.{company_domain}; {_dt(t_sent)}"],
        ["Received", f"from mx.{company_domain} by gateway.{company_domain}; {_dt(t_delivered)}"],
        ["From", f"{seed['sender_display_name']} <{sender_email}>"],
        ["Reply-To", f"<{reply_to}>"],
        ["To", primary["email"]],
        ["Subject", seed["email"]["subject"]],
        ["Message-ID", email["message_id"]],
        ["X-Originating-IP", sender_ip],
    ]
    add(_evidence(
        "EV-RAWHEADERS", "Raw message headers", "header",
        "Complete header block as received by the gateway.",
        columns=["Header", "Value"], rows=raw_rows, preservable=True,
        source="Raw message", related=["EV-HEADERS", "EV-EMAIL"],
    ), "view_raw_headers")

    add(_evidence(
        "EV-FIELD-from", "Header field: From", "header",
        "Display name versus address in the From header.",
        fields=[("Display name", seed["sender_display_name"]), ("Address", sender_email),
                ("Domain", from_domain),
                ("Sent by our own mail servers", "No" if spoof else "n/a (external sender)")],
        verdict=("The visible sender claims to be a colleague at our company but the message was relayed from outside."
                 if spoof else "The display name imitates a vendor; the address belongs to a different domain."),
        source="Raw message", entity="sender",
    ), "inspect_header_field@from")
    reply_differs = reply_to.split("@")[1] != from_domain
    add(_evidence(
        "EV-FIELD-reply_to", "Header field: Reply-To", "header",
        "Comparison of the Reply-To and From domains.",
        fields=[("From domain", from_domain), ("Reply-To", reply_to),
                ("Reply-To domain", reply_to.split("@")[1]),
                ("Domains match", "No" if reply_differs else "Yes")],
        verdict=("Replies would go to an unrelated mailbox the attacker controls."
                 if reply_differs else
                 "Reply-To matches the sender, so replies stay with the same (attacker-owned) domain."),
        source="Raw message", entity="sender", related=["EV-FIELD-from"],
    ), "inspect_header_field@reply_to")
    add(_evidence(
        "EV-FIELD-return_path", "Header field: Return-Path", "header",
        "Envelope sender used for delivery and bounces.",
        fields=[("Return-Path", return_path), ("Envelope domain", return_path.split("@")[1]),
                ("Equals From address", "Yes" if return_path == sender_email else "No")],
        verdict=("The envelope domain differs from the visible From domain - a classic spoofing sign."
                 if return_path != sender_email else "Envelope and visible sender are the same."),
        source="Raw message", entity="sender",
    ), "inspect_header_field@return_path")
    add(_evidence(
        "EV-FIELD-received", "Header field: Received chain", "header",
        "Delivery path and the originating mail server.",
        columns=["Hop", "From", "By", "Time"],
        rows=[["1", f"mail.{sender_domain} ({sender_ip})", f"mx.{company_domain}", _t(t_sent)],
              ["2", f"mx.{company_domain}", f"gateway.{company_domain}", _t(t_delivered)]],
        fields=[("Originating IP", sender_ip)],
        verdict="The first hop is an external server that is not part of the vendor's or our infrastructure.",
        source="Raw message", entity="sender", related=["EV-HEADERS"],
    ), "inspect_header_field@received", reveal_indicators=["IND-SENDER-IP"])

    # authentication analysis ------------------------------------------
    if spoof:
        spf, dkim, dmarc = (f"PASS for {sender_domain} (envelope domain, not aligned with From)",
                            "NONE", f"FAIL for {company_domain} (policy: none - message delivered)")
        header_verdict = (f"The From domain {company_domain} is ours, but the message was sent by {sender_domain}. "
                          "DMARC failed and our policy only monitors, so it was delivered.")
    elif difficulty == "easy":
        spf, dkim, dmarc = "FAIL (sender IP not authorised)", "NONE (no signature)", "FAIL"
        header_verdict = "Authentication failed on every mechanism and Reply-To points elsewhere."
    else:
        spf, dkim, dmarc = (f"PASS for {sender_domain}", f"PASS (d={sender_domain})",
                            f"PASS for {sender_domain} (aligned with the attacker's own domain)")
        header_verdict = (
            f"SPF/DKIM/DMARC pass only because the attacker owns {sender_domain}. "
            f"That domain is not {legit_domain}, was registered {domain_age_days} day(s) ago, "
            "and imitates the vendor. Passing authentication does not make a message legitimate.")
    add(_evidence(
        "EV-HEADERS", "Email authentication analysis (SPF / DKIM / DMARC)", "header",
        "Authentication results and delivery path extracted from the message headers.",
        fields=[("Return-Path", f"<{return_path}>"), ("Reply-To", reply_to),
                ("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc),
                ("X-Originating-IP", sender_ip), ("Sender domain age", f"{domain_age_days} day(s)")],
        columns=["Hop", "From", "By", "Time"],
        rows=[["1", f"mail.{sender_domain} ({sender_ip})", f"mx.{company_domain}", _t(t_sent)],
              ["2", f"mx.{company_domain}", f"gateway.{company_domain}", _t(t_delivered)]],
        verdict=header_verdict, preservable=True, source="Raw message",
        related=["EV-RAWHEADERS", "EV-EMAIL"],
    ), "analyze_headers")

    # links ------------------------------------------------------------
    add(_evidence(
        "EV-LINKTARGET-LINK-1", f"Link target: \"{seed['email']['cta_label']}\"", "url",
        "What the link shows versus where it really points (not visited).",
        fields=[("Displayed as", links[0]["display_url"]), ("Actual target", lure_url),
                ("Actual domain", lure_domain),
                ("Display matches target", "Yes" if show_real else "No")],
        verdict=("The visible text names the vendor but the real destination is a different domain."
                 if not show_real else "The target is shown openly, and it is not the vendor's site."),
        source="Email body", entity="LINK-1", related=["EV-EMAIL"],
    ), "reveal_link@LINK-1", reveal_indicators=["IND-LURE-DOMAIN", "IND-URL-LURE"])
    add(_evidence(
        "EV-LINKTARGET-LINK-2", "Link target: \"Privacy policy\"", "url",
        "What the link shows versus where it really points (not visited).",
        fields=[("Displayed as", links[1]["display_url"]), ("Actual target", links[1]["real_url"]),
                ("Display matches target", "Yes")],
        verdict="Points to the genuine vendor site.", source="Email body", entity="LINK-2",
    ), "reveal_link@LINK-2")
    add(_evidence(
        "EV-URL-LINK-1", f"Destination analysis: \"{seed['email']['cta_label']}\"", "url",
        f"The link resolves to {lure_domain}, not {legit_domain}.",
        fields=[("Displayed as", links[0]["display_url"]), ("Actual destination", lure_url),
                ("Resolved IP", lure_ip), ("Domain registered", f"{domain_age_days} day(s) ago"),
                ("Page title", f"{seed['impersonated_brand']} - Sign in"),
                ("Form action", f"POST https://{lure_domain}/session"),
                ("Reputation", "MALICIOUS - credential harvesting clone")],
        columns=["Step", "URL", "Status"],
        rows=[["1", lure_url, "302"], ["2", f"https://{lure_domain}/signin", "200"]],
        verdict="Credential-harvesting page imitating the vendor's sign-in.",
        source="Sandbox", entity="LINK-1", related=["EV-LINKTARGET-LINK-1"],
    ), "inspect_url@LINK-1", reveal_indicators=["IND-LURE-DOMAIN", "IND-URL-LURE", "IND-LURE-IP"])
    add(_evidence(
        "EV-URL-LINK-2", "Destination analysis: \"Privacy policy\"", "url",
        f"This link points to the genuine {legit_domain} site.",
        fields=[("Destination", f"https://{legit_domain}/privacy"),
                ("Domain registered", "more than 10 years ago"), ("Reputation", "Clean")],
        verdict="Benign link. Attackers often include real links to look authentic.",
        source="Sandbox", entity="LINK-2",
    ), "inspect_url@LINK-2")

    # attachment -------------------------------------------------------
    if attachment_obj:
        kind = attachment_obj["kind"]
        if infected:
            sandbox = (f"Macro auto-runs on open, launches a PowerShell stage-1 downloader "
                       f"and beacons to {c2_domain} (simulated sandbox detonation).")
            att_verdict = "Malicious macro document - a malware dropper."
        elif kind in ("html", "zip"):
            sandbox = f"Contains an HTML form that posts to {lure_domain}. No executable payload."
            att_verdict = "Credential-harvesting lure, not malware."
        elif kind == "pdf":
            sandbox = f"PDF contains a single link to {lure_domain}. No exploit or script."
            att_verdict = "Link-carrier lure, not malware."
        else:
            sandbox = f"Document contains an external link to {lure_domain}. No macros."
            att_verdict = "Link-carrier lure, not malware."
        add(_evidence(
            "EV-ATTACH", f"Attachment analysis: {attachment_obj['filename']}", "attachment",
            "Static analysis and simulated sandbox detonation of the attachment.",
            fields=[("File name", attachment_obj["filename"]), ("Type", kind.upper()),
                    ("Size", f"{attachment_obj['size_kb']} KB"), ("SHA-256", attachment_obj["sha256"]),
                    ("Sandbox", sandbox)],
            verdict=att_verdict, source="Sandbox", entity="ATT-1", related=["EV-EMAIL"],
        ), "inspect_attachment@ATT-1",
            reveal_indicators=["IND-ATTACH-HASH"] + (["IND-C2"] if infected else []))

    # IOC lookups ------------------------------------------------------
    def related_rows(ind_id):
        return [[ind_by_id[r]["type"], ind_by_id[r]["value"], ind_by_id[r]["label"]]
                for r in _RELATED.get(ind_id, []) if r in ind_by_id]

    for ind in indicators:
        iid, itype, value, bad = ind["id"], ind["type"], ind["value"], ind["malicious"]
        for tool, types in IOC_TOOLS.items():
            if itype not in types:
                continue
            ev_id = f"EV-IOC-{iid}-{tool}"
            key = f"ioc_lookup@{iid}:{tool}"
            rev = []
            fields, rows, columns, verdict, summary = [], [], [], None, ""
            if tool == "domain_reputation":
                summary = f"Reputation lookup for {value}."
                if bad:
                    fields = [("Domain", value), ("Registered", f"{domain_age_days} day(s) ago"),
                              ("Registrar", "NameBargain (fictional)"), ("Reputation", "MALICIOUS"),
                              ("Threat-intel matches", "3 of 8 feeds"),
                              ("Category", "Malware command-and-control" if iid == "IND-C2"
                               else "Phishing / credential harvesting"),
                              ("Confidence", "High")]
                    verdict = "Newly registered lookalike infrastructure with multiple threat-intel hits."
                else:
                    fields = [("Domain", value), ("Registered", "more than 10 years ago"),
                              ("Reputation", "CLEAN"), ("Threat-intel matches", "0 of 8 feeds"),
                              ("Category", "Business services"), ("Confidence", "High")]
                    verdict = "Established legitimate vendor domain. Do not block it."
            elif tool == "url_reputation":
                summary = f"URL reputation for {value}."
                fields = [("URL", value), ("Verdict", "MALICIOUS"),
                          ("Category", "Credential harvesting"), ("First seen", f"{domain_age_days} day(s) ago"),
                          ("Hosting IP", lure_ip), ("Confidence", "High")]
                verdict = "URL serves a clone of the vendor's sign-in page."
            elif tool == "ip_reputation":
                summary = f"IP reputation for {value}."
                role = {"IND-LURE-IP": "Phishing site host", "IND-SENDER-IP": "Outbound mail relay",
                        "IND-ATTACKER-IP": "Anonymising VPS used for unauthorised sign-ins"}.get(iid, "Unknown")
                fields = [("IP", value), ("Reputation", "MALICIOUS"), ("Observed role", role),
                          ("Hosting", "Bulletproof hosting (fictional)"),
                          ("Abuse reports", str(rng.randint(14, 90))), ("Confidence", "High")]
                verdict = "Address is on multiple abuse lists; treat connections as hostile."
            elif tool == "dns_analysis":
                summary = f"DNS records for {value}."
                if iid == "IND-LURE-DOMAIN":
                    rows = [["A", lure_ip, "300"], ["NS", f"ns1.{sender_domain}", "3600"]]
                    rev = ["IND-LURE-IP"]
                    verdict = "Resolves to bulletproof hosting; very short TTL typical of throwaway infrastructure."
                elif iid == "IND-SENDER":
                    rows = [["MX", f"mail.{sender_domain}", "300"], ["A", sender_ip, "300"],
                            ["TXT", f"v=spf1 ip4:{sender_ip} -all", "300"]]
                    rev = ["IND-SENDER-IP"]
                    verdict = "Mail server is hosted on the same bulletproof range; SPF only authorises itself."
                elif iid == "IND-C2":
                    rows = [["A", c2_ip, "60"]]
                    verdict = "Resolves to a fast-flux address with a 60 second TTL."
                else:
                    rows = [["A", f"203.0.113.{rng.randint(1, 9)}", "86400"], ["MX", f"mail.{value}", "3600"]]
                    verdict = "Ordinary long-lived records for a legitimate vendor."
                columns = ["Type", "Value", "TTL"]
            elif tool == "hash_lookup":
                summary = f"Threat-intelligence match for hash {value[:16]}..."
                fam = "LarkDrop macro dropper (fictional)" if infected else "Generic phishing kit"
                fields = [("SHA-256", value), ("Verdict", "MALICIOUS"), ("Family", fam),
                          ("First seen", f"{domain_age_days + 1} day(s) ago"),
                          ("Detections", "41 of 70 engines")]
                verdict = "Known malicious sample."
            else:  # related_search
                summary = f"Indicators related to {value}."
                rows = related_rows(iid)
                columns = ["Type", "Value", "Relationship"]
                rev = list(_RELATED.get(iid, []))
                verdict = "Related infrastructure found." if rows else "No related indicators found."
            add(_evidence(ev_id, f"{tool.replace('_', ' ').title()}: {value[:60]}", "ioc", summary,
                          fields=fields, columns=columns, rows=rows, verdict=verdict,
                          source="Threat intelligence (simulated)", entity=iid,
                          related=[f"EV-IOC-{iid}-{t}" for t in IOC_TOOLS
                                   if t != tool and itype in IOC_TOOLS[t]][:2]),
                key, reveal_indicators=rev)

    # SIEM -------------------------------------------------------------
    proxy_rows, proxy_users = [], []
    for uid in user_ids:
        g, u = truth[uid], by_id[uid]
        if g["clicked"]:
            proxy_users.append(uid)
            proxy_rows += [
                [_t(t_click), u["endpoint"], u["email"], lure_domain, "ALLOWED", "DNS query + HTTPS GET /review"],
                [_t(t_submit), u["endpoint"], u["email"], lure_domain, "ALLOWED", "HTTPS POST /session (form submission)"],
            ]
        if g["endpoint_malware"]:
            proxy_users.append(uid)
            proxy_rows.append([_t(t_open + timedelta(minutes=2)), u["endpoint"], u["email"],
                               c2_domain, "ALLOWED", "Periodic HTTPS beacon (60s interval)"])
    add(_evidence(
        "EV-SIEM-PROXY", "SIEM: DNS and web proxy search", "siem",
        (f"{len(proxy_rows)} event(s) found for {lure_domain} and related infrastructure in the last 24h."
         if proxy_rows else f"No DNS or proxy activity for {lure_domain} or {sender_domain} in the last 24 hours."),
        columns=["Time", "Host", "User", "Destination", "Action", "Detail"], rows=proxy_rows,
        verdict=("Hosts above contacted attacker infrastructure." if proxy_rows
                 else "No internal host contacted the attacker's infrastructure."),
        preservable=True, source="SIEM", related=["EV-SIEM-MAIL"],
    ), "search_siem@proxy_dns", reveal_users=proxy_users,
        reveal_indicators=(["IND-C2"] if infected else []))
    add(_evidence(
        "EV-SIEM-MAIL", "SIEM: mail delivery search", "siem",
        f"{len(user_ids)} recipient(s) received a message from {from_domain}.",
        columns=["Time", "Recipient", "Delivery", "Gateway verdict", "Folder"],
        rows=[[_t(t_delivered), by_id[u]["email"], "Delivered", "Suspicious - warned", "Inbox"]
              for u in user_ids],
        verdict=("Several mailboxes were targeted - the message must be removed from every one."
                 if len(user_ids) > 1 else "Single recipient."),
        source="SIEM", related=["EV-SIEM-PROXY"],
    ), "search_siem@mail_delivery", reveal_users=user_ids)

    # per-user summaries ----------------------------------------------
    for uid in user_ids:
        u, g = by_id[uid], truth[uid]
        auth_rows = [
            ["Yesterday 08:52:11", u["email"], "Success", f"10.20.4.{rng.randint(10, 200)}", "Head office", "Managed laptop", "Approved"],
            ["Today 08:47:30", u["email"], "Success", f"10.20.4.{rng.randint(10, 200)}", "Head office", "Managed laptop", "Approved"],
        ]
        if g["compromised"]:
            auth_rows += [
                [_t(t_login), u["email"], "Success", attacker_ip, "Unfamiliar location (impossible travel)",
                 "Unknown browser, new device",
                 "Approved after repeated prompts" if difficulty == "hard" else "Not requested (legacy protocol)"],
                [_t(t_rule), u["email"], "Inbox rule created", attacker_ip, "Unfamiliar location",
                 "Unknown browser, new device", "Forward all mail to an external address"],
                [_t(t_login + timedelta(minutes=1)), u["email"], "Session active", attacker_ip,
                 "Unfamiliar location", "Unknown browser, new device", "-"],
            ]
            auth_summary = "A sign-in from an unfamiliar location followed the credential submission, and a forwarding rule was created."
            auth_verdict = "Attacker is holding a valid session for this account and has set up mail forwarding."
        else:
            auth_summary = "No anomalous authentication events for this account."
            auth_verdict = "No sign of account takeover."
        add(_evidence(
            f"EV-AUTH-{uid}", f"Authentication log analysis: {u['name']}", "identity", auth_summary,
            columns=["Time", "Account", "Result", "Source IP", "Location", "Device", "MFA / detail"],
            rows=auth_rows, verdict=auth_verdict, preservable=True, source="Identity provider",
            entity=uid, related=[f"EV-USER-{uid}"],
        ), f"analyze_auth_logs@{uid}",
            reveal_indicators=["IND-ATTACKER-IP"] if g["compromised"] else [])

        if g["submitted"]:
            statement = "Recalls entering the corporate password into the invoice sign-in page."
        elif g["clicked"]:
            statement = "Recalls clicking the link but says they closed the page."
        elif g["endpoint_malware"]:
            statement = "Opened the attachment and enabled content when prompted."
        elif g["opened"]:
            statement = "Opened the message, thought it looked odd and did not interact."
        else:
            statement = "Has not opened the message. No report submitted."
        add(_evidence(
            f"EV-USER-{uid}", f"User investigation: {u['name']}", "user",
            "Mailbox audit and interview with the user.",
            fields=[("Name", u["name"]), ("Role", u["role"]), ("Department", u["department"]),
                    ("Message opened", f"Yes ({_t(t_open)})" if g["opened"] else "No"),
                    ("Link click recorded", f"Yes ({_t(t_click)})" if g["clicked"] else "No"),
                    ("User statement", statement)],
            verdict=("User interacted with the lure." if g["opened"] else "No interaction."),
            source="Mailbox audit", entity=uid, related=[f"EV-AUTH-{uid}"],
        ), f"investigate_user@{uid}")

        if g["endpoint_malware"]:
            ep_rows = [
                [_t(t_open + timedelta(minutes=1)), "WINWORD.EXE", "Macro executed", attachment_obj["filename"]],
                [_t(t_open + timedelta(minutes=1, seconds=4)), "powershell.exe", "Spawned by WINWORD.EXE", "Encoded command line"],
                [_t(t_open + timedelta(minutes=2)), "powershell.exe", "Network connection", f"{c2_domain} ({c2_ip})"],
            ]
            ep_summary, ep_verdict = ("Suspicious macro-spawned PowerShell and outbound beaconing.",
                                      "Endpoint is infected. Isolate it, preserve its triage data, then clean it.")
        elif g["clicked"]:
            ep_rows = [[_t(t_click), "msedge.exe", "Network connection", f"{lure_domain} ({lure_ip})"]]
            ep_summary, ep_verdict = ("Browser reached the phishing site. No malicious process activity.",
                                      "Credential theft only; no malware on the endpoint.")
        else:
            ep_rows = []
            ep_summary, ep_verdict = "No suspicious process, network or file activity.", "Endpoint is clean."
        add(_evidence(
            f"EV-ENDPT-{uid}", f"Endpoint telemetry: {u['endpoint']}", "endpoint", ep_summary,
            fields=[("Host", u["endpoint"]), ("EDR agent", "Healthy"), ("Network state", "Online")],
            columns=["Time", "Process", "Event", "Detail"], rows=ep_rows, verdict=ep_verdict,
            preservable=True, source="EDR", entity=uid, related=[f"EV-USER-{uid}"],
        ), f"investigate_endpoint@{uid}",
            reveal_indicators=["IND-C2"] if g["endpoint_malware"] else [])

    # late (attack-progression) evidence -------------------------------
    first_comp = compromised[0] if compromised else None
    if first_comp:
        cu = by_id[first_comp]
        catalog["EV-LATE-RULE"] = _evidence(
            "EV-LATE-RULE", f"Mail is being forwarded externally: {cu['name']}", "identity",
            "The attacker's inbox rule has started forwarding incoming mail to an external address.",
            fields=[("Account", cu["email"]), ("Rule", "Forward all mail to an external address"),
                    ("Created from", attacker_ip)],
            verdict="Ongoing data exfiltration through the mailbox rule.",
            source="Mailbox audit", entity=first_comp)
        catalog["EV-LATE-INTERNAL"] = _evidence(
            "EV-LATE-INTERNAL", "Internal phishing from compromised account", "email",
            f"The compromised account {cu['email']} sent the same lure to 14 colleagues.",
            verdict="The incident has spread inside the organisation.",
            source="Mail gateway", entity=first_comp)
    if infected:
        iu = by_id[infected[0]]
        catalog["EV-LATE-LATERAL"] = _evidence(
            "EV-LATE-LATERAL", f"Lateral movement attempt from {iu['endpoint']}", "endpoint",
            "SMB connection attempts to the file server were detected (blocked by policy).",
            fields=[("Source", iu["endpoint"]), ("Destination", "FILESRV-01")],
            verdict="Infected host is attempting to spread.", source="EDR", entity=infected[0])

    # ---- synthetic log dataset ---------------------------------------
    logs, log_seq = [], [0]

    def log(uid, source_, event, ts, ip, outcome, device, detail, crit=None, label=None):
        log_seq[0] += 1
        lid = f"LOG-{log_seq[0]:04d}"
        logs.append({
            "id": lid, "ts": _dt(ts), "source": source_, "user_id": uid,
            "user": label or (by_id[uid]["email"] if uid else "-"), "event_type": event,
            "src_ip": ip, "outcome": outcome, "device": device, "detail": detail,
            "crit": crit,
        })

    yesterday, today_am = now - timedelta(days=1), t_sent - timedelta(hours=2)
    for uid in user_ids:
        u, g = by_id[uid], truth[uid]
        corp = f"10.20.4.{rng.randint(10, 200)}"
        dev = f"Managed laptop ({u['endpoint']})"
        log(uid, "auth", "SignIn", yesterday.replace(hour=8, minute=52), corp, "success", dev, "Interactive sign-in, MFA approved")
        log(uid, "auth", "SignIn", yesterday.replace(hour=13, minute=5), corp, "failure", dev, "Incorrect password (user typo)")
        log(uid, "auth", "SignIn", today_am, corp, "success", dev, "Interactive sign-in, MFA approved")
        log(uid, "session", "SessionEstablished", today_am, corp, "success", dev, "Token issued, expires in 8h")
        log(uid, "mailbox", "MessageReceived", t_delivered, sender_ip, "success", "Exchange Online",
            f"From {sender_email}: {seed['email']['subject'][:70]}")
        log(uid, "endpoint", "ProcessStart", today_am, None, "success", u["endpoint"], "outlook.exe started by explorer.exe")
        if g["opened"]:
            log(uid, "mailbox", "MessageRead", t_open, corp, "success", dev, "Message opened in Outlook")
        if g["clicked"]:
            log(uid, "proxy", "HttpGet", t_click, corp, "allowed", u["endpoint"], f"GET {lure_url}",
                crit="Visit to the phishing page.")
            log(uid, "proxy", "HttpPost", t_submit, corp, "allowed", u["endpoint"],
                f"POST https://{lure_domain}/session (1.2 KB form submission)",
                crit="Credentials were submitted to the phishing site.")
        if g["compromised"]:
            if difficulty == "hard":
                log(uid, "auth", "MfaPrompt", t_login - timedelta(seconds=40), attacker_ip, "denied",
                    "Unknown browser", "Push notification denied (x2)")
            log(uid, "auth", "SignIn", t_login, attacker_ip, "success", "Unknown browser (new device)",
                "Sign-in from unfamiliar location, impossible travel",
                crit="Attacker signed in with the stolen credentials.")
            log(uid, "session", "SessionEstablished", t_login, attacker_ip, "success",
                "Unknown browser (new device)", "Token issued to unfamiliar device; session remains active",
                crit="A session is held by the attacker.")
            log(uid, "mailbox", "InboxRuleCreated", t_rule, attacker_ip, "success", "Exchange Online",
                "Rule 'sync' forwards all mail to an external address",
                crit="Persistence: a malicious forwarding rule exists.")
            log(uid, "mailbox", "MailItemsAccessed", t_rule + timedelta(minutes=1), attacker_ip, "success",
                "Exchange Online", "47 items accessed by unfamiliar client")
        if g["endpoint_malware"]:
            log(uid, "endpoint", "ProcessStart", t_open + timedelta(minutes=1), None, "success", u["endpoint"],
                f"WINWORD.EXE opened {attachment_obj['filename']} and ran a macro",
                crit="The macro executed on the endpoint.")
            log(uid, "endpoint", "ProcessStart", t_open + timedelta(minutes=1, seconds=4), None, "success",
                u["endpoint"], "powershell.exe -enc ... spawned by WINWORD.EXE",
                crit="Malicious child process.")
            log(uid, "proxy", "HttpsBeacon", t_open + timedelta(minutes=2), c2_ip, "allowed", u["endpoint"],
                f"Periodic HTTPS beacon to {c2_domain}", crit="Command-and-control beaconing.")
    noise_users = [("svc-backup@" + company_domain, "BKP-SRV-02"), ("j.doe@" + company_domain, "SAL-WS-017"),
                   ("m.okoye@" + company_domain, "OPS-WS-033"),
                   ("svc-legacy-print@" + company_domain, "PRN-SRV-01")]
    for _ in range(14):
        label, host = rng.choice(noise_users)
        ts = now - timedelta(minutes=rng.randint(5, 600))
        kind = rng.choice(["auth", "proxy", "endpoint"])
        internal = f"10.20.{rng.randint(1, 9)}.{rng.randint(10, 200)}"
        if kind == "auth":
            log(None, "auth", "SignIn", ts, internal, rng.choice(["success", "success", "failure"]),
                host, "Routine sign-in", label=label)
        elif kind == "proxy":
            log(None, "proxy", "HttpGet", ts, internal, "allowed", host,
                f"GET https://updates.{company_domain}/patch", label=label)
        else:
            log(None, "endpoint", "ProcessStart", ts, None, "success", host,
                "backup agent started", label=label)
    logs.sort(key=lambda r: r["ts"])
    crit_log_ids = []
    for r in logs:
        ev_id = f"EV-{r['id']}"
        catalog[ev_id] = _evidence(
            ev_id, f"Log record {r['id']}: {r['event_type']}", "log",
            f"{r['source']} log entry for {r['user']}.",
            fields=[("Time", r["ts"]), ("Source", r["source"]), ("User", r["user"]),
                    ("Event", r["event_type"]), ("Source IP", r["src_ip"] or "-"),
                    ("Outcome", r["outcome"]), ("Device", r["device"]), ("Detail", r["detail"])],
            verdict=r["crit"], source=f"{r['source']} log", entity=r["user_id"],
            related=[f"EV-AUTH-{r['user_id']}"] if r["user_id"] else [])
        evidence_map[f"collect_log@{r['id']}"] = [ev_id]
        if r["crit"]:
            crit_log_ids.append(ev_id)
    scenario_logs = {r["id"]: dict(r) for r in logs}

    # ---- alerts ------------------------------------------------------
    case_no = rng.randint(100, 999)
    n_decoys = {"easy": 2, "medium": 3, "hard": 4}[difficulty]
    decoys = rng.sample(_DECOY_ALERTS, n_decoys)
    alerts = []
    for k, d in enumerate(decoys):
        alerts.append({
            "id": f"ALR-{case_no}-{k + 2}", "title": d["title"], "severity": d["severity"],
            "confidence": d["confidence"], "source": d["source"], "rule": d["rule"],
            "entity": d["entity"].format(domain=company_domain),
            "detected_at": _dt(now - timedelta(minutes=rng.randint(3, 55))),
            "description": d["description"], "detail": d["detail"], "status": "new",
            "is_primary": False, "truth": d["truth"],
        })
    primary_alert = {
        "id": f"ALR-{case_no}-1", "title": f"Suspicious email delivered to {primary['department']}",
        "severity": "medium", "confidence": email["gateway"]["score"],
        "source": "Secure Email Gateway",
        "rule": "Phishing heuristics (display-name impersonation, newly seen sender)",
        "entity": primary["email"], "detected_at": _dt(t_alert),
        "description": (f"Email gateway flagged a suspicious message to {primary['name']} "
                        f"({primary['department']}) and delivered it with a warning."),
        "detail": ("The gateway scored the message as suspicious but delivered it with a banner. "
                   "Open the incident to inspect the message and its artifacts."),
        "status": "new", "is_primary": True, "truth": "investigate_now",
    }
    alerts.insert(rng.randint(0, len(alerts)), primary_alert)
    alert_truth = {a["id"]: a["truth"] for a in alerts}
    reveals[f"select_alert@{primary_alert['id']}"] = {"indicators": [], "users": [primary["id"]]}

    # ---- required response / evidence / events ----------------------
    required = [{"action": "quarantine_email", "target": uid, "category": "containment"}
                for uid in user_ids]
    required += [{"action": "block_indicator", "target": "IND-LURE-DOMAIN", "category": "containment"},
                 {"action": "block_indicator", "target": "IND-SENDER", "category": "containment"}]
    if compromised:
        required.append({"action": "block_indicator", "target": "IND-ATTACKER-IP", "category": "containment"})
    for uid in compromised:
        required += [
            {"action": "revoke_sessions", "target": uid, "category": "containment"},
            {"action": "remove_mailbox_rule", "target": uid, "category": "remediation"},
            {"action": "reset_account", "target": uid, "category": "remediation"},
            {"action": "enforce_mfa", "target": uid, "category": "remediation"},
        ]
    if infected:
        required.append({"action": "block_indicator", "target": "IND-C2", "category": "containment"})
    for uid in infected:
        required += [
            {"action": "isolate_endpoint", "target": uid, "category": "containment"},
            {"action": "endpoint_cleanup", "target": uid, "category": "remediation"},
            {"action": "reset_account", "target": uid, "category": "remediation"},
        ]

    critical = ["EV-EMAIL", "EV-HEADERS", "EV-FIELD-reply_to", "EV-FIELD-received",
                "EV-LINKTARGET-LINK-1", "EV-URL-LINK-1", "EV-SIEM-PROXY", "EV-SIEM-MAIL",
                "EV-IOC-IND-LURE-DOMAIN-domain_reputation", "EV-IOC-IND-SENDER-domain_reputation"]
    if attachment_obj:
        critical += ["EV-ATTACH", "EV-IOC-IND-ATTACH-HASH-hash_lookup"]
    if compromised:
        critical.append("EV-IOC-IND-ATTACKER-IP-ip_reputation")
    if infected:
        critical.append("EV-IOC-IND-C2-domain_reputation")
    for uid in user_ids:
        critical.append(f"EV-AUTH-{uid}")
        g = truth[uid]
        if g["opened"] or g["clicked"] or g["endpoint_malware"]:
            critical += [f"EV-USER-{uid}", f"EV-ENDPT-{uid}"]
    critical += crit_log_ids
    critical = [e for e in dict.fromkeys(critical) if e in catalog]

    required_preservation = ["EV-EMAIL", "EV-HEADERS"]
    required_preservation += [f"EV-AUTH-{u}" for u in compromised]
    required_preservation += [f"EV-ENDPT-{u}" for u in infected]
    destructive_guard = {}
    for uid in compromised:
        destructive_guard[f"remove_mailbox_rule@{uid}"] = [f"EV-AUTH-{uid}"]
    for uid in infected:
        destructive_guard[f"endpoint_cleanup@{uid}"] = [f"EV-ENDPT-{uid}"]

    kill_chain = [{"time": _t(t_sent),
                   "text": f"Attacker sends the lure from {sender_domain} to {len(user_ids)} recipient(s)."}]
    for uid in user_ids:
        g, u = truth[uid], by_id[uid]
        if g["opened"]:
            kill_chain.append({"time": _t(t_open), "text": f"{u['name']} opens the message."})
        if g["clicked"]:
            kill_chain.append({"time": _t(t_click), "text": f"{u['name']} clicks the link and reaches {lure_domain}."})
        if g["submitted"]:
            kill_chain.append({"time": _t(t_submit), "text": f"{u['name']} submits their credentials to the phishing page."})
        if g["compromised"]:
            kill_chain.append({"time": _t(t_login), "text": f"Attacker signs in as {u['name']} from {attacker_ip}."})
            kill_chain.append({"time": _t(t_rule), "text": f"Attacker creates a mailbox rule forwarding {u['name']}'s mail externally."})
        if g["endpoint_malware"]:
            kill_chain.append({"time": _t(t_open + timedelta(minutes=1)),
                               "text": f"{u['name']} runs the macro; {u['endpoint']} starts beaconing to {c2_domain}."})
        if not (g["opened"] or g["clicked"]):
            kill_chain.append({"time": _t(t_delivered), "text": f"{u['name']} never interacts with the message."})

    speed = 1 if difficulty == "hard" else 0
    events = []
    if not (compromised or infected):
        events.append({
            "id": "EVT-OPENED", "trigger_tick": 11 - speed,
            "unless": [f"done:quarantine_email@{primary['id']}"],
            "message": "Mailbox audit: the message is still in the inbox and was viewed again by the recipient.",
            "impact": 1, "penalty": 20, "evidence_id": None})
    if first_comp:
        events.append({
            "id": "EVT-RULE", "trigger_tick": 12 - speed,
            "unless": [f"done:remove_mailbox_rule@{first_comp}"],
            "message": "ALERT: mail is being forwarded to an external address through an inbox rule on the compromised mailbox.",
            "impact": 1, "penalty": 30, "evidence_id": "EV-LATE-RULE"})
        events.append({
            "id": "EVT-INTERNAL", "trigger_tick": 17 - speed,
            "unless": [f"done:reset_account@{first_comp}"],
            "message": "ALERT: the compromised account sent internal phishing to 14 colleagues.",
            "impact": 1, "penalty": 50, "evidence_id": "EV-LATE-INTERNAL"})
    if infected:
        events.append({
            "id": "EVT-LATERAL", "trigger_tick": 13 - speed,
            "unless": [f"done:isolate_endpoint@{infected[0]}"],
            "message": f"EDR: lateral-movement attempt from {by_id[infected[0]]['endpoint']} to FILESRV-01 (blocked by policy).",
            "impact": 1, "penalty": 40, "evidence_id": "EV-LATE-LATERAL"})

    # ---- action availability ---------------------------------------
    allowed = list(KNOWN_ACTIONS)
    if not attachment_obj:
        allowed.remove("inspect_attachment")
    if not infected and archetype in ("no_compromise", "blocked_campaign", "spoofed_internal"):
        allowed.remove("isolate_endpoint")
    if not infected:
        allowed.remove("endpoint_cleanup")
    pid = primary_alert["id"]
    prerequisites = {
        "triage_alert": ["done:select_alert@target"],
        "open_email": [f"done:select_alert@{pid}"],
        "view_raw_headers": ["done:open_email"],
        "inspect_header_field": ["done:open_email"],
        "reveal_link": ["done:open_email"],
        "analyze_headers": ["done:open_email"],
        "inspect_url": ["done:open_email"],
        "inspect_attachment": ["done:open_email", "has_attachment"],
        "ioc_lookup": ["indicator_known"],
        "search_siem:proxy_dns": ["done:inspect_url"],
        "search_siem:mail_delivery": ["done:open_email"],
        "analyze_auth_logs": ["known_user"],
        "investigate_user": ["known_user"],
        "investigate_endpoint": ["known_user"],
        "set_assessment": ["done:open_email"],
        "preserve_evidence": ["evidence_discovered"],
        "quarantine_email": ["done:open_email", "known_user"],
        "block_indicator": ["indicator_known"],
        "revoke_sessions": ["done:analyze_auth_logs@target"],
        "reset_account": ["done:analyze_auth_logs@target"],
        "enforce_mfa": ["done:analyze_auth_logs@target"],
        "remove_mailbox_rule": ["done:analyze_auth_logs@target"],
        "isolate_endpoint": ["done:investigate_endpoint@target"],
        "endpoint_cleanup": ["done:isolate_endpoint@target"],
        "verify_containment": ["any_response"],
        "verify_remediation": ["any_response"],
        "close_incident": ["done:verify_containment", "done:verify_remediation"],
    }
    transitions = [
        {"action": "quarantine_email", "scope": "user", "set": {"mailbox": "quarantined"}},
        {"action": "revoke_sessions", "scope": "user", "set": {"session": "revoked"}},
        {"action": "reset_account", "scope": "user", "set": {"account": "reset", "session": "revoked"}},
        {"action": "enforce_mfa", "scope": "user", "set": {"mfa": "enforced"}},
        {"action": "remove_mailbox_rule", "scope": "user", "set": {"mailbox_rule": "removed"}},
        {"action": "isolate_endpoint", "scope": "user", "set": {"endpoint": "isolated"}},
        {"action": "endpoint_cleanup", "scope": "user", "set": {"endpoint": "cleaned"}},
        {"action": "block_indicator", "scope": "indicator", "set": {"blocked": True}},
    ]

    scenario = {
        "scenario_id": scenario_id,
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "incident_id": f"PHISH-{now.year}-{case_no}",
        "title": seed["title"],
        "difficulty": difficulty,
        "severity": true_severity,
        "incident_type": incident_type,
        "archetype": archetype,
        "company": {"name": seed["company"]["name"], "domain": company_domain},
        "target": {"primary_user_id": primary["id"], "users": users},
        "email": email,
        "alert": {
            "detected_at": _dt(t_alert),
            "reported_severity": "medium",
            "summary": primary_alert["description"],
        },
        "alerts": alerts,
        "logs": scenario_logs,
        "indicators": indicators,
        "evidence_catalog": catalog,
        "evidence_map": evidence_map,
        "reveals": reveals,
        "simulated_events": events,
        "destructive_guard": destructive_guard,
        "attack_objective": seed["attacker_objective"],
        "ground_truth": {
            "malicious": True,
            "classification": classification,
            "true_severity": true_severity,
            "root_cause": root_cause,
            "users": truth,
            "affected_users": affected,
            "affected_assets": [by_id[u]["endpoint"] for u in infected],
            "alert_truth": alert_truth,
            "malicious_indicator_ids": malicious_ids,
            "critical_evidence": critical,
            "required_response": required,
            "required_preservation": required_preservation,
            "kill_chain": kill_chain,
        },
        "initial_state": {"known_users": []},
        "allowed_actions": allowed,
        "action_prerequisites": prerequisites,
        "possible_transitions": transitions,
        "success_conditions": {"all_required_response_complete": True, "incident_closed": True},
        "failure_conditions": [
            {"id": "closed_with_active_threat",
             "description": "Incident closed while required containment or remediation was incomplete."},
            {"id": "attack_escalated", "impact_at_least": 3,
             "description": "The attacker progressed three or more times unopposed."},
        ],
    }
    return validate_scenario(scenario)

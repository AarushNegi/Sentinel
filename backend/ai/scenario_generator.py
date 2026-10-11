"""Local-model (Ollama) scenario generation for the Blue Team phishing
simulation.

The model only writes *narrative content* (names, email wording, attachment
file name). It never decides what is true in the simulation: the composer
derives indicators, ground truth, evidence and rules deterministically, and
every model reply is validated before use. If Ollama is unreachable, slow or
returns anything unacceptable, a validated built-in template is used instead
and the fallback is recorded in the returned metadata.

All traffic to Ollama happens here, on the server. The browser never talks to
the model.
"""

import json
import os
import random
import re
import time

import requests

from blue_phishing.composer import compose_scenario
from blue_phishing.scenario_schema import (
    ARCHETYPES,
    ATTACHMENT_KINDS,
    DIFFICULTIES,
    ScenarioValidationError,
    validate_seed,
    victim_count_for,
)
from blue_phishing.templates import build_template_scenario

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3:4b"
DEFAULT_TIMEOUT = 60.0
MAX_RESPONSE_CHARS = 20000

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class ModelError(Exception):
    """The model could not produce a usable reply (carries a short reason code)."""

    def __init__(self, reason, detail=""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


# ------------------------------------------------------------------
#  Configuration (read per call so it can be changed without restart)
# ------------------------------------------------------------------

def config():
    try:
        timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", DEFAULT_TIMEOUT))
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    return {
        "base_url": os.getenv("OLLAMA_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
        "model": os.getenv("OLLAMA_MODEL", DEFAULT_MODEL),
        "timeout": max(1.0, timeout),
        "enabled": os.getenv("BLUE_PHISHING_AI_ENABLED", "true").strip().lower()
        not in ("0", "false", "no", "off"),
        "keep_alive": os.getenv("OLLAMA_KEEP_ALIVE", "30m"),
    }


def ollama_status(http=requests):
    """Report whether the local model is reachable and installed."""
    cfg = config()
    status = {"base_url": cfg["base_url"], "model": cfg["model"],
              "enabled": cfg["enabled"], "reachable": False, "model_installed": False}
    if not cfg["enabled"]:
        status["error"] = "AI generation disabled by configuration."
        return status
    try:
        resp = http.get(f"{cfg['base_url']}/api/tags", timeout=min(5.0, cfg["timeout"]))
        resp.raise_for_status()
        names = [m.get("name", "") for m in resp.json().get("models", [])]
        status["reachable"] = True
        wanted = cfg["model"]
        status["model_installed"] = wanted in names or (
            ":" not in wanted and f"{wanted}:latest" in names)
        if not status["model_installed"]:
            status["error"] = f"Model '{wanted}' is not installed. Run: ollama pull {wanted}"
    except Exception:  # noqa: BLE001 - any failure just means "not available"
        status["error"] = "Ollama is not reachable."
    return status


def warm_up(http=requests):
    """Load the model into memory so the first real request is not a cold start.

    Safe to call at any time: failures are ignored (generation will simply
    fall back to templates until Ollama is available). Returns True on success.
    """
    cfg = config()
    if not cfg["enabled"]:
        return False
    try:
        resp = http.post(
            f"{cfg['base_url']}/api/generate",
            json={"model": cfg["model"], "prompt": "", "keep_alive": cfg["keep_alive"], "stream": False},
            timeout=300,
        )
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


def warm_up_in_background(http=requests):
    """Fire-and-forget warm-up that never blocks or breaks server start-up."""
    import threading

    thread = threading.Thread(target=warm_up, args=(http,), daemon=True, name="ollama-warmup")
    thread.start()
    return thread


# ------------------------------------------------------------------
#  Prompt + JSON schema
# ------------------------------------------------------------------

def seed_json_schema(archetype, difficulty):
    n_victims = victim_count_for(archetype)
    text = lambda lo, hi: {"type": "string", "minLength": lo, "maxLength": hi}  # noqa: E731
    return {
        "type": "object",
        "required": ["title", "archetype", "difficulty", "company", "victims",
                     "impersonated_brand", "sender_display_name", "email",
                     "attachment", "attacker_objective"],
        "properties": {
            "title": text(5, 80),
            "archetype": {"type": "string", "enum": [archetype]},
            "difficulty": {"type": "string", "enum": [difficulty]},
            "company": {"type": "object", "required": ["name"],
                        "properties": {"name": text(2, 40)}},
            "victims": {
                "type": "array", "minItems": n_victims, "maxItems": n_victims,
                "items": {"type": "object",
                          "required": ["first_name", "last_name", "role", "department"],
                          "properties": {"first_name": text(2, 30), "last_name": text(2, 30),
                                         "role": text(2, 50), "department": text(2, 40)}},
            },
            "impersonated_brand": text(2, 40),
            "sender_display_name": text(2, 50),
            "email": {
                "type": "object",
                "required": ["subject", "paragraphs", "cta_label", "signature"],
                "properties": {
                    "subject": text(5, 120),
                    "paragraphs": {"type": "array", "minItems": 2, "maxItems": 4,
                                   "items": text(10, 400)},
                    "cta_label": text(3, 40),
                    "signature": text(2, 60),
                },
            },
            "attachment": {
                "anyOf": [
                    {"type": "null"},
                    {"type": "object", "required": ["filename", "kind"],
                     "properties": {"filename": text(3, 60),
                                    "kind": {"type": "string", "enum": list(ATTACHMENT_KINDS)}}},
                ]
            },
            "attacker_objective": text(10, 240),
        },
    }


_ARCH_BRIEF = {
    "no_compromise": ("a phishing email that reached ONE employee's inbox; the employee "
                      "did not click anything. Attachment is optional."),
    "blocked_campaign": ("a phishing campaign sent to THREE employees in different departments "
                         "where nobody interacts with it. No attachment needed."),
    "spoofed_internal": ("an email that impersonates a senior executive of the employee's own "
                         "company and pressures ONE employee into an urgent confidential payment. "
                         "No attachment needed. sender_display_name must be the executive's name and title."),
    "credential_compromise": ("a credential-harvesting phishing email sent to ONE employee "
                              "who then enters their password on a fake sign-in page. No attachment needed."),
    "malicious_attachment": ("an email to ONE employee with a macro-enabled Word attachment "
                             "(kind \"docm\", file name ending in .docm) that the employee opens."),
    "multi_user_campaign": ("a phishing campaign against THREE employees in different "
                            "departments. The email must have a macro-enabled Word attachment "
                            "(kind \"docm\", file name ending in .docm)."),
}
_THEMES = {
    "no_compromise": [
        "an overdue GST invoice from an office-supplies vendor",
        "a fake bank KYC update warning for the company's current account",
        "a fake electricity bill disconnection notice for the office",
        "a fake scholarship or fee-payment notice sent to a college accounts clerk",
        "a fake internship or job offer asking for a registration fee",
    ],
    "blocked_campaign": [
        "a fake courier parcel on hold that needs a customs fee paid by UPI",
        "a fake postal delivery address-verification notice",
        "a fake electricity bill disconnection warning",
        "a fake UPI cashback or refund notice",
        "a fake examination timetable change sent to college staff",
    ],
    "spoofed_internal": [
        "an urgent confidential NEFT or RTGS transfer request from the CFO",
        "a managing director asking an employee to buy gift vouchers urgently",
        "a vendor bank-account change request claimed to be approved by a director",
    ],
    "credential_compromise": [
        "a fake salary or payroll portal re-verification",
        "a fake bank KYC update for the corporate banking portal",
        "a fake provident-fund or HR benefits portal login",
        "a fake university portal notice that needs a staff sign-in",
        "a fake employee onboarding portal",
    ],
    "malicious_attachment": [
        "a GST statement or e-way bill sent as a macro-enabled Word file",
        "a fake purchase order from a customer",
        "a fake salary revision letter",
        "a fake audit schedule document",
    ],
    "multi_user_campaign": [
        "a revised freight invoice and e-way bill attachment",
        "a fake government-style tender document",
        "a fake purchase order from a large customer",
    ],
}
_DIFFICULTY_BRIEF = {
    "easy": "The lure is fairly obvious (urgent tone, generic greeting).",
    "medium": "The lure is plausible and professionally written.",
    "hard": "The lure is highly convincing, personalised and calm in tone.",
}


def build_messages(archetype, difficulty):
    from blue_phishing.templates import get_template_seed

    system = (
        "You write fictional content for a cybersecurity TRAINING simulation for "
        "Indian college students. Create a realistic INDIAN-CONTEXT incident: use "
        "familiar Indian situations and institutions (UPI payments, bank KYC, "
        "courier and parcel delivery, college fees and examination notices, "
        "internships, GST invoices, e-way bills, NEFT/RTGS transfers, salary and "
        "provident-fund portals), plausible invented Indian names, cities, "
        "colleges and companies, and amounts in rupees written as Rs (for example "
        "Rs 1,250 or Rs 4,75,000). Keep it understandable for someone with basic "
        "cybersecurity knowledge. Reply with ONE JSON object only, matching the "
        "supplied schema exactly. Use only invented people, companies and vendors; "
        "prefer fictional bank, courier and college names. Never include URLs, "
        "e-mail addresses, phone numbers, HTML, markdown, square brackets or "
        "placeholders like [Click here]; the simulation adds all web and e-mail "
        "addresses and the greeting itself. Keep it realistic but harmless: no "
        "working instructions, no real payment details, no real brands."
    )
    example = get_template_seed(archetype)
    theme = random.choice(_THEMES[archetype])
    user = (
        f"Create a phishing training incident: {_ARCH_BRIEF[archetype]} "
        f"Theme for this incident (keep it fictional and Indian in context): {theme}. "
        f"{_DIFFICULTY_BRIEF[difficulty]} "
        f'Set "archetype" to "{archetype}" and "difficulty" to "{difficulty}". '
        'The "email.paragraphs" are the body lines of the lure email (2 to 4 short '
        "paragraphs, WITHOUT any greeting such as Hello/Dear and WITHOUT a signature). "
        '"cta_label" is the 2-4 word text of the button, e.g. "Review invoice". '
        '"impersonated_brand" is an invented vendor or service the attacker pretends to be. '
        '"attacker_objective" is one sentence about what the ATTACKER wants. '
        f"Use {victim_count_for(archetype)} victim(s) with realistic names, roles and departments. "
        "Invent different names, companies and wording from this example "
        "(it only shows the format and the Indian style): " + json.dumps(example)
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


# ------------------------------------------------------------------
#  Cleaning of model prose (cosmetic only; validation still decides)
# ------------------------------------------------------------------

_NAME = r"(?:[A-Z][\w\'’-]*|team|all|everyone|there|colleagues?)"
_GREETING_RE = re.compile(
    r"^\s*(?i:hello|hi|dear|greetings)\b(?:[ ,]+(?:and\s+)?" + _NAME + r"){0,5}\s*[,:]\s*"
)
_BRACKET_RE = re.compile(r"\[[^\]]{0,60}\]|\{[^}]{0,60}\}")
_DEFAULT_OBJECTIVE = {
    "no_compromise": "Trick the recipient into paying a fake invoice or entering portal credentials.",
    "blocked_campaign": "Collect UPI and card details from several employees through a fake delivery-fee page.",
    "spoofed_internal": "Pressure a finance employee into authorising a fraudulent NEFT or RTGS transfer.",
    "credential_compromise": "Steal the employee's corporate credentials to access mailbox and finance systems.",
    "malicious_attachment": "Run a macro downloader on a workstation to gain a foothold on the network.",
    "multi_user_campaign": "Gain footholds on several workstations and harvest credentials for payment fraud.",
}


def tidy_seed(raw, archetype):
    """Remove artefacts small models commonly produce. Never adds new content
    other than the fixed default objective."""
    if not isinstance(raw, dict):
        return raw
    seed = dict(raw)
    email = seed.get("email")
    if isinstance(email, dict):
        email = dict(email)
        paragraphs = email.get("paragraphs")
        if isinstance(paragraphs, list):
            cleaned = []
            for i, p in enumerate(paragraphs):
                if not isinstance(p, str):
                    cleaned.append(p)
                    continue
                if i == 0:
                    p = _GREETING_RE.sub("", p)
                p = re.sub(r"\s+", " ", _BRACKET_RE.sub("", p)).strip()
                p = re.sub(r"\s*:\s*$", ".", p)
                p = p[:1].upper() + p[1:]
                if len(p) >= 10:
                    cleaned.append(p)
            email["paragraphs"] = cleaned[:4]
        for key in ("signature", "cta_label", "subject"):
            val = email.get(key)
            if isinstance(val, str):
                val = _BRACKET_RE.sub("", val).strip()
                if key == "signature" and len(val) > 60:
                    val = val[:60].rsplit(" ", 1)[0]
                email[key] = val
        seed["email"] = email
    objective = seed.get("attacker_objective")
    if not isinstance(objective, str) or len(objective.strip()) < 30:
        seed["attacker_objective"] = _DEFAULT_OBJECTIVE[archetype]
    return seed


# ------------------------------------------------------------------
#  Model call + parsing
# ------------------------------------------------------------------

def _extract_json(text):
    text = _THINK_RE.sub("", text or "").strip()
    if len(text) > MAX_RESPONSE_CHARS:
        raise ModelError("invalid_output", "model reply too long")
    try:
        return json.loads(text)
    except ValueError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ModelError("invalid_output", "no JSON object in model reply")
    try:
        return json.loads(text[start:end + 1])
    except ValueError as exc:
        raise ModelError("invalid_output", "model reply is not valid JSON") from exc


def call_ollama_json(messages, schema, *, timeout, http=requests):
    """POST to Ollama's /api/chat with a JSON-schema constrained reply."""
    cfg = config()
    payload = {
        "model": cfg["model"],
        "messages": messages,
        "stream": False,
        "think": False,
        "format": schema,
        "keep_alive": cfg["keep_alive"],
        "options": {"temperature": 0.8, "num_predict": 1100},
    }
    try:
        resp = http.post(f"{cfg['base_url']}/api/chat", json=payload, timeout=timeout)
    except requests.exceptions.Timeout as exc:
        raise ModelError("timeout", "Ollama did not answer in time") from exc
    except requests.exceptions.RequestException as exc:
        raise ModelError("ollama_unavailable", "Ollama is not reachable") from exc
    if resp.status_code == 404:
        raise ModelError("model_missing", f"Model '{cfg['model']}' is not installed")
    if resp.status_code != 200:
        raise ModelError("ollama_error", f"Ollama returned HTTP {resp.status_code}")
    try:
        body = resp.json()
        content = body["message"]["content"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ModelError("invalid_output", "unexpected Ollama response shape") from exc
    return _extract_json(content)


# ------------------------------------------------------------------
#  Public API
# ------------------------------------------------------------------

def generate_scenario(*, preferred_archetype=None, use_ai=True, rng=None, now=None,
                      http=requests, clock=time.monotonic):
    """Return ``(scenario, meta)``.

    ``meta`` records how the scenario was produced:
    ``source`` ("ollama" | "template"), ``model``, ``fallback`` (bool),
    ``fallback_reason`` and ``duration_ms``.
    """
    rng = rng or random.Random()
    cfg = config()
    archetype = preferred_archetype if preferred_archetype in ARCHETYPES else rng.choice(ARCHETYPES)
    difficulty = rng.choice(DIFFICULTIES)
    started = clock()
    meta = {"source": "template", "model": None, "fallback": False,
            "fallback_reason": None, "duration_ms": 0, "archetype": archetype}

    def finish(scenario):
        meta["duration_ms"] = int((clock() - started) * 1000)
        return scenario, meta

    def fallback(reason):
        meta.update(source="template", model=None, fallback=True, fallback_reason=reason)
        return finish(build_template_scenario(archetype, rng=rng, now=now))

    if not use_ai:
        meta["fallback_reason"] = "template_requested"
        return finish(build_template_scenario(archetype, rng=rng, now=now))
    if not cfg["enabled"]:
        return fallback("ai_disabled")

    schema = seed_json_schema(archetype, difficulty)
    messages = build_messages(archetype, difficulty)
    deadline = started + cfg["timeout"]
    reason = "invalid_output"
    for _attempt in range(2):
        remaining = deadline - clock()
        if remaining < 2:
            reason = "timeout"
            break
        try:
            raw = call_ollama_json(messages, schema, timeout=remaining, http=http)
            if isinstance(raw, dict):
                raw = tidy_seed({**raw, "archetype": archetype, "difficulty": difficulty}, archetype)
            seed = validate_seed(raw, expected_archetype=archetype,
                                 expected_difficulty=difficulty)
            scenario = compose_scenario(seed, source="ollama", now=now)
        except ModelError as exc:
            reason = exc.reason
            if reason in ("ollama_unavailable", "model_missing", "timeout", "ollama_error"):
                break  # retrying cannot help
            continue
        except ScenarioValidationError:
            reason = "validation_failed"
            continue
        meta.update(source="ollama", model=cfg["model"])
        return finish(scenario)
    return fallback(reason)


def generate_debrief(report_facts, *, http=requests, timeout=20.0):
    """Optional short AI commentary for the final report.

    Returns a validated plain-text string, or None. The report itself never
    depends on this: scores, timeline and findings come from the engine.
    """
    cfg = config()
    if not cfg["enabled"]:
        return None
    schema = {"type": "object", "required": ["commentary"],
              "properties": {"commentary": {"type": "string", "minLength": 20, "maxLength": 600}}}
    messages = [
        {"role": "system", "content": (
            "You are a SOC mentor giving brief, encouraging feedback on a TRAINING "
            "exercise. Reply with one JSON object. Use only the facts provided. "
            "No URLs, no markdown.")},
        {"role": "user", "content": "Facts:\n" + json.dumps(report_facts)[:3000] +
         "\nWrite 2-3 sentences of feedback."},
    ]
    try:
        data = call_ollama_json(messages, schema, timeout=timeout, http=http)
        from blue_phishing.scenario_schema import clean_text
        return clean_text(data.get("commentary"), "commentary", min_len=20, max_len=600)
    except (ModelError, ScenarioValidationError, AttributeError):
        return None


def generate_hint(context, level, *, http=requests, timeout=7.0):
    """One short, optional coaching hint for the current investigation step.

    `context` is built by the server from the analyst-visible view only
    (never the scenario or ground truth), so a hint cannot mention a clue the
    student has not found. Returns validated plain text, or None so callers
    can use their built-in hint.
    """
    cfg = config()
    if not cfg["enabled"]:
        return None
    level = level if level in (1, 2, 3) else 1
    guidance = {
        1: "Point to WHERE to look (which part of the screen) without saying what it shows.",
        2: "Say what KIND of pattern to look for, without stating the answer.",
        3: "Explain WHY the pattern matters for the decision, still without stating the verdict.",
    }[level]
    schema = {"type": "object", "required": ["hint"],
              "properties": {"hint": {"type": "string", "minLength": 15, "maxLength": 240}}}
    messages = [
        {"role": "system", "content": (
            "You are a friendly SOC mentor for a beginner in a TRAINING simulation. "
            "Reply with one JSON object. Give ONE or TWO short sentences. Use only the facts "
            "provided; never guess hidden facts, never state whether the email is malicious. "
            "Do not write URLs, email addresses, domains or markdown. " + guidance)},
        {"role": "user", "content": "Facts the student can already see:\n" + json.dumps(context)[:2500]},
    ]
    try:
        data = call_ollama_json(messages, schema, timeout=timeout, http=http)
        from blue_phishing.scenario_schema import clean_text
        return clean_text(data.get("hint"), "hint", min_len=15, max_len=240)
    except (ModelError, ScenarioValidationError, AttributeError):
        return None

"""Scenario schema, seed validation, Ollama adapter and fallback behaviour."""
import copy
import json
import random

import pytest
import requests

from ai import scenario_generator as gen
from blue_phishing import scenario_schema as schema
from blue_phishing.composer import compose_scenario
from blue_phishing.templates import get_template_seed, template_archetypes


def good_seed(archetype="credential_compromise"):
    return get_template_seed(archetype)


class FakeResponse:
    def __init__(self, status=200, payload=None, text=None):
        self.status_code = status
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(str(self.status_code))


class FakeHttp:
    """Stands in for the ``requests`` module."""

    def __init__(self, reply=None, exc=None, status=200):
        self.reply, self.exc, self.status = reply, exc, status
        self.calls = []

    def post(self, url, json=None, timeout=None):
        self.calls.append((url, json, timeout))
        if self.exc:
            raise self.exc
        content = self.reply if isinstance(self.reply, str) else __import__("json").dumps(self.reply)
        return FakeResponse(self.status, {"message": {"content": content}})

    def get(self, url, timeout=None):
        if self.exc:
            raise self.exc
        return FakeResponse(200, {"models": [{"name": "qwen3:4b"}]})


# ---------------------------------------------------------------- templates

@pytest.mark.parametrize("archetype", template_archetypes())
def test_all_templates_validate(archetype):
    seed = schema.validate_seed(good_seed(archetype))
    scenario = compose_scenario(seed, source="template")
    schema.validate_scenario(scenario)
    assert scenario["archetype"] == archetype
    assert scenario["ground_truth"]["required_response"]


def test_scenarios_use_reserved_domains_and_documentation_ips(scenario):
    for ind in scenario["indicators"]:
        if ind["type"] in ("domain", "sender_domain"):
            assert schema.is_reserved_domain(ind["value"])
        if ind["type"] == "ip":
            assert schema.is_safe_ip(ind["value"])
    assert schema.is_reserved_domain(scenario["email"]["sender_email"].split("@")[1])


def test_scenarios_differ_per_template():
    ids = {a: compose_scenario(schema.validate_seed(good_seed(a))) for a in template_archetypes()}
    assert ids["no_compromise"]["ground_truth"]["classification"] == "phishing_no_compromise"
    assert ids["credential_compromise"]["ground_truth"]["classification"] == "credential_compromise"
    assert len(ids["multi_user_campaign"]["target"]["users"]) == 3


# ---------------------------------------------------------------- seed validation

@pytest.mark.parametrize("mutate,fragment", [
    (lambda s: s.pop("title"), "missing"),
    (lambda s: s.update(difficulty="impossible"), "difficulty"),
    (lambda s: s.update(archetype="ransomware"), "archetype"),
    (lambda s: s["email"].update(subject="x" * 500), "too long"),
    (lambda s: s["email"].update(subject="Click http://evil.test now"), "URL"),
    (lambda s: s["email"]["paragraphs"].__setitem__(0, "Mail me at a@b.test please"), "URL"),
    (lambda s: s["email"].update(paragraphs=["only one paragraph here"]), "paragraphs"),
    (lambda s: s["victims"][0].update(first_name="<script>"), "markup"),
    (lambda s: s["victims"][0].update(first_name="R2D2!!"), "invalid"),
    (lambda s: s.update(victims=[]), "victim"),
    (lambda s: s.update(attachment={"filename": "../../etc/passwd", "kind": "zip"}), "safe file name"),
    (lambda s: s.update(attachment={"filename": "invoice.exe", "kind": "exe"}), "attachment.kind"),
    (lambda s: s.update(attachment={"filename": "invoice.pdf", "kind": "zip"}), "extension"),
])
def test_invalid_seed_is_rejected(mutate, fragment):
    seed = good_seed("credential_compromise")
    mutate(seed)
    with pytest.raises(schema.ScenarioValidationError) as exc:
        schema.validate_seed(seed)
    assert fragment.lower() in str(exc.value).lower()


def test_campaign_requires_three_victims():
    seed = good_seed("multi_user_campaign")
    seed["victims"] = seed["victims"][:2]
    with pytest.raises(schema.ScenarioValidationError):
        schema.validate_seed(seed)


# ---------------------------------------------------------------- scenario consistency

def _mutated(scenario, fn):
    s = copy.deepcopy(scenario)
    fn(s)
    return s


def test_inconsistent_ground_truth_is_rejected():
    s = compose_scenario(schema.validate_seed(good_seed("no_compromise")))
    bad = _mutated(s, lambda x: x["ground_truth"]["users"]["u1"].update(compromised=True))
    with pytest.raises(schema.ScenarioValidationError):
        schema.validate_scenario(bad)


def test_session_without_compromise_is_rejected():
    s = compose_scenario(schema.validate_seed(good_seed("credential_compromise")))
    bad = _mutated(s, lambda x: x["ground_truth"]["users"]["u1"].update(compromised=False))
    with pytest.raises(schema.ScenarioValidationError):
        schema.validate_scenario(bad)


def test_classification_must_match_impact():
    s = compose_scenario(schema.validate_seed(good_seed("credential_compromise")))
    bad = _mutated(s, lambda x: x["ground_truth"].update(classification="phishing_no_compromise"))
    with pytest.raises(schema.ScenarioValidationError):
        schema.validate_scenario(bad)


def test_unknown_critical_evidence_is_rejected():
    s = compose_scenario(schema.validate_seed(good_seed("credential_compromise")))
    bad = _mutated(s, lambda x: x["ground_truth"]["critical_evidence"].append("EV-NOPE"))
    with pytest.raises(schema.ScenarioValidationError):
        schema.validate_scenario(bad)


def test_real_domain_is_rejected():
    s = compose_scenario(schema.validate_seed(good_seed("credential_compromise")))
    bad = _mutated(s, lambda x: x["indicators"][0].update(value="microsoft.com"))
    with pytest.raises(schema.ScenarioValidationError):
        schema.validate_scenario(bad)


def test_overlong_field_is_rejected():
    s = compose_scenario(schema.validate_seed(good_seed("credential_compromise")))
    bad = _mutated(s, lambda x: x.update(attack_objective="y" * 5000))
    with pytest.raises(schema.ScenarioValidationError):
        schema.validate_scenario(bad)


# ---------------------------------------------------------------- Ollama adapter

def _ai_seed(archetype="credential_compromise", difficulty="medium"):
    seed = good_seed(archetype)
    seed["difficulty"] = difficulty
    return seed


def _run(http, archetype="credential_compromise", **kw):
    return gen.generate_scenario(preferred_archetype=archetype, rng=random.Random(7),
                                 http=http, **kw)


def test_valid_model_output_is_used(monkeypatch):
    # Pin the difficulty the generator will ask for.
    rng = random.Random(7)
    rng.choice(gen.ARCHETYPES) if False else None
    http = FakeHttp()

    def reply_for_any(url, json=None, timeout=None):
        wanted = json["format"]["properties"]["difficulty"]["enum"][0]
        http.calls.append(json)
        return FakeResponse(200, {"message": {"content": __import__("json").dumps(
            _ai_seed("credential_compromise", wanted))}})

    http.post = reply_for_any
    scenario, meta = _run(http)
    assert meta["source"] == "ollama" and meta["fallback"] is False
    assert meta["model"] == "qwen3:4b"
    schema.validate_scenario(scenario)
    # constrained structured output was requested, with thinking off
    assert http.calls[0]["think"] is False and isinstance(http.calls[0]["format"], dict)


def test_model_cannot_change_requested_archetype():
    seed = _ai_seed("no_compromise", "easy")
    seed["archetype"] = "multi_user_campaign"
    http = FakeHttp(reply=seed)
    scenario, meta = _run(http, archetype="credential_compromise")
    # archetype is forced to the requested one, so the 1-victim seed is fine
    assert scenario["archetype"] == "credential_compromise" or meta["fallback"]


@pytest.mark.parametrize("reply", [
    "this is not json at all",
    "{broken json",
    json.dumps({"title": "only a title"}),
    json.dumps([1, 2, 3]),
])
def test_malformed_model_output_falls_back(reply):
    scenario, meta = _run(FakeHttp(reply=reply))
    assert meta["fallback"] is True and meta["source"] == "template"
    assert meta["fallback_reason"] in ("invalid_output", "validation_failed")
    schema.validate_scenario(scenario)


def test_model_output_with_url_falls_back():
    seed = _ai_seed()
    seed["email"]["paragraphs"][0] = "Visit https://real-bank.com to continue your session."
    scenario, meta = _run(FakeHttp(reply=seed))
    assert meta["fallback"] is True and meta["fallback_reason"] == "validation_failed"


def test_overlong_model_output_falls_back():
    seed = _ai_seed()
    seed["email"]["subject"] = "S" * 900
    scenario, meta = _run(FakeHttp(reply=seed))
    assert meta["fallback"] is True


def test_think_block_is_stripped():
    http = FakeHttp()

    def post(url, json=None, timeout=None):
        wanted = json["format"]["properties"]["difficulty"]["enum"][0]
        body = "<think>planning...</think>" + __import__("json").dumps(
            _ai_seed("credential_compromise", wanted))
        return FakeResponse(200, {"message": {"content": body}})

    http.post = post
    _, meta = _run(http)
    assert meta["source"] == "ollama"


def test_timeout_falls_back():
    http = FakeHttp(exc=requests.exceptions.Timeout())
    scenario, meta = _run(http)
    assert meta["fallback"] and meta["fallback_reason"] == "timeout"


def test_ollama_unavailable_falls_back():
    http = FakeHttp(exc=requests.exceptions.ConnectionError())
    scenario, meta = _run(http)
    assert meta["fallback"] and meta["fallback_reason"] == "ollama_unavailable"
    schema.validate_scenario(scenario)


def test_missing_model_falls_back():
    scenario, meta = _run(FakeHttp(status=404))
    assert meta["fallback"] and meta["fallback_reason"] == "model_missing"


def test_template_requested_is_not_a_fallback():
    http = FakeHttp(exc=AssertionError("must not be called"))
    scenario, meta = _run(http, use_ai=False)
    assert meta["source"] == "template" and meta["fallback"] is False
    assert http.calls == []


def test_ai_can_be_disabled(monkeypatch):
    monkeypatch.setenv("BLUE_PHISHING_AI_ENABLED", "false")
    scenario, meta = _run(FakeHttp(exc=AssertionError("must not be called")))
    assert meta["fallback"] and meta["fallback_reason"] == "ai_disabled"


def test_generation_is_bounded_by_timeout(monkeypatch):
    monkeypatch.setenv("OLLAMA_TIMEOUT_SECONDS", "3")
    ticks = iter([0.0, 0.1, 100.0, 200.0, 300.0])
    scenario, meta = gen.generate_scenario(
        preferred_archetype="credential_compromise", rng=random.Random(1),
        http=FakeHttp(reply="garbage"), clock=lambda: next(ticks))
    assert meta["fallback"] is True


def test_status_reports_missing_ollama():
    status = gen.ollama_status(http=FakeHttp(exc=requests.exceptions.ConnectionError()))
    assert status["reachable"] is False and status["model_installed"] is False


def test_status_reports_installed_model():
    status = gen.ollama_status(http=FakeHttp())
    assert status["reachable"] and status["model_installed"]


def test_debrief_is_validated():
    ok = FakeHttp(reply={"commentary": "Good work isolating scope early; next time preserve logs first."})
    assert gen.generate_debrief({"x": 1}, http=ok)
    bad = FakeHttp(reply={"commentary": "Go to https://evil.test for more"})
    assert gen.generate_debrief({"x": 1}, http=bad) is None
    assert gen.generate_debrief({"x": 1}, http=FakeHttp(exc=requests.exceptions.Timeout())) is None


# ---------------------------------------------------------------- cleanup of model prose

def test_tidy_seed_removes_greetings_placeholders_and_weak_objectives():
    raw = _ai_seed("credential_compromise", "medium")
    raw["email"]["paragraphs"] = [
        "Hello Alex, Marcus, and Aisha, we detected unusual activity on the account.",
        "Click here to verify your identity: [Verify Now]",
        "Failure to respond may lock the account.",
    ]
    raw["email"]["cta_label"] = "[CTA]"
    raw["attacker_objective"] = "No compromise"
    tidy = gen.tidy_seed(raw, "credential_compromise")
    assert tidy["email"]["paragraphs"][0].startswith("We detected unusual activity")
    assert "[" not in tidy["email"]["paragraphs"][1]
    assert len(tidy["attacker_objective"]) > 30
    assert raw["email"]["paragraphs"][0].startswith("Hello")     # input not mutated


def test_tidy_seed_passes_non_dicts_through():
    assert gen.tidy_seed("nope", "no_compromise") == "nope"


def test_model_output_with_artifacts_still_produces_a_playable_scenario():
    http = FakeHttp()

    def post(url, json=None, timeout=None):
        wanted = json["format"]["properties"]["difficulty"]["enum"][0]
        seed = _ai_seed("credential_compromise", wanted)
        seed["email"]["paragraphs"][0] = "Dear Daniel, we need you to verify your payroll profile today."
        seed["email"]["paragraphs"][1] = "Use the button below: [Verify Now]"
        return FakeResponse(200, {"message": {"content": __import__("json").dumps(seed)}})

    http.post = post
    scenario, meta = _run(http)
    assert meta["source"] == "ollama"
    assert not scenario["email"]["paragraphs"][0].lower().startswith("dear")


# ---------------------------------------------------------------- warm-up

def test_warm_up_loads_model_and_keeps_it_alive():
    seen = {}

    class Http:
        def post(self, url, json=None, timeout=None):
            seen.update(url=url, json=json)
            return FakeResponse(200, {})

    assert gen.warm_up(http=Http()) is True
    assert seen["url"].endswith("/api/generate")
    assert seen["json"]["model"] == "qwen3:4b" and seen["json"]["keep_alive"]


def test_warm_up_never_raises():
    assert gen.warm_up(http=FakeHttp(exc=requests.exceptions.ConnectionError())) is False


def test_chat_requests_keep_the_model_loaded():
    http = FakeHttp()
    captured = {}

    def post(url, json=None, timeout=None):
        captured.update(json)
        return FakeResponse(200, {"message": {"content": "{}"}})

    http.post = post
    gen.call_ollama_json([], {}, timeout=5, http=http)
    assert captured["keep_alive"] == "30m" and captured["stream"] is False and captured["think"] is False


# ---------------------------------------------------------------- every scenario type via the model path

@pytest.mark.parametrize("archetype", list(schema.ARCHETYPES))
def test_every_scenario_type_can_be_generated_from_model_output(archetype):
    def post(url, json=None, timeout=None):
        wanted = json["format"]["properties"]["difficulty"]["enum"][0]
        seed = good_seed(archetype)
        seed["difficulty"] = wanted
        return FakeResponse(200, {"message": {"content": __import__("json").dumps(seed)}})

    http = FakeHttp()
    http.post = post
    scenario, meta = _run(http, archetype=archetype)
    assert meta["source"] == "ollama" and not meta["fallback"], meta
    assert scenario["archetype"] == archetype and scenario["source"] == "ollama"
    schema.validate_scenario(scenario)
    assert len(scenario["alerts"]) >= 3 and scenario["logs"]


@pytest.mark.parametrize("archetype", list(schema.ARCHETYPES))
def test_prompt_and_schema_exist_for_every_scenario_type(archetype):
    messages = gen.build_messages(archetype, "medium")
    assert archetype in messages[1]["content"]
    assert gen.seed_json_schema(archetype, "medium")["properties"]["victims"]["minItems"] == schema.victim_count_for(archetype)


def test_attachment_scenarios_always_get_a_macro_document_even_if_the_model_omits_it():
    seed = good_seed("malicious_attachment")
    seed["attachment"] = None
    seed["difficulty"] = "medium"
    scenario = compose_scenario(schema.validate_seed(seed))
    assert scenario["email"]["attachment"]["kind"] == "docm"
    assert "inspect_attachment" in scenario["allowed_actions"]

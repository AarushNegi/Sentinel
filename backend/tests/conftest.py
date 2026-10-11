import os
import sys

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

# Never reach out to a real database or model during tests.
os.environ.setdefault("MONGO_URI", "mongodb://localhost:1/test")
os.environ.setdefault("JWT_SECRET", "test-secret-test-secret-test-secret-123")
os.environ["OLLAMA_BASE_URL"] = "http://127.0.0.1:9"   # nothing listens here
os.environ["OLLAMA_TIMEOUT_SECONDS"] = "5"
os.environ["BLUE_PHISHING_WARMUP"] = "false"

from blue_phishing.templates import build_template_scenario, template_archetypes  # noqa: E402


@pytest.fixture(params=list(template_archetypes()))
def scenario(request):
    return build_template_scenario(request.param)


@pytest.fixture
def app_client(monkeypatch):
    import mongomock
    import server
    from flask_jwt_extended import create_access_token

    db = mongomock.MongoClient()["sentinel"]
    monkeypatch.setattr(server, "db", db)
    server.app.config["TESTING"] = True

    def token_for(user_id):
        with server.app.app_context():
            return {"Authorization": f"Bearer {create_access_token(identity=user_id)}"}

    client = server.app.test_client()
    return client, token_for, db, server

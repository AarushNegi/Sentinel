# ===========================
# Sentinel — server.py
# ===========================

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import timedelta
from pymongo import MongoClient
from bson import ObjectId
from bson.errors import InvalidId
import certifi
import bcrypt
import os

# ── Load .env ────────────────────────────────────────────────────
load_dotenv()

# ── App Setup ────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── MongoDB ───────────────────────────────────────────────────────
client = MongoClient(
    os.getenv("MONGO_URI"),
    tlsCAFile=certifi.where(),
    tls=True,
    tlsAllowInvalidCertificates=True
)
db = client["sentinel"]   # ← THIS LINE WAS MISSING

# ── JWT Config ────────────────────────────────────────────────────
app.config["JWT_SECRET_KEY"]           = os.getenv("JWT_SECRET")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
jwt = JWTManager(app)


# ================================================================
#  AUTH ROUTES
# ================================================================

@app.route("/api/auth/register", methods=["POST"])
def register():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name     = data.get("name", "").strip()

    if not email or not password or not name:
        return jsonify({"error": "All fields are required"}), 400

    if db.users.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 409

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    db.users.insert_one({
        "name"    : name,
        "email"   : email,
        "password": hashed,
        "role"    : "student"
    })

    return jsonify({"message": "Account created successfully"}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"error": "Invalid email or password"}), 401

    token = create_access_token(identity=str(user["_id"]))

    return jsonify({
        "message": "Login successful",
        "token"  : token,
        "user"   : {
            "name" : user["name"],
            "email": user["email"],
            "role" : user["role"]
        }
    }), 200


@app.route("/api/auth/guest", methods=["POST"])
def guest_login():
    token = create_access_token(identity="guest")
    return jsonify({
        "message": "Continuing as guest",
        "token"  : token,
        "user"   : {"name": "Guest", "email": "", "role": "guest"}
    }), 200


# ================================================================
#  SIMULATION ROUTES
# ================================================================

@app.route("/api/simulation", methods=["GET"])
@jwt_required()
def get_simulations():
    sims = list(db.simulations.find({}, {"_id": 0}))
    return jsonify({"simulations": sims}), 200


@app.route("/api/simulation/start", methods=["POST"])
@jwt_required()
def start_simulation():
    data        = request.get_json()
    attack_type = data.get("attack_type", "Unknown")
    user_id     = get_jwt_identity()

    sim = {
        "user_id"    : user_id,
        "attack_type": attack_type,
        "status"     : "Running",
        "stage"      : "Reconnaissance",
        "logs"       : []
    }

    result = db.simulations.insert_one(sim)
    return jsonify({
        "message"      : f"{attack_type} simulation started",
        "simulation_id": str(result.inserted_id)
    }), 201


@app.route("/api/simulation/stop", methods=["POST"])
@jwt_required()
def stop_simulation():
    data   = request.get_json()
    sim_id = data.get("simulation_id")
    db.simulations.update_one(
        {"_id": ObjectId(sim_id)},
        {"$set": {"status": "Stopped"}}
    )
    return jsonify({"message": "Simulation stopped"}), 200


# ================================================================
#  KILL CHAIN
# ================================================================

KILL_CHAIN_STAGES = [
    "Reconnaissance", "Weaponization", "Delivery",
    "Exploitation", "Installation", "Command & Control", "Actions on Objectives"
]

PHISHING_SEED_STAGES = {
    "Reconnaissance": {
        "description": "Attacker gathers employee emails from LinkedIn and the company website to identify targets.",
        "mitre_id": "TA0043", "timestamp": "09:01",
        "logs": ["INFO  Recon started", "INFO  3 employee emails harvested"]
    },
    "Weaponization": {
        "description": "Attacker crafts a phishing email impersonating IT support, embedding a malicious login link.",
        "mitre_id": "TA0001", "timestamp": "09:03",
        "logs": ["INFO  Phishing template generated", "INFO  Malicious link embedded"]
    },
    "Delivery": {
        "description": "The phishing email is sent to the target's inbox, disguised as an urgent password reset request.",
        "mitre_id": "T1566.001", "timestamp": "09:06",
        "logs": ["SUCCESS  Email delivered", "INFO  Spam filter bypassed"]
    },
    "Exploitation": {
        "description": "Victim clicks the link and enters credentials on a fake login page.",
        "mitre_id": "T1204.001", "timestamp": "09:08",
        "logs": ["WARNING  Credential reuse detected", "ALERT  Fake login page submitted"]
    },
    "Installation": {
        "description": "Attacker uses stolen credentials to install a lightweight backdoor for persistent access.",
        "mitre_id": "T1505", "timestamp": "09:10",
        "logs": ["ALERT  Unauthorized login detected", "CRITICAL  Backdoor installed"]
    },
    "Command & Control": {
        "description": "Backdoor connects to attacker's remote server, establishing a covert command channel.",
        "mitre_id": "TA0011", "timestamp": "09:14",
        "logs": ["CRITICAL  Outbound C2 connection established", "WARNING  Unusual traffic pattern detected"]
    },
    "Actions on Objectives": {
        "description": "Attacker exfiltrates sensitive files from the workstation to an external server.",
        "mitre_id": "TA0010", "timestamp": "09:18",
        "logs": ["CRITICAL  Sensitive data accessed", "CRITICAL  Data exfiltration in progress"]
    }
}


@app.route("/api/simulation/seed-demo", methods=["POST"])
@jwt_required()
def seed_demo_simulation():
    user_id = get_jwt_identity()
    sim = {
        "user_id"      : user_id,
        "attack_type"  : "Phishing",
        "status"       : "Running",
        "stage"        : "Command & Control",
        "stage_details": PHISHING_SEED_STAGES,
        "logs"         : []
    }
    result = db.simulations.insert_one(sim)
    return jsonify({
        "message"      : "Demo phishing simulation created",
        "simulation_id": str(result.inserted_id)
    }), 201


@app.route("/api/killchain/<simulation_id>", methods=["GET"])
@jwt_required()
def get_kill_chain(simulation_id):
    try:
        obj_id = ObjectId(simulation_id)
    except InvalidId:
        return jsonify({"error": "Invalid simulation ID"}), 400

    sim = db.simulations.find_one({"_id": obj_id})
    if not sim:
        return jsonify({"error": "Simulation not found"}), 404

    current_stage_name  = sim.get("stage", "Reconnaissance")
    current_stage_index = KILL_CHAIN_STAGES.index(current_stage_name) if current_stage_name in KILL_CHAIN_STAGES else 0
    stage_details       = sim.get("stage_details", {})

    stages = []
    for i, stage_name in enumerate(KILL_CHAIN_STAGES):
        if i < current_stage_index:    status = "completed"
        elif i == current_stage_index: status = "active"
        else:                          status = "pending"

        detail = stage_details.get(stage_name, {})
        stages.append({
            "id"         : i,
            "name"       : stage_name,
            "status"     : status,
            "description": detail.get("description", ""),
            "mitre_id"   : detail.get("mitre_id", ""),
            "timestamp"  : detail.get("timestamp"),
            "logs"       : detail.get("logs", [])
        })

    return jsonify({
        "simulation_id": str(sim["_id"]),
        "attack_type"  : sim.get("attack_type"),
        "status"       : sim.get("status"),
        "stages"       : stages
    }), 200


# ================================================================
#  LOGS ROUTES
# ================================================================

@app.route("/api/logs", methods=["GET"])
@jwt_required()
def get_logs():
    logs = list(db.logs.find({}, {"_id": 0}))
    return jsonify({"logs": logs}), 200


@app.route("/api/logs/add", methods=["POST"])
@jwt_required()
def add_log():
    data = request.get_json()
    db.logs.insert_one({
        "message" : data.get("message"),
        "severity": data.get("severity", "INFO"),
        "source"  : data.get("source", "System"),
    })
    return jsonify({"message": "Log added"}), 201


# ================================================================
#  DASHBOARD STATS
# ================================================================

@app.route("/api/dashboard/stats", methods=["GET"])
@jwt_required()
def dashboard_stats():
    return jsonify({
        "total_logs"        : db.logs.count_documents({}),
        "active_simulations": db.simulations.count_documents({"status": "Running"}),
        "total_simulations" : db.simulations.count_documents({}),
        "threat_level"      : "High",
        "success_rate"      : 87
    }), 200


# ================================================================
#  HEALTH CHECK
# ================================================================

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "running", "project": "Sentinel", "version": "1.0.0"}), 200


# ================================================================
#  RUN SERVER
# ================================================================

if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") == "development"
    app.run(debug=debug, host="0.0.0.0", port=port)
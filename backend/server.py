# ===========================
# Sentinel — server.py
# ===========================

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import timedelta, datetime
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
db = client["sentinel"]

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
#  LEGACY SIMULATION ROUTES (AlertQueue / demo flow)
# ================================================================

@app.route("/api/simulation", methods=["GET"])
@jwt_required()
def get_simulations():
    sims = list(db.simulations.find({}, {"_id": 0}))
    return jsonify({"simulations": sims}), 200


@app.route("/api/simulation/start-legacy", methods=["POST"])
@jwt_required()
def start_simulation_legacy():
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
#  SIMULATION REPORTS
# ================================================================

@app.route("/api/simulation/report", methods=["POST"])
@jwt_required()
def save_simulation_report():
    user_id = get_jwt_identity()
    data = request.get_json()

    report = {
        "user_id"         : user_id,
        "mode"             : data.get("mode"),
        "attack"           : data.get("attack"),
        "guide_title"      : data.get("guideTitle"),
        "result"           : data.get("result"),
        "failed_at_stage"  : data.get("failedAtStage"),
        "total_stages"     : data.get("totalStages"),
        "stages_completed" : data.get("stagesCompleted"),
        "score"            : data.get("score"),
        "max_score"        : data.get("maxScore"),
        "duration_seconds" : data.get("durationSeconds"),
        "choices"          : data.get("choices", []),
        "log_lines"        : data.get("logLines", []),
        "created_at"       : datetime.utcnow().isoformat()
    }

    result = db.reports.insert_one(report)
    return jsonify({
        "message"  : "Report saved",
        "report_id": str(result.inserted_id)
    }), 201


@app.route("/api/simulation/reports", methods=["GET"])
@jwt_required()
def get_my_reports():
    user_id = get_jwt_identity()
    reports = list(db.reports.find({"user_id": user_id}).sort("created_at", -1))
    for r in reports:
        r["_id"] = str(r["_id"])
    return jsonify({"reports": reports}), 200


@app.route("/api/simulation/report/<report_id>", methods=["GET"])
@jwt_required()
def get_report(report_id):
    try:
        obj_id = ObjectId(report_id)
    except InvalidId:
        return jsonify({"error": "Invalid report ID"}), 400

    report = db.reports.find_one({"_id": obj_id})
    if not report:
        return jsonify({"error": "Report not found"}), 404

    report["_id"] = str(report["_id"])
    return jsonify({"report": report}), 200


# ================================================================
#  KILL CHAIN (demo/legacy - kept for compatibility)
# ================================================================

KILL_CHAIN_STAGES = [
    "Reconnaissance", "Weaponization", "Delivery",
    "Exploitation", "Installation", "Command & Control", "Actions on Objectives"
]

PHISHING_SEED_STAGES = {
    "Reconnaissance": {"description": "Attacker gathers employee emails.", "mitre_id": "TA0043", "timestamp": "09:01", "logs": []},
    "Weaponization": {"description": "Attacker crafts a phishing email.", "mitre_id": "TA0001", "timestamp": "09:03", "logs": []},
    "Delivery": {"description": "The phishing email is sent.", "mitre_id": "T1566.001", "timestamp": "09:06", "logs": []},
    "Exploitation": {"description": "Victim clicks the link.", "mitre_id": "T1204.001", "timestamp": "09:08", "logs": []},
    "Installation": {"description": "Attacker installs a backdoor.", "mitre_id": "T1505", "timestamp": "09:10", "logs": []},
    "Command & Control": {"description": "Backdoor connects to C2.", "mitre_id": "TA0011", "timestamp": "09:14", "logs": []},
    "Actions on Objectives": {"description": "Attacker exfiltrates data.", "mitre_id": "TA0010", "timestamp": "09:18", "logs": []}
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
    user_id = get_jwt_identity()
    return jsonify({
        "total_logs"        : db.logs.count_documents({}),
        "active_simulations": db.simulations.count_documents({"status": "Running"}),
        "total_simulations" : db.simulations.count_documents({}),
        "reports_completed" : db.reports.count_documents({"user_id": user_id}),
        "threat_level"      : "High",
        "success_rate"      : 87
    }), 200


# ================================================================
#  SCENARIOS (new backend-driven simulation engine)
# ================================================================

@app.route("/api/scenarios/<mode>/<attack>", methods=["GET"])
@jwt_required()
def get_scenario(mode, attack):
    scenario = db.scenarios.find_one({"mode": mode, "attack": attack})
    if not scenario:
        return jsonify({"error": "Scenario not found"}), 404

    # Strip outcome/feedback/hint from options — client only gets id + text
    safe_stages = []
    for stage in scenario["stages"]:
        safe_options = [
            {"id": opt["id"], "text": opt["text"]}
            for opt in stage["challenge"]["options"]
        ]
        safe_stages.append({
            "stageId": stage["stageId"],
            "name": stage["name"],
            "narrative": stage["narrative"],
            "mitre": stage["mitre"],
            "challenge": {
                "prompt": stage["challenge"]["prompt"],
                "options": safe_options
            }
        })

    return jsonify({
        "title": scenario["title"],
        "headline": scenario["headline"],
        "overview": scenario["overview"],
        "targets": scenario["targets"],
        "tips": scenario["tips"],
        "stages": safe_stages
    }), 200


@app.route("/api/simulation/start", methods=["POST"])
@jwt_required()
def start_simulation():
    data = request.get_json()
    mode = data.get("mode")
    attack = data.get("attack")
    user_id = get_jwt_identity()

    scenario = db.scenarios.find_one({"mode": mode, "attack": attack})
    if not scenario:
        return jsonify({"error": "Scenario not found"}), 404

    session = {
        "user_id": user_id,
        "mode": mode,
        "attack": attack,
        "scenario_id": scenario["_id"],
        "current_stage_idx": 0,
        "choices": [],
        "log_lines": [],
        "status": "in_progress",
        "started_at": datetime.utcnow().isoformat()
    }
    result = db.simulation_sessions.insert_one(session)

    return jsonify({
        "session_id": str(result.inserted_id),
        "total_stages": len(scenario["stages"])
    }), 201


@app.route("/api/simulation/<session_id>/choice", methods=["POST"])
@jwt_required()
def submit_choice(session_id):
    data = request.get_json()
    option_id = data.get("optionId")

    try:
        obj_id = ObjectId(session_id)
    except InvalidId:
        return jsonify({"error": "Invalid session ID"}), 400

    session = db.simulation_sessions.find_one({"_id": obj_id})
    if not session:
        return jsonify({"error": "Session not found"}), 404
    if session["status"] != "in_progress":
        return jsonify({"error": "Simulation already ended"}), 400

    scenario = db.scenarios.find_one({"_id": session["scenario_id"]})
    stage_idx = session["current_stage_idx"]
    stage = scenario["stages"][stage_idx]

    chosen_option = next((o for o in stage["challenge"]["options"] if o["id"] == option_id), None)
    if not chosen_option:
        return jsonify({"error": "Invalid option"}), 400

    points_map = {"best": 10, "risky": 5, "fail": 0}
    points = points_map[chosen_option["outcome"]]

    db.simulation_sessions.update_one(
        {"_id": session["_id"]},
        {
            "$push": {
                "choices": {
                    "stageId": stage["stageId"],
                    "optionId": option_id,
                    "outcome": chosen_option["outcome"],
                    "points": points
                },
                "log_lines": stage["log"]
            }
        }
    )

    ended = chosen_option["outcome"] == "fail"
    next_stage_idx = stage_idx + 1
    is_last_stage = next_stage_idx >= len(scenario["stages"])

    if ended or is_last_stage:
        db.simulation_sessions.update_one(
            {"_id": session["_id"]},
            {"$set": {"status": "failed" if ended else "completed"}}
        )
    else:
        db.simulation_sessions.update_one(
            {"_id": session["_id"]},
            {"$set": {"current_stage_idx": next_stage_idx}}
        )

    return jsonify({
        "outcome": chosen_option["outcome"],
        "feedback": chosen_option["feedback"],
        "points": points,
        "log": stage["log"],
        "ended": ended or is_last_stage,
        "nextStageIdx": None if (ended or is_last_stage) else next_stage_idx
    }), 200


@app.route("/api/simulation/<session_id>/complete", methods=["POST"])
@jwt_required()
def complete_simulation(session_id):
    try:
        obj_id = ObjectId(session_id)
    except InvalidId:
        return jsonify({"error": "Invalid session ID"}), 400

    session = db.simulation_sessions.find_one({"_id": obj_id})
    if not session:
        return jsonify({"error": "Session not found"}), 404

    scenario = db.scenarios.find_one({"_id": session["scenario_id"]})
    total_points = sum(c["points"] for c in session["choices"])
    max_points = len(scenario["stages"]) * 10

    report = {
        "user_id": session["user_id"],
        "mode": session["mode"],
        "attack": session["attack"],
        "result": session["status"],
        "score": total_points,
        "max_score": max_points,
        "choices": session["choices"],
        "log_lines": session["log_lines"],
        "created_at": datetime.utcnow().isoformat()
    }
    db.reports.insert_one(report)

    return jsonify({"message": "Report saved", "score": total_points}), 200

# ================================================================
#  LEARN HUB
# ================================================================

@app.route("/api/learn/articles", methods=["GET"])
@jwt_required()
def get_learn_articles():
    category = request.args.get("category")
    query = {"category": category} if category else {}
    articles = list(db.learn_articles.find(
        query,
        {"content": 0, "furtherReading": 0}  # list view doesn't need full body
    ))
    for a in articles:
        a["_id"] = str(a["_id"])
    return jsonify({"articles": articles}), 200


@app.route("/api/learn/articles/<slug>", methods=["GET"])
@jwt_required()
def get_learn_article(slug):
    article = db.learn_articles.find_one({"slug": slug})
    if not article:
        return jsonify({"error": "Article not found"}), 404
    article["_id"] = str(article["_id"])
    return jsonify({"article": article}), 200


@app.route("/api/learn/categories", methods=["GET"])
@jwt_required()
def get_learn_categories():
    categories = db.learn_articles.distinct("category")
    return jsonify({"categories": categories}), 200



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
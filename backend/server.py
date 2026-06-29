# ===========================
# Sentinel — server.py
# ===========================

from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import timedelta
import bcrypt
import os

# ── Load .env ────────────────────────────────────────────────────
load_dotenv()

# ── App Setup ────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── MongoDB Config ────────────────────────────────────────────────
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)

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

    existing = mongo.db.users.find_one({"email": email})
    if existing:
        return jsonify({"error": "Email already registered"}), 409

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    mongo.db.users.insert_one({
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

    user = mongo.db.users.find_one({"email": email})
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
    sims = list(mongo.db.simulations.find({}, {"_id": 0}))
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

    result = mongo.db.simulations.insert_one(sim)
    return jsonify({
        "message"      : f"{attack_type} simulation started",
        "simulation_id": str(result.inserted_id)
    }), 201


@app.route("/api/simulation/stop", methods=["POST"])
@jwt_required()
def stop_simulation():
    data   = request.get_json()
    sim_id = data.get("simulation_id")
    mongo.db.simulations.update_one(
        {"_id": sim_id},
        {"$set": {"status": "Stopped"}}
    )
    return jsonify({"message": "Simulation stopped"}), 200


# ================================================================
#  LOGS ROUTES
# ================================================================

@app.route("/api/logs", methods=["GET"])
@jwt_required()
def get_logs():
    logs = list(mongo.db.logs.find({}, {"_id": 0}))
    return jsonify({"logs": logs}), 200


@app.route("/api/logs/add", methods=["POST"])
@jwt_required()
def add_log():
    data = request.get_json()
    log  = {
        "message" : data.get("message"),
        "severity": data.get("severity", "INFO"),
        "source"  : data.get("source", "System"),
    }
    mongo.db.logs.insert_one(log)
    return jsonify({"message": "Log added"}), 201


# ================================================================
#  DASHBOARD STATS
# ================================================================

@app.route("/api/dashboard/stats", methods=["GET"])
@jwt_required()
def dashboard_stats():
    return jsonify({
        "total_logs"        : mongo.db.logs.count_documents({}),
        "active_simulations": mongo.db.simulations.count_documents({"status": "Running"}),
        "total_simulations" : mongo.db.simulations.count_documents({}),
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
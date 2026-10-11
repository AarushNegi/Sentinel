# ===========================
# Sentinel — server.py
# ===========================

from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import timedelta, datetime, timezone
from pymongo import MongoClient
from bson import ObjectId
from bson.errors import InvalidId
import certifi
import bcrypt
import os
import uuid

from blue_phishing import engine as blue_engine
from blue_phishing import scenario_schema as blue_schema
from blue_phishing import templates as blue_templates
from ai import scenario_generator as blue_ai


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
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

jwt = JWTManager(app)


# ================================================================
#  RED TEAM — PHISHING COMPLETE
# ================================================================

@app.route("/api/red-phishing/complete", methods=["POST"])

@jwt_required()

def complete_red_phishing():

    try:

        data = request.get_json() or {}
        user_id = get_jwt_identity()

        target = data.get("target", {})
        campaign = data.get("campaign", {})

        # NOTE: no password is ever accepted or stored here. Only a fixed,
        # fictional training account is tracked — never a real credential.
        credential_capture = None
        if data.get("credentialSubmitted"):
            credential_capture = {
                "username": data.get("targetAccount"),
                "credential_submission": True,
                "credential_type": "simulated",
                "source": campaign.get("simulatedLink"),
            }

        report = {

            "user_id": user_id,

            "mode": "red",

            "attack": "phishing",

            "guide_title": "Red Team — FaceWorld Phishing",

            "target": {
                "id": target.get("id"),
                "name": target.get("name"),
                "role": target.get("role"),
                "department": target.get("department"),
                "email": target.get("email"),
            },

            "credential_capture": credential_capture,

            "campaign": campaign,

            "campaign_analysis": data.get("campaignAnalysis", {}),

            "defender_indicators": data.get("indicators", []),

            "score": data.get("score", 0),

            "max_score": data.get("maxScore", 1025),

            "duration_seconds": data.get(
                "durationSeconds",
                0
            ),

            "stages_completed": data.get(
                "stagesCompleted",
                []
            ),

            "total_stages": data.get("totalStages", 7),

            "failed_at_stage": data.get("failedAtStage"),

            "choices": data.get(
                "choices",
                []
            ),

            "log_lines": data.get(
                "logLines",
                []
            ),

            "result": data.get("result", "success"),

            "created_at": datetime.now(timezone.utc),
        }

        result = db.simulation_reports.insert_one(
            report
        )

        return jsonify({

            "success": True,

            "message":
                "Red Team phishing simulation saved",

            "report_id":
                str(result.inserted_id)

        }), 201

    except Exception as e:

        print(
            "Red phishing save error:",
            e
        )

        return jsonify({

            "success": False,

            "error": str(e)

        }), 500
    # ================================================================
#  RED TEAM — RANSOMWARE SIMULATION
# ================================================================

RED_RANSOMWARE_MAX_SCORE = 1000

RED_RANSOMWARE_STAGES = [
    "recon",
    "vulnerability",
    "execution",
    "propagation",
    "compromise",
    "encryption",
    "impact",
]


RED_RANSOMWARE_INCIDENT = {
    "id": "RANSOM-2017-001",

    "name": "WannaCry-Inspired Ransomware Simulation",

    "organization": "Northbridge Health Network",

    "severity": "CRITICAL",

    "type": "Ransomware",

    "historical_basis": (
        "Inspired by documented characteristics of the "
        "2017 WannaCry ransomware incident."
    ),

    "environment": {
        "network": "Northbridge Internal Network",

        "hosts": [
            {
                "id": "clinic-ws-014",
                "name": "CLINIC-WS-014",
                "type": "Clinical Workstation",
                "department": "Emergency Care",
                "os": "Windows 7",
                "exposure": "HIGH",
            },
            {
                "id": "lab-ws-008",
                "name": "LAB-WS-008",
                "type": "Laboratory Workstation",
                "department": "Diagnostics",
                "os": "Windows 7",
                "exposure": "HIGH",
            },
            {
                "id": "admin-ws-022",
                "name": "ADMIN-WS-022",
                "type": "Administrative Workstation",
                "department": "Administration",
                "os": "Windows 10",
                "exposure": "MEDIUM",
            },
            {
                "id": "pharm-ws-031",
                "name": "PHARM-WS-031",
                "type": "Pharmacy Workstation",
                "department": "Pharmacy",
                "os": "Windows 7",
                "exposure": "HIGH",
            },
            {
                "id": "file-srv-01",
                "name": "FILE-SRV-01",
                "type": "File Server",
                "department": "Shared Services",
                "os": "Windows Server",
                "exposure": "CRITICAL",
            },
            {
                "id": "dc-01",
                "name": "DC-01",
                "type": "Domain Controller",
                "department": "Infrastructure",
                "os": "Windows Server",
                "exposure": "CRITICAL",
            },
        ],
    },
}


RED_RANSOMWARE_INITIAL_STATE = {
    "networkScanned": False,
    "hostInspected": False,
    "vulnerabilityIdentified": False,
    "executionSimulated": False,
    "propagationStarted": False,
    "compromiseEstablished": False,
    "encryptionSimulated": False,
    "impactAssessed": False,
}


RED_RANSOMWARE_ACTIONS = {

    "scan_network": {
        "state": "networkScanned",
        "points": 100,
        "stage": "recon",
    },

    "inspect_host": {
        "state": "hostInspected",
        "points": 0,
        "stage": "recon",
    },

    "identify_vulnerability": {
        "state": "vulnerabilityIdentified",
        "points": 150,
        "stage": "vulnerability",
    },

    "simulate_execution": {
        "state": "executionSimulated",
        "points": 125,
        "stage": "execution",
    },

    "start_propagation": {
        "state": "propagationStarted",
        "points": 150,
        "stage": "propagation",
    },

    "compromise_hosts": {
        "state": "compromiseEstablished",
        "points": 150,
        "stage": "compromise",
    },

    "simulate_encryption": {
        "state": "encryptionSimulated",
        "points": 150,
        "stage": "encryption",
    },

    "assess_impact": {
        "state": "impactAssessed",
        "points": 175,
        "stage": "impact",
    },
}
def red_ransomware_action_allowed(state, action):

    requirements = {

        "scan_network": [],

        "inspect_host": [
            "networkScanned"
        ],

        "identify_vulnerability": [
            "networkScanned",
            "hostInspected"
        ],

        "simulate_execution": [
            "networkScanned",
            "hostInspected",
            "vulnerabilityIdentified"
        ],

        "start_propagation": [
            "executionSimulated"
        ],

        "compromise_hosts": [
            "propagationStarted"
        ],

        "simulate_encryption": [
            "compromiseEstablished"
        ],

        "assess_impact": [
            "encryptionSimulated"
        ],
    }

    required = requirements.get(action)

    if required is None:
        return False, "Unknown Red Team ransomware action."

    for state_key in required:

        if not state.get(state_key):

            return (
                False,
                f"Required step not completed: {state_key}"
            )

    return True, None
# ================================================================
#  RED RANSOMWARE — START / RESUME SESSION
# ================================================================

@app.route(
    "/api/red-ransomware/start",
    methods=["POST"]
)
@jwt_required()
def start_red_ransomware():

    try:

        user_id = get_jwt_identity()

        # --------------------------------------------------------
        # Resume existing unfinished ransomware session
        # --------------------------------------------------------

        existing = db.red_ransomware_sessions.find_one(
            {
                "user_id": user_id,
                "mode": "red",
                "attack": "ransomware",
                "status": "in_progress",
            },
            sort=[("updated_at", -1)]
        )

        if existing:

            return jsonify({

                "success": True,

                "resumed": True,

                "session_id":
                    str(existing["_id"]),

                "incident":
                    existing.get(
                        "incident",
                        RED_RANSOMWARE_INCIDENT
                    ),

                "state":
                    existing.get(
                        "state",
                        RED_RANSOMWARE_INITIAL_STATE
                    ),

                "stage":
                    existing.get(
                        "stage",
                        "recon"
                    ),

                "score":
                    existing.get(
                        "score",
                        0
                    ),

                "max_score":
                    existing.get(
                        "max_score",
                        RED_RANSOMWARE_MAX_SCORE
                    ),

                "events":
                    existing.get(
                        "events",
                        []
                    ),

                "actions":
                    existing.get(
                        "actions",
                        []
                    ),

                "selected_host":
                    existing.get(
                        "selected_host"
                    ),

                "elapsed_seconds":
                    0,

                "status":
                    "in_progress",

            }), 200

        # --------------------------------------------------------
        # Create new session
        # --------------------------------------------------------

        now = datetime.now(timezone.utc)

        events = [
            "Ransomware operation initialized",
            "Northbridge Health Network environment loaded",
            "Fictional internal network available",
            "Historical basis: WannaCry-inspired simulation",
            "No real malware or exploit code is executed",
        ]

        session = {

            "user_id":
                user_id,

            "mode":
                "red",

            "attack":
                "ransomware",

            "incident":
                RED_RANSOMWARE_INCIDENT,

            "state":
                RED_RANSOMWARE_INITIAL_STATE.copy(),

            "stage":
                "recon",

            "score":
                0,

            "max_score":
                RED_RANSOMWARE_MAX_SCORE,

            "events":
                events,

            "actions":
                [],

            "selected_host":
                None,

            "status":
                "in_progress",

            "started_at":
                now,

            "updated_at":
                now,

            "completed_at":
                None,
        }

        result = db.red_ransomware_sessions.insert_one(
            session
        )

        return jsonify({

            "success":
                True,

            "resumed":
                False,

            "session_id":
                str(result.inserted_id),

            "incident":
                RED_RANSOMWARE_INCIDENT,

            "state":
                RED_RANSOMWARE_INITIAL_STATE,

            "stage":
                "recon",

            "score":
                0,

            "max_score":
                RED_RANSOMWARE_MAX_SCORE,

            "events":
                events,

            "actions":
                [],

            "selected_host":
                None,

            "elapsed_seconds":
                0,

            "status":
                "in_progress",

        }), 201

    except Exception as e:

        print(
            "Red ransomware start error:",
            e
        )

        return jsonify({

            "success":
                False,

            "error":
                str(e),

        }), 500
    # ================================================================
#  RED RANSOMWARE — PERFORM ACTION
# ================================================================

@app.route(
    "/api/red-ransomware/<session_id>/action",
    methods=["POST"]
)
@jwt_required()
def red_ransomware_action(session_id):

    try:

        user_id = get_jwt_identity()

        # --------------------------------------------------------
        # Validate MongoDB session ID
        # --------------------------------------------------------

        try:

            object_id = ObjectId(
                session_id
            )

        except InvalidId:

            return jsonify({

                "success":
                    False,

                "error":
                    "Invalid simulation session."

            }), 400

        # --------------------------------------------------------
        # Find session belonging to current user
        # --------------------------------------------------------

        session = db.red_ransomware_sessions.find_one({

            "_id":
                object_id,

            "user_id":
                user_id,

        })

        if not session:

            return jsonify({

                "success":
                    False,

                "error":
                    "Simulation session not found."

            }), 404

        # --------------------------------------------------------
        # Prevent actions after completion
        # --------------------------------------------------------

        if session.get("status") == "completed":

            return jsonify({

                "success":
                    False,

                "error":
                    "Simulation is already completed."

            }), 400

        data = request.get_json() or {}

        action = data.get(
            "action"
        )

        # --------------------------------------------------------
        # Validate action name
        # --------------------------------------------------------

        if action not in RED_RANSOMWARE_ACTIONS:

            return jsonify({

                "success":
                    False,

                "error":
                    "Unknown Red Team ransomware action."

            }), 400

        action_config = RED_RANSOMWARE_ACTIONS[
            action
        ]

        state = dict(
            session.get(
                "state",
                RED_RANSOMWARE_INITIAL_STATE.copy()
            )
        )

        state_key = action_config["state"]

        # --------------------------------------------------------
        # Prevent duplicate scoring
        # --------------------------------------------------------

        if state.get(state_key):

            return jsonify({

                "success":
                    False,

                "error":
                    "This action has already been completed.",

                "state":
                    state,

                "stage":
                    session.get(
                        "stage"
                    ),

                "score":
                    session.get(
                        "score",
                        0
                    ),

                "events":
                    session.get(
                        "events",
                        []
                    ),

            }), 409

        # --------------------------------------------------------
        # Server-side sequence validation
        # --------------------------------------------------------

        allowed, error_message = (
            red_ransomware_action_allowed(
                state,
                action
            )
        )

        if not allowed:

            return jsonify({

                "success":
                    False,

                "error":
                    error_message,

                "state":
                    state,

                "stage":
                    session.get(
                        "stage"
                    ),

                "score":
                    session.get(
                        "score",
                        0
                    ),

                "events":
                    session.get(
                        "events",
                        []
                    ),

            }), 400

        # --------------------------------------------------------
        # Selected host
        # --------------------------------------------------------

        selected_host = session.get(
            "selected_host"
        )

        if action == "inspect_host":

            host_id = data.get("host_id")

            if not host_id:
                return jsonify({
                    "success": False,
                    "error": "Missing host ID."
                }), 400

            hosts = RED_RANSOMWARE_INCIDENT.get(
                "environment", {}
            ).get(
                "hosts", []
            )

            selected = next(
                (
                    host
                    for host in hosts
                    if host.get("id") == host_id
                ),
                None
            )

            if selected is None:
                return jsonify({
                    "success": False,
                    "error": "Invalid fictional host."
                }), 400

            selected_host = selected

        # --------------------------------------------------------
        # Update state
        # --------------------------------------------------------

        state[state_key] = True

        current_score = int(
            session.get(
                "score",
                0
            )
        )

        points = int(
            action_config["points"]
        )

        new_score = min(

            RED_RANSOMWARE_MAX_SCORE,

            current_score + points

        )

        events = list(
            session.get(
                "events",
                []
            )
        )

        actions = list(
            session.get(
                "actions",
                []
            )
        )

        # --------------------------------------------------------
        # Telemetry
        # --------------------------------------------------------
        host_info = selected_host or {}
        telemetry = {

            "scan_network": [
                "Internal network discovery simulation initiated",
                "Northbridge network segments enumerated",
                "Legacy Windows hosts identified",
                "Clinical, laboratory and administrative systems discovered",
            ],

            "inspect_host": [
                f"Host selected: {host_info.get('name', 'Unknown')}",
                f"Host type: {host_info.get('type', 'Unknown')}",
                f"Operating system: {host_info.get('os', 'Unknown')}",
                f"Exposure classification: {host_info.get('exposure', 'Unknown')}",
            ],

            "identify_vulnerability": [
                f"Security posture reviewed for {host_info.get('name', 'selected host')}",
                "Legacy SMB exposure identified",
                "Historical MS17-010 class weakness represented in simulation",
                "No real exploit code executed",
            ],

            "simulate_execution": [
                f"Simulated ransomware execution triggered on {host_info.get('name', 'selected host')}",
                "Malicious payload represented as a controlled event",
                "No real ransomware binary executed",
            ],

            "start_propagation": [
                "Propagation simulation initiated",
                "Internal SMB relationships evaluated",
                "Additional vulnerable Windows hosts identified",
                "Clinical network segment exposed to simulated propagation",
                "FILE-SRV-01 relationship identified",
            ],

            "compromise_hosts": [
                "Simulated host compromise confirmed",
                "CLINIC-WS-014 status: COMPROMISED",
                "LAB-WS-008 status: COMPROMISED",
                "PHARM-WS-031 status: COMPROMISED",
                "FILE-SRV-01 status: AT RISK",
            ],

            "simulate_encryption": [
                "File encryption simulation initiated",
                "Clinical workstation documents marked as encrypted",
                "Shared network files marked as encrypted",
                "FILE-SRV-01 shared resources affected",
                "No real files were modified or encrypted",
            ],

            "assess_impact": [
                "Operational impact assessment initiated",
                "Clinical workstation availability degraded",
                "Shared file resources unavailable",
                "Patient-care support systems potentially disrupted",
                "Incident classified as HIGH operational impact",
            ],
        }

        for message in telemetry.get(
            action,
            []
        ):

            events.append(
                message
            )

        # --------------------------------------------------------
        # Record action
        # --------------------------------------------------------

        actions.append({

            "action":
                action,

            "points":
                points,

            "stage":
                action_config["stage"],

            "host":
                selected_host,

            "created_at":
                datetime.now(timezone.utc),

        })

        now = datetime.now(timezone.utc)

        # --------------------------------------------------------
        # Move to next stage
        # --------------------------------------------------------

        current_stage = action_config["stage"]

        stage_index = (
            RED_RANSOMWARE_STAGES.index(
                current_stage
            )
        )

        new_stage = current_stage

        if stage_index < len(
            RED_RANSOMWARE_STAGES
        ) - 1:

            new_stage = (
                RED_RANSOMWARE_STAGES[
                    stage_index + 1
                ]
            )

        # --------------------------------------------------------
        # Final impact action completes the session
        # --------------------------------------------------------

        status = "in_progress"
        completed_at = None

        if action == "assess_impact":

            status = "completed"

            completed_at = now

            new_stage = "complete"

            events.append(
                "Ransomware operation completed successfully"
            )

        # --------------------------------------------------------
        # Persist
        # --------------------------------------------------------

        update_data = {

            "state":
                state,

            "stage":
                new_stage,

            "score":
                new_score,

            "events":
                events,

            "actions":
                actions,

            "selected_host":
                selected_host,

            "status":
                status,

            "updated_at":
                now,

        }

        if completed_at:

            update_data[
                "completed_at"
            ] = completed_at

        db.red_ransomware_sessions.update_one(

            {
                "_id":
                    object_id,

                "user_id":
                    user_id,

            },

            {
                "$set":
                    update_data
            }

        )

        return jsonify({

            "success":
                True,

            "action":
                action,

            "state":
                state,

            "stage":
                new_stage,

            "score":
                new_score,

            "max_score":
                RED_RANSOMWARE_MAX_SCORE,

            "events":
                events,

            "actions":
                actions,

            "selected_host":
                selected_host,

            "status":
                status,

            "completed":
                status == "completed",

        }), 200

    except Exception as e:

        print(
            "Red ransomware action error:",
            e
        )

        return jsonify({

            "success":
                False,

            "error":
                str(e),

        }), 500
    # ================================================================
#  RED RANSOMWARE — REPORT JSON SAFETY
# ================================================================

def red_ransomware_json_safe(value):

    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, dict):
        return {
            key: red_ransomware_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            red_ransomware_json_safe(item)
            for item in value
        ]

    return value


# ================================================================
#  RED RANSOMWARE — COMPLETE SESSION / CREATE REPORT
# ================================================================

@app.route(
    "/api/red-ransomware/<session_id>/complete",
    methods=["POST"]
)
@jwt_required()
def complete_red_ransomware(session_id):

    try:

        user_id = get_jwt_identity()

        try:

            object_id = ObjectId(
                session_id
            )

        except InvalidId:

            return jsonify({

                "success":
                    False,

                "error":
                    "Invalid simulation session."

            }), 400

        session = db.red_ransomware_sessions.find_one({

            "_id":
                object_id,

            "user_id":
                user_id,

        })

        if not session:

            return jsonify({

                "success":
                    False,

                "error":
                    "Simulation session not found."

            }), 404

        state = session.get(
            "state",
            RED_RANSOMWARE_INITIAL_STATE.copy()
        )

        if not state.get(
            "impactAssessed"
        ):

            return jsonify({

                "success":
                    False,

                "error":
                    "Complete the ransomware operation before generating the final report."

            }), 400

        completed_at = session.get(
            "completed_at"
        )

        if not completed_at:

            completed_at = datetime.now(
                timezone.utc
            )

            db.red_ransomware_sessions.update_one(

                {
                    "_id":
                        object_id,

                    "user_id":
                        user_id,

                },

                {
                    "$set": {

                        "completed_at":
                            completed_at,

                        "status":
                            "completed",

                        "updated_at":
                            completed_at,

                    }
                }

            )

        started_at = session.get(
            "started_at"
        )

        duration_seconds = 0

        if started_at and completed_at:

            if started_at.tzinfo is None:

                started_at = started_at.replace(
                    tzinfo=timezone.utc
                )

            if completed_at.tzinfo is None:

                completed_at = completed_at.replace(
                    tzinfo=timezone.utc
                )

            duration_seconds = max(

                0,

                int(
                    (
                        completed_at
                        - started_at
                    ).total_seconds()
                )

            )

        actions = session.get(
            "actions",
            []
        )

        # --------------------------------------------------------
        # Make MongoDB-safe action copies
        # --------------------------------------------------------

        report_actions = []

        for action in actions:

            report_actions.append({

                "action":
                    action.get(
                        "action"
                    ),

                "stage":
                    action.get(
                        "stage"
                    ),

                "points":
                    action.get(
                        "points",
                        0
                    ),

                "host":
                    action.get(
                        "host"
                    ),

                "created_at":
                    action.get(
                        "created_at"
                    ),

            })

        report = {

            "report_id":
                str(
                    session["_id"]
                ),

            "session_id":
                str(
                    session["_id"]
                ),

            "user_id":
                user_id,

            "mode":
                "red",

            "attack":
                "ransomware",

            "guide_title":
                "Red Team — WannaCry-Inspired Ransomware",

            "result":
                "success",

            "incident":
                session.get(
                    "incident",
                    RED_RANSOMWARE_INCIDENT
                ),

            "target":
                session.get(
                    "selected_host"
                ),

            "score":
                session.get(
                    "score",
                    0
                ),

            "max_score":
                session.get(
                    "max_score",
                    RED_RANSOMWARE_MAX_SCORE
                ),

            "duration_seconds":
                duration_seconds,

            "total_stages":
                len(
                    RED_RANSOMWARE_STAGES
                ),

            "stages_completed":
                RED_RANSOMWARE_STAGES,

            "actions":
                report_actions,

            "state":
                state,

            "log_lines":
                session.get(
                    "events",
                    []
                ),

            "created_at":
                completed_at,

            "completed_at":
                completed_at,

        }

        # --------------------------------------------------------
        # Prevent duplicate permanent reports
        # --------------------------------------------------------

        existing_report = (
            db.red_ransomware_reports.find_one({

                "session_id":
                    str(
                        session["_id"]
                    ),

                "user_id":
                    user_id,

            })
        )

        if existing_report:

            report_id = str(
                existing_report["_id"]
            )

            db.red_ransomware_reports.update_one(

                {
                    "_id":
                        existing_report["_id"]
                },

                {
                    "$set":
                        report
                }

            )

        else:

            result = (
                db.red_ransomware_reports.insert_one(
                    report
                )
            )

            report_id = str(
                result.inserted_id
            )

        safe_report = red_ransomware_json_safe(
            report
        )

        return jsonify({

            "success":
                True,

            "message":
                "Red Team ransomware report saved",

            "report_id":
                report_id,

            "report":
                safe_report,

        }), 200

    except Exception as e:

        print(
            "Red ransomware completion error:",
            e
        )

        return jsonify({

            "success":
                False,

            "error":
                str(e),

        }), 500
    # ================================================================
#  RED RANSOMWARE — GET REPORT
# ================================================================

@app.route(
    "/api/red-ransomware/<session_id>/report",
    methods=["GET"]
)
@jwt_required()
def get_red_ransomware_report(session_id):

    try:

        user_id = get_jwt_identity()

        # --------------------------------------------------------
        # First check permanent report
        # --------------------------------------------------------

        report = db.red_ransomware_reports.find_one({

            "session_id":
                session_id,

            "user_id":
                user_id,

        })

        if report:

            report["_id"] = str(
                report["_id"]
            )

            safe_report = red_ransomware_json_safe(
                report
            )

            return jsonify({

                "success":
                    True,

                "report":
                    safe_report,

            }), 200

        # --------------------------------------------------------
        # Otherwise check session
        # --------------------------------------------------------

        try:

            object_id = ObjectId(
                session_id
            )

        except InvalidId:

            return jsonify({

                "success":
                    False,

                "error":
                    "Invalid simulation session."

            }), 400

        session = db.red_ransomware_sessions.find_one({

            "_id":
                object_id,

            "user_id":
                user_id,

        })

        if not session:

            return jsonify({

                "success":
                    False,

                "error":
                    "Simulation session not found."

            }), 404

        if session.get(
            "status"
        ) != "completed":

            return jsonify({

                "success":
                    False,

                "error":
                    "Simulation has not been completed yet."

            }), 400

        # --------------------------------------------------------
        # Generate report from completed session
        # --------------------------------------------------------

        started_at = session.get(
            "started_at"
        )

        completed_at = session.get(
            "completed_at"
        )

        duration_seconds = 0

        if started_at and completed_at:

            if started_at.tzinfo is None:
                started_at = started_at.replace(
                    tzinfo=timezone.utc
                )

            if completed_at.tzinfo is None:
                completed_at = completed_at.replace(
                    tzinfo=timezone.utc
                )

            duration_seconds = max(

                0,

                int(
                    (
                        completed_at
                        - started_at
                    ).total_seconds()
                )

            )

        report = {

            "report_id":
                str(
                    session["_id"]
                ),

            "session_id":
                str(
                    session["_id"]
                ),

            "user_id":
                user_id,

            "mode":
                "red",

            "attack":
                "ransomware",

            "guide_title":
                "Red Team — WannaCry-Inspired Ransomware",

            "result":
                "success",

            "incident":
                session.get(
                    "incident",
                    RED_RANSOMWARE_INCIDENT
                ),

            "target":
                session.get(
                    "selected_host"
                ),

            "score":
                session.get(
                    "score",
                    0
                ),

            "max_score":
                session.get(
                    "max_score",
                    RED_RANSOMWARE_MAX_SCORE
                ),

            "duration_seconds":
                duration_seconds,

            "total_stages":
                len(
                    RED_RANSOMWARE_STAGES
                ),

            "stages_completed":
                RED_RANSOMWARE_STAGES,

            "actions":
                session.get(
                    "actions",
                    []
                ),

            "state":
                session.get(
                    "state",
                    RED_RANSOMWARE_INITIAL_STATE
                ),

            "log_lines":
                session.get(
                    "events",
                    []
                ),

            "created_at":
                completed_at,

            "completed_at":
                completed_at,

        }

        safe_report = red_ransomware_json_safe(
            report
        )

        return jsonify({

            "success":
                True,

            "report":
                safe_report,

        }), 200

    except Exception as e:

        print(
            "Red ransomware report error:",
            e
        )

        return jsonify({

            "success":
                False,

            "error":
                str(e),

        }), 500


# ================================================================
#  BLUE TEAM — PHISHING INCIDENT RESPONSE (AI-driven scenarios)
# ================================================================
#
#  Scenario generation lives in ai/scenario_generator.py (local Ollama
#  model with validated template fallback); all simulation rules and
#  scoring are in blue_phishing/engine.py. The routes below only handle
#  authentication, ownership, persistence and serialisation. Ground truth
#  is stored on the session but never serialised to the browser until the
#  incident is closed and the report is generated.

BLUE_MAX_SCORE = blue_engine.MAX_SCORE
BLUE_STAGES = blue_engine.STAGES
BLUE_SCHEMA_VERSION = blue_schema.SCHEMA_VERSION
BLUE_MAX_BODY_BYTES = 8 * 1024

if os.getenv("BLUE_PHISHING_WARMUP", "true").strip().lower() not in ("0", "false", "no", "off"):
    # Load the local model in the background so the first incident is fast.
    blue_ai.warm_up_in_background()


def _blue_error(message, status, **extra):
    return jsonify({"success": False, "error": message, **extra}), status


def _blue_aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _blue_elapsed(session, end=None):
    started = _blue_aware(session.get("started_at"))
    end = _blue_aware(end or session.get("completed_at")) or datetime.now(timezone.utc)
    if not started:
        return 0
    return max(0, int((end - started).total_seconds()))


def _blue_is_current(session):
    """True for sessions created by the scenario engine (not the legacy fixed one)."""
    return bool(session) and session.get("schema_version") == BLUE_SCHEMA_VERSION \
        and "scenario" in session and "sim" in session


def _blue_generation_public(session):
    gen = session.get("generation") or {}
    return {
        "source": gen.get("source", "template"),
        "model": gen.get("model"),
        "fallback": bool(gen.get("fallback")),
        "fallback_reason": gen.get("fallback_reason"),
        "duration_ms": gen.get("duration_ms", 0),
    }


def _blue_view(session, **extra):
    """Analyst-visible payload for a session (no ground truth)."""
    view = blue_engine.public_view(
        session["scenario"], session["sim"], session["timeline"],
        elapsed_seconds=_blue_elapsed(session))
    view.update({
        "success": True,
        "session_id": str(session["_id"]),
        "generation": _blue_generation_public(session),
        "elapsed_seconds": _blue_elapsed(session),
    })
    view.update(extra)
    return view


def _blue_find_session(session_id, user_id):
    try:
        object_id = ObjectId(session_id)
    except (InvalidId, TypeError):
        return None, None, _blue_error("Invalid simulation session.", 400)
    session = db.blue_phishing_sessions.find_one({"_id": object_id, "user_id": user_id})
    if not session:
        return None, None, _blue_error("Simulation session not found.", 404)
    return object_id, session, None


def _blue_persist_fields(session_scenario, sim, timeline, elapsed):
    """Mongo fields that mirror the engine state (incl. legacy-compatible ones)."""
    view = blue_engine.public_view(session_scenario, sim, timeline, elapsed)
    return {
        "sim": sim,
        "timeline": timeline,
        "events": view["events"],
        "state": view["state"],
        "stage": view["stage"],
        "score": view["score"],
        "score_breakdown": view["score_breakdown"],
        "incident": view["incident"],
    }


@app.route("/api/blue-phishing/ai-status", methods=["GET"])
@jwt_required()
def blue_phishing_ai_status():
    status = blue_ai.ollama_status()
    status.pop("base_url", None)   # no infrastructure details to the browser
    return jsonify({"success": True, **status}), 200


@app.route("/api/blue-phishing/start", methods=["POST"])
@jwt_required()
def start_blue_phishing():

    try:
        user_id = get_jwt_identity()
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            body = {}

        generator = body.get("generator", "ai")
        if generator not in ("ai", "template"):
            return _blue_error("generator must be 'ai' or 'template'.", 400)
        archetype = body.get("archetype")
        if archetype is not None and archetype not in blue_schema.ARCHETYPES:
            return _blue_error("Unknown scenario type.", 400)

        existing = db.blue_phishing_sessions.find_one(
            {"user_id": user_id, "mode": "blue", "attack": "phishing",
             "status": "in_progress"},
            sort=[("updated_at", -1)])

        if existing:
            resumable = _blue_is_current(existing) and not body.get("restart")
            if resumable:
                return jsonify(_blue_view(existing, resumed=True)), 200
            db.blue_phishing_sessions.update_many(
                {"user_id": user_id, "mode": "blue", "attack": "phishing",
                 "status": "in_progress"},
                {"$set": {"status": "abandoned",
                          "abandoned_reason": ("restart_requested" if body.get("restart")
                                               else "legacy_format"),
                          "updated_at": datetime.now(timezone.utc)}})

        # Generate (or fall back) BEFORE touching the database so a model
        # failure can never leave a half-created session behind.
        try:
            scenario, meta = blue_ai.generate_scenario(
                preferred_archetype=archetype, use_ai=(generator == "ai"))
        except Exception as gen_error:  # noqa: BLE001 - last-resort safety net
            print("Blue phishing generation error:", type(gen_error).__name__)
            scenario = blue_templates.build_template_scenario(archetype)
            meta = {"source": "template", "model": None, "fallback": True,
                    "fallback_reason": "generator_error", "duration_ms": 0}

        # Another start (e.g. the user chose "use a built-in scenario" while a
        # slow model call was still running) may have created a session in
        # the meantime. Keep that one instead of creating a duplicate.
        raced = db.blue_phishing_sessions.find_one(
            {"user_id": user_id, "mode": "blue", "attack": "phishing",
             "status": "in_progress"},
            sort=[("updated_at", -1)])
        if raced and _blue_is_current(raced):
            return jsonify(_blue_view(raced, resumed=True)), 200

        now = datetime.now(timezone.utc)
        sim, timeline = blue_engine.new_sim(scenario, now)
        session = {
            "user_id": user_id,
            "mode": "blue",
            "attack": "phishing",
            "schema_version": BLUE_SCHEMA_VERSION,
            "scenario_id": scenario["scenario_id"],
            "scenario": scenario,          # includes hidden ground truth: server-side only
            "generation": meta,
            "max_score": BLUE_MAX_SCORE,
            "actions": [],
            "status": "in_progress",
            "version": 0,
            "started_at": now,
            "updated_at": now,
            "completed_at": None,
        }
        session.update(_blue_persist_fields(scenario, sim, timeline, 0))

        result = db.blue_phishing_sessions.insert_one(session)
        session["_id"] = result.inserted_id
        return jsonify(_blue_view(session, resumed=False)), 201

    except Exception as e:
        print("Blue phishing start error:", e)
        return _blue_error("Unable to start the Blue Team simulation.", 500)


@app.route("/api/blue-phishing/<session_id>/action", methods=["POST"])
@jwt_required()
def blue_phishing_action(session_id):

    try:
        user_id = get_jwt_identity()
        object_id, session, error = _blue_find_session(session_id, user_id)
        if error:
            return error

        if request.content_length and request.content_length > BLUE_MAX_BODY_BYTES:
            return _blue_error("Request too large.", 413)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _blue_error("A JSON body is required.", 400)

        if not _blue_is_current(session):
            return _blue_error(
                "This session was created by an older version of the simulation. "
                "Start a new incident.", 409, restart_required=True)
        if session.get("status") == "completed":
            return _blue_error("Simulation is already completed.", 400)
        if session.get("status") != "in_progress":
            return _blue_error("This incident is no longer active. Start a new one.", 409,
                               restart_required=True)

        scenario = session["scenario"]
        sim = blue_engine.clone(session["sim"])
        timeline = blue_engine.clone(session["timeline"])
        old_score = int(session.get("score", 0))
        now = datetime.now(timezone.utc)
        elapsed = _blue_elapsed(session, now)

        res = blue_engine.apply_action(
            scenario, sim, timeline,
            data.get("action"), data.get("target"), data.get("params"),
            now=now, elapsed_seconds=elapsed)

        if not res["persist"]:
            return jsonify({
                **_blue_view(session),
                "success": False, "error": res["error"],
                "confirmation_required": bool(res.get("confirmation_required")),
            }), res["http"]

        fields = _blue_persist_fields(scenario, sim, timeline, elapsed)
        status = "completed" if sim["closed"] else "in_progress"
        fields.update(status=status, updated_at=now, version=session["version"] + 1)
        if sim["closed"]:
            fields["completed_at"] = now
        if res["ok"]:
            fields["actions"] = list(session.get("actions", [])) + [{
                "action": data.get("action"),
                "target": data.get("target") if isinstance(data.get("target"), str) else None,
                "points": fields["score"] - old_score,
                "timestamp": now,
            }]

        # Optimistic concurrency: a concurrent request on the same session
        # must not double-apply score or evidence.
        written = db.blue_phishing_sessions.update_one(
            {"_id": object_id, "user_id": user_id, "version": session["version"]},
            {"$set": fields})
        if written.matched_count != 1:
            return _blue_error(
                "The session changed in another request. Reload and try again.", 409)

        session.update(fields)
        if sim["closed"]:
            # Persist the report immediately so it is never lost if the browser
            # is closed on the closure screen. AI commentary is added later by
            # /complete, which keeps this response fast.
            try:
                _blue_store_report(session, user_id, with_ai=False)
            except Exception as report_error:  # noqa: BLE001
                print("Blue phishing report save error:", report_error)
        new_ids = res["new_evidence"]
        view = _blue_view(
            session,
            message=res["message"] or None,
            feedback=res["feedback"],
            attacker_alerts=res["alerts"],
            new_evidence=[e for e in blue_engine.public_view(
                scenario, sim, timeline, elapsed)["evidence"] if e["id"] in new_ids],
            new_indicator_ids=res["new_indicators"],
            new_user_ids=res["new_users"],
            score_delta=fields["score"] - old_score,
            penalty_points=res["penalty_points"],
            verification=res.get("verification"),
            action=data.get("action"),
        )
        if not res["ok"]:
            view.update(success=False, error=res["error"])
            return jsonify(view), res["http"]
        return jsonify(view), 200

    except Exception as e:
        print("Blue phishing action error:", e)
        return _blue_error("Action could not be completed.", 500)


def _blue_report_doc(session, user_id, report_core, completed_at):
    scenario = session["scenario"]
    primary = next(u for u in scenario["target"]["users"]
                   if u["id"] == scenario["target"]["primary_user_id"])
    incident = dict(session.get("incident") or {})
    incident["classification"] = report_core["evaluation"]["classification"]["truth"]
    report = {
        **report_core,
        "user_id": user_id,
        "session_id": str(session["_id"]),
        "mode": "blue",
        "attack": "phishing",
        "guide_title": "Blue Team — Phishing Incident Response",
        "target": {k: primary[k] for k in ("name", "role", "department", "email", "endpoint")},
        "incident": incident,
        "total_stages": len(BLUE_STAGES),
        "stages_completed": BLUE_STAGES,
        "choices": [
            {"type": a.get("action"), "value": True, "points": a.get("points", 0)}
            for a in session.get("actions", [])
        ],
        "actions": session.get("actions", []),
        "scenario_id": session.get("scenario_id"),
        "schema_version": session.get("schema_version"),
        "generation": _blue_generation_public(session),
        "created_at": completed_at,
        "completed_at": completed_at,
    }
    return report


# ================================================================
#  RED TEAM — RANSOMWARE SIMULATION (fictional, sandboxed)
# ================================================================

RR_HOST_IDS = ["pc-014", "lab-008", "file-01", "backup-01", "dc-01", "hr-022"]

# action -> (required current stage or None, next stage or None, points)
RR_ACTIONS = {
    "scan_network":          {"stage": "recon",         "next": "vulnerability", "points": 100},
    "inspect_host":          {"stage": None,             "next": None,            "points": 0},
    "identify_vulnerability":{"stage": "vulnerability",  "next": "execution",     "points": 150},
    "simulate_execution":    {"stage": "execution",      "next": "propagation",   "points": 150},
    "start_propagation":     {"stage": "propagation",    "next": "compromise",    "points": 150},
    "compromise_hosts":      {"stage": "compromise",     "next": "encryption",    "points": 150},
    "simulate_encryption":   {"stage": "encryption",     "next": "impact",        "points": 200},
    "assess_impact":         {"stage": "impact",         "next": None,            "points": 100},
}


@app.route("/api/red-ransomware/start", methods=["POST"])
@jwt_required()
def rr_start():
    user_id = get_jwt_identity()
    session = {
        "user_id": user_id,
        "stage": "recon",
        "score": 0,
        "completed_actions": [],
        "status": "in_progress",
        "started_at": datetime.utcnow().isoformat()
    }
    result = db.red_ransomware_sessions.insert_one(session)
    return jsonify({
        "session_id": str(result.inserted_id),
        "score": 0,
        "stage": "recon"
    }), 201


@app.route("/api/red-ransomware/<session_id>/action", methods=["POST"])
@jwt_required()
def rr_action(session_id):
    try:
        obj_id = ObjectId(session_id)
    except InvalidId:
        return jsonify({"error": "Invalid session ID"}), 400

    session = db.red_ransomware_sessions.find_one({"_id": obj_id})
    if not session:
        return jsonify({"error": "Session not found"}), 404
    if session["status"] != "in_progress":
        return jsonify({"error": "Simulation already ended"}), 400

    data = request.get_json() or {}
    action = data.get("action")
    host_id = data.get("host_id")

    config = RR_ACTIONS.get(action)
    if not config:
        return jsonify({"error": "Unknown action"}), 400

    completed = session.get("completed_actions", [])
    score = session.get("score", 0)
    stage = session.get("stage", "recon")

    # Award points once per unique action per session (prevents farming by re-clicking)
    already_done = action in completed
    if not already_done and config["points"] > 0:
        completed.append(action)
        score += config["points"]

    if config["next"] and not already_done:
        stage = config["next"]

    db.red_ransomware_sessions.update_one(
        {"_id": obj_id},
        {"$set": {"completed_actions": completed, "score": score, "stage": stage}}
    )

    response = {
        "score": score,
        "stage": stage,
        "next_stage": stage
    }

    if action == "scan_network":
        response["discovered_hosts"] = RR_HOST_IDS

    return jsonify(response), 200


@app.route("/api/red-ransomware/<session_id>/complete", methods=["POST"])
@jwt_required()
def rr_complete(session_id):
    try:
        obj_id = ObjectId(session_id)
    except InvalidId:
        return jsonify({"error": "Invalid session ID"}), 400

    session = db.red_ransomware_sessions.find_one({"_id": obj_id})
    if not session:
        return jsonify({"error": "Session not found"}), 404

    db.red_ransomware_sessions.update_one(
        {"_id": obj_id},
        {"$set": {"status": "completed", "completed_at": datetime.utcnow().isoformat()}}
    )
    return jsonify({"message": "Simulation marked complete"}), 200


@app.route("/api/red-ransomware/<session_id>/report", methods=["GET"])
@jwt_required()
def rr_report(session_id):
    try:
        obj_id = ObjectId(session_id)
    except InvalidId:
        return jsonify({"error": "Invalid session ID"}), 400

    session = db.red_ransomware_sessions.find_one({"_id": obj_id})
    if not session:
        return jsonify({"error": "Session not found"}), 404

    actions = session.get("completed_actions", [])
    score = session.get("score", 0)

    compromised = 1 if "compromise_hosts" in actions or "simulate_execution" in actions else 0
    encrypted = 1 if "simulate_encryption" in actions else 0
    severity = "CRITICAL" if encrypted and score >= 700 else "HIGH" if encrypted else "MEDIUM" if compromised else "LOW"

    started = session.get("started_at")
    completed_at = session.get("completed_at")
    duration_seconds = None
    if started and completed_at:
        duration_seconds = (datetime.fromisoformat(completed_at) - datetime.fromisoformat(started)).total_seconds()

    report = {
        "session_id": str(session["_id"]),
        "mode": "red",
        "attack": "ransomware",
        "environment": "Northbridge Health Network (fictional)",
        "final_stage": session.get("stage"),
        "score": score,
        "max_score": 1000,
        "completed_actions": actions,
        "compromised_hosts": compromised,
        "encrypted_hosts": encrypted,
        "severity": severity,
        "duration_seconds": duration_seconds,
        "status": session.get("status"),
        "note": "All systems, hosts, and data in this simulation are fictional. No real exploitation or encryption occurred."
    }

    # Save to shared reports collection too, so it shows up on the Dashboard
    db.reports.insert_one({
        "user_id": session["user_id"],
        "mode": "red",
        "attack": "ransomware",
        "guide_title": "Ransomware (Simulated Network Exercise)",
        "result": "success" if session.get("stage") == "impact" else "incomplete",
        "score": score,
        "max_score": 1000,
        "choices": [],
        "log_lines": actions,
        "created_at": datetime.utcnow().isoformat()
    })

    return jsonify({"report": report}), 200



@app.route("/api/blue-phishing/<session_id>/query", methods=["POST"])
@jwt_required()
def blue_phishing_query(session_id):
    """Read-only SIEM / log search over the simulated dataset. It never
    changes simulation state, and only returns rows for users the analyst
    has already identified."""

    try:
        user_id = get_jwt_identity()
        object_id, session, error = _blue_find_session(session_id, user_id)
        if error:
            return error
        if request.content_length and request.content_length > BLUE_MAX_BODY_BYTES:
            return _blue_error("Request too large.", 413)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _blue_error("A JSON body is required.", 400)
        if not _blue_is_current(session):
            return _blue_error("This session predates the current simulation.", 409,
                               restart_required=True)
        try:
            result = blue_engine.query_logs(
                session["scenario"], session["sim"],
                source=data.get("source"), filters=data.get("filters"))
        except ValueError as bad:
            return _blue_error(str(bad), 400)
        return jsonify({"success": True, **result}), 200

    except Exception as e:
        print("Blue phishing query error:", e)
        return _blue_error("Unable to run the search.", 500)


@app.route("/api/blue-phishing/<session_id>/hint", methods=["POST"])
@jwt_required()
def blue_phishing_hint(session_id):
    """Optional coaching hint. Built only from what the analyst can already
    see; a null hint tells the client to use its built-in hint."""

    try:
        user_id = get_jwt_identity()
        _, session, error = _blue_find_session(session_id, user_id)
        if error:
            return error
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _blue_error("A JSON body is required.", 400)
        if not _blue_is_current(session):
            return _blue_error("This session predates the current simulation.", 409,
                               restart_required=True)
        level = data.get("level")
        step = str(data.get("step", ""))[:60]
        title = str(data.get("title", ""))[:80]
        if level not in (1, 2, 3):
            return _blue_error("Choose hint level 1, 2 or 3.", 400)
        view = _blue_view(session)
        context = {
            "step": title or step,
            "email_subject": view["email"].get("subject") if view["email"].get("opened") else None,
            "clues_found": [{"title": e["title"], "summary": (e["content"].get("summary") or "")[:160]}
                            for e in view["evidence"][-8:]],
            "indicators_found": len(view["indicators"]),
            "users_identified": len(view["users"]),
        }
        hint = blue_ai.generate_hint(context, level) if not view["closed"] else None
        return jsonify({"success": True, "hint": hint, "source": "ai" if hint else "builtin"}), 200

    except Exception as e:
        print("Blue phishing hint error:", e)
        return jsonify({"success": True, "hint": None, "source": "builtin"}), 200


def _blue_store_report(session, user_id, with_ai=False):
    """Build the authoritative report from the closed session and upsert it
    (one report per session). Optional AI commentary is validated, never used
    for scoring, and reused if it already exists."""
    completed_at = session.get("completed_at") or datetime.now(timezone.utc)
    elapsed = _blue_elapsed(session, completed_at)
    report_core = blue_engine.build_report(
        session["scenario"], session["sim"], session["timeline"], elapsed,
        generation=_blue_generation_public(session))
    report = _blue_report_doc(session, user_id, report_core, completed_at)

    key = {"session_id": str(session["_id"]), "user_id": user_id}
    existing = db.blue_phishing_reports.find_one(key)
    commentary = ((existing or {}).get("debrief") or {}).get("ai_commentary")
    if commentary is None and with_ai and session["scenario"].get("source") == "ollama":
        commentary = blue_ai.generate_debrief({
            "outcome": report["outcome"], "score": report["score"],
            "classification_correct": report["evaluation"]["classification"]["correct"],
            "missed_evidence": [m["title"] for m in report["evaluation"]["missed_evidence"]],
            "mistakes": [p["code"] for p in report["evaluation"]["incorrect_decisions"]],
            "scenario": session["scenario"]["title"],
        })
    if commentary:
        report["debrief"]["ai_commentary"] = commentary

    db.blue_phishing_reports.update_one(key, {"$set": report}, upsert=True)
    saved = db.blue_phishing_reports.find_one(key)
    report.pop("_id", None)
    return str(saved["_id"]), report


@app.route("/api/blue-phishing/<session_id>/complete", methods=["POST"])
@jwt_required()
def complete_blue_phishing(session_id):

    try:
        user_id = get_jwt_identity()
        object_id, session, error = _blue_find_session(session_id, user_id)
        if error:
            return error
        if not _blue_is_current(session):
            return _blue_error("This session predates the current simulation.", 409,
                               restart_required=True)

        if not session["sim"].get("closed"):
            return _blue_error(
                "Complete the incident before generating the final report.", 400)

        if not session.get("completed_at"):
            now = datetime.now(timezone.utc)
            db.blue_phishing_sessions.update_one(
                {"_id": object_id, "user_id": user_id},
                {"$set": {"completed_at": now, "status": "completed", "updated_at": now}})
            session["completed_at"] = now

        report_id, report = _blue_store_report(session, user_id, with_ai=True)
        return jsonify({
            "success": True,
            "message": "Blue Team phishing report saved",
            "report_id": report_id,
            "report": report,
        }), 200

    except Exception as e:
        print("Blue phishing completion error:", e)
        return _blue_error("Unable to generate the report.", 500)


@app.route("/api/blue-phishing/<session_id>/report", methods=["GET"])
@jwt_required()
def get_blue_phishing_report(session_id):

    try:
        user_id = get_jwt_identity()

        report = db.blue_phishing_reports.find_one(
            {"session_id": session_id, "user_id": user_id})
        if report:
            report["_id"] = str(report["_id"])
            report["report_id"] = report["_id"]
            return jsonify({"success": True, "report": report}), 200

        object_id, session, error = _blue_find_session(session_id, user_id)
        if error:
            return error
        if not _blue_is_current(session) or not session["sim"].get("closed"):
            return _blue_error("Simulation has not been completed yet.", 400)

        completed_at = session.get("completed_at") or session.get("updated_at")
        report_core = blue_engine.build_report(
            session["scenario"], session["sim"], session["timeline"],
            _blue_elapsed(session, completed_at),
            generation=_blue_generation_public(session))
        report = _blue_report_doc(session, user_id, report_core, completed_at)
        report["report_id"] = str(session["_id"])
        return jsonify({"success": True, "report": report}), 200

    except Exception as e:
        print("Blue phishing report error:", e)
        return _blue_error("Unable to load the report.", 500)


# ================================================================
#  AUTH ROUTES
# ================================================================

@app.route(
    "/api/auth/register",
    methods=["POST"]
)
def register():

    data = request.get_json()

    email = data.get(
        "email",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    name = data.get(
        "name",
        ""
    ).strip()


    if not email or not password or not name:

        return jsonify({

            "error":
                "All fields are required"

        }), 400


    if db.users.find_one(
        {
            "email":
                email
        }
    ):

        return jsonify({

            "error":
                "Email already registered"

        }), 409


    hashed = bcrypt.hashpw(

        password.encode(
            "utf-8"
        ),

        bcrypt.gensalt()

    )


    db.users.insert_one({

        "name":
            name,

        "email":
            email,

        "password":
            hashed,

        "role":
            "student"

    })


    return jsonify({

        "message":
            "Account created successfully"

    }), 201


@app.route(
    "/api/auth/login",
    methods=["POST"]
)
def login():

    data = request.get_json()

    email = data.get(
        "email",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )


    if not email or not password:

        return jsonify({

            "error":
                "Email and password are required"

        }), 400


    user = db.users.find_one(
        {
            "email":
                email
        }
    )


    if not user:

        return jsonify({

            "error":
                "Invalid email or password"

        }), 401


    if not bcrypt.checkpw(

        password.encode(
            "utf-8"
        ),

        user["password"]

    ):

        return jsonify({

            "error":
                "Invalid email or password"

        }), 401


    token = create_access_token(

        identity=str(
            user["_id"]
        )

    )


    return jsonify({

        "message":
            "Login successful",

        "token":
            token,

        "user": {

            "name":
                user["name"],

            "email":
                user["email"],

            "role":
                user["role"]

        }

    }), 200


@app.route("/api/auth/guest", methods=["POST"])
def guest_login():
    # Create a unique temporary identity for every Guest login.
    guest_id = f"guest-{uuid.uuid4()}"

    token = create_access_token(
        identity=guest_id
    )

    return jsonify({
        "message": "Continuing as guest",
        "token": token,
        "user": {
            "name": "Guest",
            "email": "",
            "role": "guest"
        }
    }), 200


# ================================================================
#  LEGACY SIMULATION ROUTES
#  AlertQueue / demo flow
# ================================================================

@app.route(
    "/api/simulation",
    methods=["GET"]
)
@jwt_required()
def get_simulations():

    sims = list(
        db.simulations.find(
            {},
            {
                "_id":
                    0
            }
        )
    )


    return jsonify({

        "simulations":
            sims

    }), 200


@app.route(
    "/api/simulation/start-legacy",
    methods=["POST"]
)
@jwt_required()
def start_simulation_legacy():

    data = request.get_json()

    attack_type = data.get(
        "attack_type",
        "Unknown"
    )

    user_id = get_jwt_identity()


    sim = {

        "user_id":
            user_id,

        "attack_type":
            attack_type,

        "status":
            "Running",

        "stage":
            "Reconnaissance",

        "logs":
            []

    }


    result = db.simulations.insert_one(
        sim
    )


    return jsonify({

        "message":
            f"{attack_type} simulation started",

        "simulation_id":
            str(
                result.inserted_id
            )

    }), 201


@app.route(
    "/api/simulation/stop",
    methods=["POST"]
)
@jwt_required()
def stop_simulation():

    data = request.get_json()

    sim_id = data.get(
        "simulation_id"
    )


    db.simulations.update_one(

        {
            "_id":
                ObjectId(sim_id)
        },

        {
            "$set": {
                "status":
                    "Stopped"
            }
        }

    )


    return jsonify({

        "message":
            "Simulation stopped"

    }), 200


# ================================================================
#  SIMULATION REPORTS
# ================================================================

@app.route(
    "/api/simulation/report",
    methods=["POST"]
)
@jwt_required()
def save_simulation_report():

    user_id = get_jwt_identity()

    data = request.get_json()


    report = {

        "user_id":
            user_id,

        "mode":
            data.get("mode"),

        "attack":
            data.get("attack"),

        "guide_title":
            data.get("guideTitle"),

        "result":
            data.get("result"),

        "failed_at_stage":
            data.get("failedAtStage"),

        "total_stages":
            data.get("totalStages"),

        "stages_completed":
            data.get("stagesCompleted"),

        "score":
            data.get("score"),

        "max_score":
            data.get("maxScore"),

        "duration_seconds":
            data.get("durationSeconds"),

        "choices":
            data.get(
                "choices",
                []
            ),

        "log_lines":
            data.get(
                "logLines",
                []
            ),

        "created_at":
            datetime.utcnow().isoformat()

    }


    result = db.reports.insert_one(
        report
    )


    return jsonify({

        "message":
            "Report saved",

        "report_id":
            str(
                result.inserted_id
            )

    }), 201


@app.route("/api/simulation/reports", methods=["GET"])
@jwt_required()
def get_my_reports():
    user_id = get_jwt_identity()

    # Normal simulation reports belonging to this user
    reports = list(
        db.reports.find({
            "user_id": user_id
        })
    )

    # Red Phishing reports belonging to this user
    red_phishing_reports = list(
        db.simulation_reports.find({
            "user_id": user_id
        })
    )

    # Blue Phishing reports belonging to this user
    blue_phishing_reports = list(
        db.blue_phishing_reports.find({
            "user_id": user_id
        })
    )

    # Combine only this user's reports
    all_reports = (
        reports
        + red_phishing_reports
        + blue_phishing_reports
    )

    # Newest first
    all_reports.sort(
        key=lambda r: str(
            r.get("created_at", "")
        ),
        reverse=True
    )

    # Convert MongoDB ObjectIds to strings
    for report in all_reports:
        report["_id"] = str(report["_id"])

    return jsonify({
        "reports": all_reports
    }), 200


@app.route(
    "/api/simulation/report/<report_id>",
    methods=["GET"]
)
@jwt_required()
def get_report(report_id):

    try:

        obj_id = ObjectId(
            report_id
        )

    except InvalidId:

        return jsonify({

            "error":
                "Invalid report ID"

        }), 400


    report = db.reports.find_one(

        {
            "_id":
                obj_id
        }

    )


    if not report:

        return jsonify({

            "error":
                "Report not found"

        }), 404


    report["_id"] = str(
        report["_id"]
    )


    return jsonify({

        "report":
            report

    }), 200


# ================================================================
#  KILL CHAIN
#  demo/legacy - kept for compatibility
# ================================================================

KILL_CHAIN_STAGES = [

    "Reconnaissance",

    "Weaponization",

    "Delivery",

    "Exploitation",

    "Installation",

    "Command & Control",

    "Actions on Objectives"

]


PHISHING_SEED_STAGES = {

    "Reconnaissance": {

        "description":
            "Attacker gathers employee emails.",

        "mitre_id":
            "TA0043",

        "timestamp":
            "09:01",

        "logs":
            []

    },

    "Weaponization": {

        "description":
            "Attacker crafts a phishing email.",

        "mitre_id":
            "TA0001",

        "timestamp":
            "09:03",

        "logs":
            []

    },

    "Delivery": {

        "description":
            "The phishing email is sent.",

        "mitre_id":
            "T1566.001",

        "timestamp":
            "09:06",

        "logs":
            []

    },

    "Exploitation": {

        "description":
            "Victim clicks the link.",

        "mitre_id":
            "T1204.001",

        "timestamp":
            "09:08",

        "logs":
            []

    },

    "Installation": {

        "description":
            "Attacker installs a backdoor.",

        "mitre_id":
            "T1505",

        "timestamp":
            "09:10",

        "logs":
            []

    },

    "Command & Control": {

        "description":
            "Backdoor connects to C2.",

        "mitre_id":
            "TA0011",

        "timestamp":
            "09:14",

        "logs":
            []

    },

    "Actions on Objectives": {

        "description":
            "Attacker exfiltrates data.",

        "mitre_id":
            "TA0010",

        "timestamp":
            "09:18",

        "logs":
            []

    }

}


@app.route(
    "/api/simulation/seed-demo",
    methods=["POST"]
)
@jwt_required()
def seed_demo_simulation():

    user_id = get_jwt_identity()


    sim = {

        "user_id":
            user_id,

        "attack_type":
            "Phishing",

        "status":
            "Running",

        "stage":
            "Command & Control",

        "stage_details":
            PHISHING_SEED_STAGES,

        "logs":
            []

    }


    result = db.simulations.insert_one(
        sim
    )


    return jsonify({

        "message":
            "Demo phishing simulation created",

        "simulation_id":
            str(
                result.inserted_id
            )

    }), 201


@app.route(
    "/api/killchain/<simulation_id>",
    methods=["GET"]
)
@jwt_required()
def get_kill_chain(simulation_id):

    try:

        obj_id = ObjectId(
            simulation_id
        )

    except InvalidId:

        return jsonify({

            "error":
                "Invalid simulation ID"

        }), 400


    sim = db.simulations.find_one(

        {
            "_id":
                obj_id
        }

    )


    if not sim:

        return jsonify({

            "error":
                "Simulation not found"

        }), 404


    current_stage_name = sim.get(

        "stage",

        "Reconnaissance"

    )


    current_stage_index = (

        KILL_CHAIN_STAGES.index(
            current_stage_name
        )

        if current_stage_name
        in KILL_CHAIN_STAGES

        else 0

    )


    stage_details = sim.get(
        "stage_details",
        {}
    )


    stages = []


    for i, stage_name in enumerate(
        KILL_CHAIN_STAGES
    ):

        if i < current_stage_index:

            status = "completed"

        elif i == current_stage_index:

            status = "active"

        else:

            status = "pending"


        detail = stage_details.get(
            stage_name,
            {}
        )


        stages.append({

            "id":
                i,

            "name":
                stage_name,

            "status":
                status,

            "description":
                detail.get(
                    "description",
                    ""
                ),

            "mitre_id":
                detail.get(
                    "mitre_id",
                    ""
                ),

            "timestamp":
                detail.get(
                    "timestamp"
                ),

            "logs":
                detail.get(
                    "logs",
                    []
                )

        })


    return jsonify({

        "simulation_id":
            str(
                sim["_id"]
            ),

        "attack_type":
            sim.get(
                "attack_type"
            ),

        "status":
            sim.get(
                "status"
            ),

        "stages":
            stages

    }), 200


# ================================================================
#  LOGS ROUTES
# ================================================================

@app.route(
    "/api/logs",
    methods=["GET"]
)
@jwt_required()
def get_logs():

    logs = list(

        db.logs.find(

            {},

            {
                "_id":
                    0
            }

        )

    )


    return jsonify({

        "logs":
            logs

    }), 200


@app.route(
    "/api/logs/add",
    methods=["POST"]
)
@jwt_required()
def add_log():

    data = request.get_json()


    db.logs.insert_one({

        "message":
            data.get(
                "message"
            ),

        "severity":
            data.get(
                "severity",
                "INFO"
            ),

        "source":
            data.get(
                "source",
                "System"
            ),

    })


    return jsonify({

        "message":
            "Log added"

    }), 201


# ================================================================
#  DASHBOARD STATS
# ================================================================

@app.route(
    "/api/dashboard/stats",
    methods=["GET"]
)
@jwt_required()
def dashboard_stats():

    user_id = get_jwt_identity()


    return jsonify({

        "total_logs":
            db.logs.count_documents({}),

        "active_simulations":
            db.simulations.count_documents(
                {
                    "status":
                        "Running"
                }
            ),

        "total_simulations":
            db.simulations.count_documents({}),

        "reports_completed":
    (
        db.reports.count_documents({
            "user_id": user_id
        })
        +
        db.simulation_reports.count_documents({
            "user_id": user_id
        })
        +
        db.blue_phishing_reports.count_documents({
            "user_id": user_id
        })
    ),

        "threat_level":
            "High",

        "success_rate":
            87

   }), 200


# ================================================================
#  SCENARIOS
#  new backend-driven simulation engine
# ================================================================

@app.route(
    "/api/scenarios/<mode>/<attack>",
    methods=["GET"]
)
@jwt_required()
def get_scenario(
    mode,
    attack
):

    scenario = db.scenarios.find_one(

        {
            "mode":
                mode,

            "attack":
                attack
        }

    )


    if not scenario:

        return jsonify({

            "error":
                "Scenario not found"

        }), 404


    # Strip outcome/feedback/hint from options —
    # client only gets id + text

    safe_stages = []


    for stage in scenario["stages"]:

        safe_options = [

            {
                "id":
                    opt["id"],

                "text":
                    opt["text"]

            }

            for opt
            in stage["challenge"]["options"]

        ]


        safe_stages.append({

            "stageId":
                stage["stageId"],

            "name":
                stage["name"],

            "narrative":
                stage["narrative"],

            "mitre":
                stage["mitre"],

            "challenge": {

                "prompt":
                    stage["challenge"]["prompt"],

                "options":
                    safe_options

            }

        })


    return jsonify({

        "title":
            scenario["title"],

        "headline":
            scenario["headline"],

        "overview":
            scenario["overview"],

        "targets":
            scenario["targets"],

        "tips":
            scenario["tips"],

        "stages":
            safe_stages

    }), 200


@app.route(
    "/api/simulation/start",
    methods=["POST"]
)
@jwt_required()
def start_simulation():

    data = request.get_json()

    mode = data.get(
        "mode"
    )

    attack = data.get(
        "attack"
    )

    user_id = get_jwt_identity()


    scenario = db.scenarios.find_one(

        {
            "mode":
                mode,

            "attack":
                attack
        }

    )


    if not scenario:

        return jsonify({

            "error":
                "Scenario not found"

        }), 404


    session = {

        "user_id":
            user_id,

        "mode":
            mode,

        "attack":
            attack,

        "scenario_id":
            scenario["_id"],

        "current_stage_idx":
            0,

        "choices":
            [],

        "log_lines":
            [],

        "status":
            "in_progress",

        "started_at":
            datetime.utcnow().isoformat()

    }


    result = (
        db.simulation_sessions.insert_one(
            session
        )
    )


    return jsonify({

        "session_id":
            str(
                result.inserted_id
            ),

        "total_stages":
            len(
                scenario["stages"]
            )

    }), 201


@app.route(
    "/api/simulation/<session_id>/choice",
    methods=["POST"]
)
@jwt_required()
def submit_choice(session_id):

    data = request.get_json()

    option_id = data.get(
        "optionId"
    )


    try:

        obj_id = ObjectId(
            session_id
        )

    except InvalidId:

        return jsonify({

            "error":
                "Invalid session ID"

        }), 400


    session = db.simulation_sessions.find_one(

        {
            "_id":
                obj_id
        }

    )


    if not session:

        return jsonify({

            "error":
                "Session not found"

        }), 404


    if session["status"] != "in_progress":

        return jsonify({

            "error":
                "Simulation already ended"

        }), 400


    scenario = db.scenarios.find_one(

        {
            "_id":
                session["scenario_id"]
        }

    )


    stage_idx = session[
        "current_stage_idx"
    ]


    stage = scenario[
        "stages"
    ][stage_idx]


    chosen_option = next(

        (
            o

            for o
            in stage["challenge"]["options"]

            if o["id"] == option_id

        ),

        None

    )


    if not chosen_option:

        return jsonify({

            "error":
                "Invalid option"

        }), 400


    points_map = {

        "best":
            10,

        "risky":
            5,

        "fail":
            0

    }


    points = points_map[
        chosen_option["outcome"]
    ]


    db.simulation_sessions.update_one(

        {
            "_id":
                session["_id"]
        },

        {

            "$push": {

                "choices": {

                    "stageId":
                        stage["stageId"],

                    "optionId":
                        option_id,

                    "outcome":
                        chosen_option["outcome"],

                    "points":
                        points

                },

                "log_lines":
                    stage["log"]

            }

        }

    )


    ended = (
        chosen_option["outcome"]
        == "fail"
    )


    next_stage_idx = (
        stage_idx + 1
    )


    is_last_stage = (
        next_stage_idx
        >= len(
            scenario["stages"]
        )
    )


    if ended or is_last_stage:

        db.simulation_sessions.update_one(

            {
                "_id":
                    session["_id"]
            },

            {

                "$set": {

                    "status":
                        "failed"
                        if ended
                        else "completed"

                }

            }

        )

    else:

        db.simulation_sessions.update_one(

            {
                "_id":
                    session["_id"]
            },

            {

                "$set": {

                    "current_stage_idx":
                        next_stage_idx

                }

            }

        )


    return jsonify({

        "outcome":
            chosen_option["outcome"],

        "feedback":
            chosen_option["feedback"],

        "points":
            points,

        "log":
            stage["log"],

        "ended":
            ended or is_last_stage,

        "nextStageIdx":

            None
            if (
                ended
                or is_last_stage
            )

            else
            next_stage_idx

    }), 200


@app.route(
    "/api/simulation/<session_id>/complete",
    methods=["POST"]
)
@jwt_required()
def complete_simulation(session_id):

    try:

        obj_id = ObjectId(
            session_id
        )

    except InvalidId:

        return jsonify({

            "error":
                "Invalid session ID"

        }), 400


    user_id = get_jwt_identity()


    session = db.simulation_sessions.find_one(

        {
            "_id":
                obj_id,

            "user_id":
                user_id

        }

    )


    if not session:

        return jsonify({

            "error":
                "Simulation session not found"

        }), 404


    if session.get(
        "status"
    ) == "in_progress":

        return jsonify({

            "error":
                "Simulation is not finished yet"

        }), 400


    scenario = db.scenarios.find_one(

        {
            "_id":
                session["scenario_id"]
        }

    )


    if not scenario:

        return jsonify({

            "error":
                "Scenario not found"

        }), 404


    choices = session.get(
        "choices",
        []
    )


    total_points = sum(

        c.get(
            "points",
            0
        )

        for c in choices

    )


    max_points = (
        len(
            scenario.get(
                "stages",
                []
            )
        )
        * 10
    )


    result = (

        "success"

        if session.get(
            "status"
        ) == "completed"

        else "fail"

    )


    stages_completed = len(
        choices
    )


    report = {

        "user_id":
            user_id,

        "mode":
            session.get(
                "mode"
            ),

        "attack":
            session.get(
                "attack"
            ),

        "guide_title":
            scenario.get(
                "title"
            ),

        "result":
            result,

        "failed_at_stage": (

            choices[-1].get(
                "stageId"
            )

            if result == "fail"
            and choices

            else None

        ),

        "total_stages":
            len(
                scenario.get(
                    "stages",
                    []
                )
            ),

        "stages_completed":
            stages_completed,

        "score":
            total_points,

        "max_score":
            max_points,

        "duration_seconds":
            0,

        "choices":
            choices,

        "log_lines":
            session.get(
                "log_lines",
                []
            ),

        "created_at":
            datetime.utcnow().isoformat()

    }


    result_insert = (
        db.reports.insert_one(
            report
        )
    )


    report["_id"] = str(
        result_insert.inserted_id
    )


    return jsonify({

        "message":
            "Report saved",

        "score":
            total_points,

        "report":
            report

    }), 200


# ================================================================
#  LEARN HUB
# ================================================================

@app.route(
    "/api/learn/articles",
    methods=["GET"]
)
@jwt_required()
def get_learn_articles():

    category = request.args.get(
        "category"
    )


    query = (

        {
            "category":
                category
        }

        if category

        else {}

    )


    articles = list(

        db.learn_articles.find(

            query,

            {
                "content":
                    0,

                "furtherReading":
                    0

            }

        )

    )


    for a in articles:

        a["_id"] = str(
            a["_id"]
        )


    return jsonify({

        "articles":
            articles

    }), 200


@app.route(
    "/api/learn/articles/<slug>",
    methods=["GET"]
)
@jwt_required()
def get_learn_article(slug):

    article = db.learn_articles.find_one(

        {
            "slug":
                slug
        }

    )


    if not article:

        return jsonify({

            "error":
                "Article not found"

        }), 404


    article["_id"] = str(
        article["_id"]
    )


    return jsonify({

        "article":
            article

    }), 200


@app.route(
    "/api/learn/categories",
    methods=["GET"]
)
@jwt_required()
def get_learn_categories():

    categories = (
        db.learn_articles.distinct(
            "category"
        )
    )

    return jsonify({

        "categories":
            categories

    }), 200


# ================================================================
#  HEALTH CHECK
# ================================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health_check():

    return jsonify({

        "status":
            "running",

        "project":
            "Sentinel",

        "version":
            "1.0.0"

    }), 200


# ================================================================
#  RUN SERVER
# ================================================================

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            5000
        )
    )

    debug = (
        os.getenv(
            "FLASK_ENV"
        )
        == "development"
    )


    app.run(

        debug=debug,

        host="0.0.0.0",

        port=port

    )
    
    
# backend/seed_scenarios.py
"""
One-time migration script: moves hardcoded frontend guide data
into MongoDB's `scenarios` collection.

Run once: python seed_scenarios.py
"""

from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))
db = client.get_database("sentinel")

# ============================================================
#  RED / PHISHING
# ============================================================
red_phishing = {
    "mode": "red",
    "attack": "phishing",
    "title": "Phishing",
    "headline": "Get one click. That's all it takes.",
    "overview": "Phishing exploits trust, not systems. Your job is to craft a lure believable enough that a target hands over credentials or executes a payload without a second thought.",
    "targets": [
        "Employee email accounts",
        "Login credentials for internal tools",
        "Any user with access to sensitive systems"
    ],
    "tips": [
        "Urgency and authority work better than technical sophistication.",
        "Match the sender domain as closely as possible.",
        "Never reuse the same lure twice in one engagement."
    ],
    "stages": [
        {
            "stageId": "reconnaissance",
            "name": "Reconnaissance",
            "narrative": None,
            "mitre": "T1589",
            "challenge": {
                "prompt": "Pick your recon method to identify a target.",
                "options": [
                    {"id": "a", "text": "Check LinkedIn for employee names, roles, and org structure", "outcome": "best", "feedback": "Passive, low-risk, and gives you exactly what you need to write a believable pretext."},
                    {"id": "b", "text": "Call the company help desk pretending to be an employee", "outcome": "fail", "feedback": "The help desk logs the call and flags it internally. Your engagement is burned before you send a single email.", "hint": "Direct contact this early creates a paper trail. Stay passive during recon."},
                    {"id": "c", "text": "Guess emails using firstname.lastname@company.com pattern", "outcome": "risky", "feedback": "It often works, but you have no confirmation you've got the right person or that the account is even active."}
                ]
            },
            "log": "INFO  Recon started — target identified via passive OSINT"
        },
        {
            "stageId": "weaponization",
            "name": "Weaponization",
            "narrative": "Lure",
            "mitre": "T1587",
            "challenge": {
                "prompt": "Choose your lure format.",
                "options": [
                    {"id": "a", "text": "Fake IT password-reset email using the company's real branding", "outcome": "best", "feedback": "Familiar branding lowers suspicion instantly — this is the highest-converting lure format."},
                    {"id": "b", "text": "\"You've won a prize!\" email", "outcome": "fail", "feedback": "Obvious spam. Most mail clients flag it before it even reaches the inbox, and no employee trusts it.", "hint": "Your lure needs to look like something the target expects to receive."},
                    {"id": "c", "text": "PDF invoice with an embedded macro", "outcome": "risky", "feedback": "Can work, but modern attachment scanners catch macro-enabled documents more often than not."}
                ]
            },
            "log": "INFO  Phishing template generated — impersonating IT support"
        },
        {
            "stageId": "delivery",
            "name": "Delivery",
            "narrative": "Bait",
            "mitre": "T1566.001",
            "challenge": {
                "prompt": "Which sender domain do you use to deliver the email?",
                "options": [
                    {"id": "a", "text": "it-support@companyname-secure.com (typosquatted domain)", "outcome": "best", "feedback": "Close enough to the real domain that most targets won't look twice."},
                    {"id": "b", "text": "randomguy123@gmail.com", "outcome": "fail", "feedback": "A free personal email address claiming to be \"IT Support\" is an instant red flag. Deleted on sight.", "hint": "Your domain needs to look like it belongs to the organization, not a stranger."},
                    {"id": "c", "text": "A domain already flagged by threat intel from a past campaign", "outcome": "risky", "feedback": "Many mail filters already block it — it might land in spam before the target ever sees it."}
                ]
            },
            "log": "SUCCESS  Email delivered — urgent password reset request, spam filter bypassed"
        },
        {
            "stageId": "exploitation",
            "name": "Exploitation",
            "narrative": "Trap",
            "mitre": "T1204.001",
            "challenge": {
                "prompt": "The target opened the email. What's your call-to-action?",
                "options": [
                    {"id": "a", "text": "\"Your password expires in 1 hour — reset now\" with urgency", "outcome": "best", "feedback": "Urgency short-circuits careful thinking. This is the highest click-through pattern in real phishing data."},
                    {"id": "b", "text": "\"Click here to unsubscribe\"", "outcome": "fail", "feedback": "No urgency, no incentive — almost nobody clicks, and you get no credentials.", "hint": "Give the target a reason to act immediately, not eventually."},
                    {"id": "c", "text": "\"Important document attached, open immediately\" (macro-enabled)", "outcome": "risky", "feedback": "Only works if the target has macros enabled — many orgs disable them by default now."}
                ]
            },
            "log": "ALERT  Victim clicked link — credentials submitted on fake login page"
        },
        {
            "stageId": "installation",
            "name": "Installation",
            "narrative": "Harvest",
            "mitre": "T1098",
            "challenge": {
                "prompt": "You have credentials. How do you keep access?",
                "options": [
                    {"id": "a", "text": "Register a mail-forwarding rule / OAuth app using the stolen credentials", "outcome": "best", "feedback": "No malware, no file dropped — just abuses legitimate account features. Very hard to detect."},
                    {"id": "b", "text": "Drop a custom backdoor executable on their machine", "outcome": "risky", "feedback": "It can work, but AV/EDR tools have a real chance of flagging a new unsigned binary."},
                    {"id": "c", "text": "Log in once, take what you can immediately, and don't come back", "outcome": "fail", "feedback": "The session times out and password gets rotated after the incident is noticed — you lose access fast.", "hint": "Think about what lets you come back later without re-phishing."}
                ]
            },
            "log": "CRITICAL  Backdoor installed using captured credentials"
        },
        {
            "stageId": "c2",
            "name": "Command and Control",
            "narrative": "Harvest",
            "mitre": "T1071",
            "challenge": {
                "prompt": "How do you maintain a channel back to your infrastructure?",
                "options": [
                    {"id": "a", "text": "Blend C2 traffic over HTTPS with low-frequency beacons", "outcome": "best", "feedback": "Looks like normal web traffic. Low beacon frequency avoids traffic-pattern-based detection."},
                    {"id": "b", "text": "Beacon every second over a raw unencrypted socket", "outcome": "fail", "feedback": "Immediately flagged — unencrypted, high-frequency traffic to an unknown IP is a textbook SOC alert.", "hint": "Your traffic needs to blend in with what the network normally sees."},
                    {"id": "c", "text": "Use a popular C2 framework's default, unmodified traffic profile", "outcome": "risky", "feedback": "Signature-based detection tools often have this exact default profile in their ruleset."}
                ]
            },
            "log": "CRITICAL  Outbound C2 connection established"
        },
        {
            "stageId": "actions",
            "name": "Actions on Objectives",
            "narrative": "Harvest",
            "mitre": "T1041",
            "challenge": {
                "prompt": "You have persistent access. What's the payoff?",
                "options": [
                    {"id": "a", "text": "Quietly exfiltrate a small set of high-value files over time", "outcome": "best", "feedback": "Slow and targeted — stays under most Data Loss Prevention (DLP) thresholds."},
                    {"id": "b", "text": "Immediately dump the entire file server", "outcome": "fail", "feedback": "A massive spike in outbound traffic trips DLP and network monitoring alarms almost instantly.", "hint": "A sudden, huge data transfer is one of the easiest things for defenders to catch."},
                    {"id": "c", "text": "Deploy ransomware across the network", "outcome": "risky", "feedback": "Guarantees detection immediately — only makes sense if disruption, not stealth, was the actual goal."}
                ]
            },
            "log": "CRITICAL  Sensitive data exfiltrated to external server"
        }
    ]
}

# ============================================================
#  BLUE / PHISHING
# ============================================================
blue_phishing = {
    "mode": "blue",
    "attack": "phishing",
    "title": "Phishing",
    "headline": "Every alert is a clue. Catch it before the click.",
    "overview": "Phishing succeeds by exploiting trust, not systems — which means your best defenses are awareness, filtering, and fast detection rather than patching a vulnerability. Your job is to spot the signals at every stage before the attacker reaches their objective.",
    "targets": [
        "Employee inboxes and email gateways",
        "Login pages and authentication systems",
        "Endpoint activity following a suspicious click"
    ],
    "tips": [
        "The best detection is often a suspicious employee — make reporting easy and blameless.",
        "A single reported phishing email is a chance to block it organization-wide before others click.",
        "Correlate multiple weak signals (unusual login + odd time + new device) rather than waiting for one strong one."
    ],
    "stages": [
        {
            "stageId": "reconnaissance",
            "name": "Reconnaissance",
            "narrative": None,
            "mitre": "T1589",
            "challenge": {
                "prompt": "You get a tip that someone may be researching your employees online. What's your move?",
                "options": [
                    {"id": "a", "text": "Review what's publicly exposed about staff (LinkedIn, org charts, bios) and flag oversharing", "outcome": "best", "feedback": "You can't stop recon, but reducing exposed attack-surface information makes future lures harder to craft."},
                    {"id": "b", "text": "Ignore it — recon isn't an attack, so there's nothing to act on", "outcome": "fail", "feedback": "Recon is the earliest possible warning sign. Ignoring it means losing your best chance to prepare before delivery.", "hint": "Recon activity, even passive, is worth logging and reviewing — it often precedes a targeted campaign."},
                    {"id": "c", "text": "Send a company-wide warning email about \"possible phishing\"", "outcome": "risky", "feedback": "Too vague to be actionable, and constant unspecific warnings train employees to tune out real alerts later."}
                ]
            },
            "log": "INFO  Passive OSINT activity noted — no direct organizational contact detected"
        },
        {
            "stageId": "weaponization",
            "name": "Weaponization",
            "narrative": "Lure",
            "mitre": "T1587",
            "challenge": {
                "prompt": "Threat intel flags a new phishing kit mimicking your company's login page. What do you do?",
                "options": [
                    {"id": "a", "text": "Add the fake login domain to your blocklist and alert the SOC to watch for related traffic", "outcome": "best", "feedback": "Proactive blocking before delivery even happens is the cheapest possible win — no employee ever sees the lure."},
                    {"id": "b", "text": "Wait until an employee actually reports receiving it", "outcome": "fail", "feedback": "By the time someone reports it, others may have already clicked. You had the chance to block it network-wide first.", "hint": "Threat intel exists so you can act before the first click, not after."},
                    {"id": "c", "text": "Forward the intel to IT with no specific action requested", "outcome": "risky", "feedback": "Without a clear next step, this kind of alert often sits unread until it's too late to matter."}
                ]
            },
            "log": "INFO  Threat intel received — lookalike domain identified in the wild"
        },
        {
            "stageId": "delivery",
            "name": "Delivery",
            "narrative": "Bait",
            "mitre": "T1566.001",
            "challenge": {
                "prompt": "An email claiming to be \"IT Support\" lands in an employee's inbox from an external domain. How do you handle it?",
                "options": [
                    {"id": "a", "text": "Check the sender domain against your allow-list and quarantine anything that doesn't match", "outcome": "best", "feedback": "Domain verification at the gateway catches typosquatted senders before a human ever has to make a judgment call."},
                    {"id": "b", "text": "Let it through — employees are trained to spot phishing themselves", "outcome": "fail", "feedback": "Training helps, but relying on it alone means your weakest link is your only line of defense. One tired employee is all it takes.", "hint": "Technical filtering should catch what training might miss on a busy day."},
                    {"id": "c", "text": "Manually review every external email before delivery", "outcome": "risky", "feedback": "This doesn't scale — email volume will overwhelm manual review, and delays frustrate legitimate business communication."}
                ]
            },
            "log": "ALERT  Suspicious sender domain flagged by email gateway rule"
        },
        {
            "stageId": "exploitation",
            "name": "Exploitation",
            "narrative": "Trap",
            "mitre": "T1204.001",
            "challenge": {
                "prompt": "An employee clicks the link and lands on a fake login page. What's the best detection layer here?",
                "options": [
                    {"id": "a", "text": "Browser isolation or DNS filtering blocks the non-corporate domain before credentials are entered", "outcome": "best", "feedback": "This is your last automated line of defense — stopping the page load before the credential form is even seen."},
                    {"id": "b", "text": "Nothing — if the email got through, there's no way to stop it now", "outcome": "fail", "feedback": "Giving up here means the attacker gets the credentials by default. Detection layers exist precisely for this moment.", "hint": "Even after delivery, there are still technical controls that can intercept the click itself."},
                    {"id": "c", "text": "Rely on the employee to notice the fake page looks slightly different", "outcome": "risky", "feedback": "Modern phishing pages are often pixel-perfect clones — human visual inspection catches this only some of the time."}
                ]
            },
            "log": "ALERT  Outbound connection to known-bad domain attempted"
        },
        {
            "stageId": "installation",
            "name": "Installation",
            "narrative": "Harvest",
            "mitre": "T1098",
            "challenge": {
                "prompt": "You see a new mail-forwarding rule and an unfamiliar OAuth app grant on a compromised account. What now?",
                "options": [
                    {"id": "a", "text": "Revoke the OAuth grant, remove the forwarding rule, and force a password reset immediately", "outcome": "best", "feedback": "This directly removes the attacker's persistence mechanisms — the exact things letting them stay in without malware."},
                    {"id": "b", "text": "Just reset the password and consider it resolved", "outcome": "fail", "feedback": "The forwarding rule and OAuth grant survive a password reset. The attacker keeps reading mail even after \"fixing\" the account.", "hint": "Password resets don't undo every persistence mechanism an attacker may have set up."},
                    {"id": "c", "text": "Monitor the account for a few more days before acting", "outcome": "risky", "feedback": "Every extra day gives the attacker more time to read sensitive mail or escalate further inside the account."}
                ]
            },
            "log": "CRITICAL  Unauthorized OAuth app and mail-forwarding rule detected on user account"
        },
        {
            "stageId": "c2",
            "name": "Command and Control",
            "narrative": "Harvest",
            "mitre": "T1071",
            "challenge": {
                "prompt": "Network monitoring shows an endpoint making regular, low-volume HTTPS calls to an unfamiliar domain. What's your next step?",
                "options": [
                    {"id": "a", "text": "Correlate the beacon pattern with threat intel and isolate the host if it matches known C2 behavior", "outcome": "best", "feedback": "Beaconing patterns are subtle by design — cross-referencing with intel is how you tell normal traffic from disguised C2."},
                    {"id": "b", "text": "Ignore it — it's just HTTPS traffic, which is normal and encrypted", "outcome": "fail", "feedback": "Attackers deliberately blend C2 into normal-looking HTTPS traffic. Dismissing it because it's \"just HTTPS\" is exactly the blind spot they're counting on.", "hint": "Encrypted doesn't mean safe — the pattern of the traffic matters more than the protocol."},
                    {"id": "c", "text": "Block the domain immediately without further investigation", "outcome": "risky", "feedback": "Blocking without confirmation risks disrupting legitimate services and losing the chance to trace what the attacker already accessed."}
                ]
            },
            "log": "ALERT  Low-frequency beaconing pattern detected from internal host"
        },
        {
            "stageId": "actions",
            "name": "Actions on Objectives",
            "narrative": "Harvest",
            "mitre": "T1041",
            "challenge": {
                "prompt": "DLP flags a slow trickle of files being uploaded to an external file-sharing site from one account. How do you respond?",
                "options": [
                    {"id": "a", "text": "Investigate what was accessed, contain the account, and determine scope of exposure", "outcome": "best", "feedback": "Slow exfiltration is designed to fly under simple volume-based alarms — full investigation is the only way to know the real damage."},
                    {"id": "b", "text": "Dismiss it since the volume is too small to be a real incident", "outcome": "fail", "feedback": "That's exactly why the attacker chose a slow trickle — to stay under naive volume thresholds while still getting the data out.", "hint": "Attackers deliberately keep exfiltration small and slow specifically to avoid triggering size-based alerts."},
                    {"id": "c", "text": "Immediately disable the account without checking what was already taken", "outcome": "risky", "feedback": "Stops future exfiltration, but you lose the chance to determine exactly what was already exposed for a proper incident report."}
                ]
            },
            "log": "ALERT  DLP flagged unusual low-volume file uploads to external destination"
        }
    ]
}

# ============================================================
#  RUN MIGRATION
# ============================================================
if __name__ == "__main__":
    for scenario in [red_phishing, blue_phishing]:
        existing = db.scenarios.find_one({"mode": scenario["mode"], "attack": scenario["attack"]})
        if existing:
            db.scenarios.update_one(
                {"_id": existing["_id"]},
                {"$set": scenario}
            )
            print(f"Updated: {scenario['mode']}/{scenario['attack']}")
        else:
            db.scenarios.insert_one(scenario)
            print(f"Inserted: {scenario['mode']}/{scenario['attack']}")

    print("\nMigration complete.")
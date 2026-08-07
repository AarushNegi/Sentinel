# backend/seed_learn_articles.py
"""
Seeds the `learn_articles` collection in MongoDB.
Run once: python seed_learn_articles.py
Re-run safely anytime — updates existing articles by slug instead of duplicating.
"""

from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))
db = client["sentinel"]

articles = [
    {
        "slug": "cyber-kill-chain-overview",
        "category": "kill-chain",
        "title": "The Cyber Kill Chain: A Framework for Understanding Attacks",
        "difficulty": "beginner",
        "readTime": 5,
        "mitreRefs": [],
        "interactive": None,
        "content": """The Cyber Kill Chain, developed by Lockheed Martin, breaks down a cyberattack into seven distinct stages — from initial reconnaissance to the attacker's final objective. Understanding this framework matters because it gives defenders multiple points to intervene. An attack doesn't succeed or fail at one moment; it has to survive every stage.

**The seven stages:**

1. **Reconnaissance** — The attacker researches the target: employee names, technologies in use, exposed services. This is almost always passive and hard to detect directly.

2. **Weaponization** — A deliverable payload is built, such as a malicious document paired with a remote-access backdoor.

3. **Delivery** — The weapon is transmitted to the target, most commonly via email, but also through USB drives, malicious websites, or supply-chain compromise.

4. **Exploitation** — Once delivered, the payload executes, exploiting a vulnerability in an application or human trust to trigger malicious code.

5. **Installation** — The attacker establishes persistence, often through a backdoor or remote access trojan, ensuring continued access even if the initial vector is closed.

6. **Command and Control (C2)** — The compromised system phones home to attacker-controlled infrastructure, enabling remote hands-on-keyboard access.

7. **Actions on Objectives** — With access and control established, the attacker pursues their original goal: data theft, destruction, encryption for ransom, or lateral movement to higher-value targets.

**Why this matters for defenders:** every stage is an opportunity. A phishing email blocked at Delivery never reaches Exploitation. A blocked C2 channel neutralizes an attacker even if Installation already succeeded. Sentinel's simulations are built directly around this framework so you can practice recognizing and responding to each stage individually.""",
        "furtherReading": [
            {"label": "Lockheed Martin — Cyber Kill Chain (original framework)", "url": "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html"},
            {"label": "MITRE ATT&CK Enterprise Matrix", "url": "https://attack.mitre.org/matrices/enterprise/"}
        ]
    },
    {
        "slug": "sha-256-explained",
        "category": "cryptography",
        "title": "SHA-256: How It Works",
        "difficulty": "intermediate",
        "readTime": 6,
        "mitreRefs": [],
        "interactive": "hash-playground",
        "content": """SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that takes an input of any size and produces a fixed 256-bit (32-byte) output, called a digest. It's part of the SHA-2 family, published by the NSA and standardized by NIST in FIPS 180-4.

**Key properties that make it useful for security:**

- **Deterministic** — the same input always produces the same output.
- **Fast to compute** — hashing even large inputs takes microseconds.
- **Pre-image resistant** — given a hash, it's computationally infeasible to find the original input.
- **Avalanche effect** — changing a single bit of input produces a completely different, unpredictable output. Try it in the playground below.
- **Collision resistant** — it's extremely difficult (though not mathematically impossible) to find two different inputs that produce the same hash.

**Where you'll see it in practice:** password storage (usually combined with salting, since raw SHA-256 is fast enough to be brute-forced at scale), file integrity verification (checking a downloaded file's hash against a published value), blockchain proof-of-work, and digital signatures.

**A common mistake:** using SHA-256 alone for password storage. Because it's designed to be fast, attackers can compute billions of hashes per second on GPUs. Purpose-built password hashing algorithms like bcrypt or Argon2 deliberately slow down the process to resist brute-forcing — which is why Sentinel's own backend uses bcrypt for user passwords, not raw SHA-256.""",
        "furtherReading": [
            {"label": "NIST FIPS 180-4 (SHA-2 Standard)", "url": "https://csrc.nist.gov/publications/detail/fips/180/4/final"},
            {"label": "OWASP Password Storage Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"}
        ]
    },
    {
        "slug": "phishing-technique-t1566",
        "category": "social-engineering",
        "title": "Phishing (T1566): Techniques and Variants",
        "difficulty": "beginner",
        "readTime": 4,
        "mitreRefs": ["T1566", "T1566.001", "T1566.002"],
        "interactive": None,
        "content": """Phishing is classified under MITRE ATT&CK technique T1566, and remains one of the most common initial access vectors in real-world breaches — not because it's technically sophisticated, but because it targets human trust rather than software vulnerabilities.

**Common variants:**

- **T1566.001 — Spearphishing Attachment**: a malicious file (document, executable disguised as a document, archive) is attached directly to the email.
- **T1566.002 — Spearphishing Link**: the email contains a link to an attacker-controlled site, often a convincing clone of a legitimate login page, designed to harvest credentials.
- **T1566.003 — Spearphishing via Service**: the lure is delivered through a third-party service (social media DM, collaboration platform) rather than email directly, often to bypass email security filters.

**Why it works:** phishing exploits urgency, authority, and familiarity. An email claiming to be from IT support, warning of an imminent password expiration, short-circuits careful evaluation — the target acts before they think.

**Defensive layers:** email gateway filtering (catching known-bad domains and lookalike domains before delivery), user awareness training, browser isolation or DNS filtering (blocking the malicious page even if the link is clicked), and multi-factor authentication (limiting the damage even if credentials are captured). No single layer is sufficient — defense against phishing depends on multiple overlapping controls, since any individual layer can fail.""",
        "furtherReading": [
            {"label": "MITRE ATT&CK — T1566 Phishing", "url": "https://attack.mitre.org/techniques/T1566/"},
            {"label": "CISA Phishing Guidance", "url": "https://www.cisa.gov/"}
        ]
    }
]

if __name__ == "__main__":
    for article in articles:
        existing = db.learn_articles.find_one({"slug": article["slug"]})
        if existing:
            db.learn_articles.update_one({"_id": existing["_id"]}, {"$set": article})
            print(f"Updated: {article['slug']}")
        else:
            db.learn_articles.insert_one(article)
            print(f"Inserted: {article['slug']}")

    print("\nSeed complete.")
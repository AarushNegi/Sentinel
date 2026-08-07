# backend/seed_learn_articles_batch2.py
"""
Second batch - adds 18 more articles to `learn_articles`, bringing the total to 21.
Run once: python seed_learn_articles_batch2.py
Safe to re-run - upserts by slug.
"""

from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()
client = MongoClient(os.getenv("MONGO_URI"))
db = client["sentinel"]

articles = [
    # ============================================================
    #  CRYPTOGRAPHY
    # ============================================================
    {
        "slug": "md5-and-collisions",
        "category": "cryptography",
        "title": "MD5 and Why It's Considered Broken",
        "difficulty": "beginner",
        "readTime": 4,
        "mitreRefs": [],
        "interactive": None,
        "content": """MD5 (Message Digest Algorithm 5) produces a 128-bit hash and was once the standard for checksums and password storage. It's fast, simple, and still shows up in legacy systems - but it should never be used anywhere security matters today.

**Why it's broken:** researchers demonstrated practical collision attacks against MD5 as early as 2004 - meaning two different inputs can be crafted to produce the identical hash. This breaks MD5's core promise as a security tool: if collisions are findable, an attacker can substitute a malicious file for a legitimate one while keeping the same checksum, or forge digital certificates.

**Where it's still (barely) acceptable:** non-security checksums, like verifying a file wasn't accidentally corrupted during a transfer where nobody is actively trying to fool the check. Even here, most tools have moved to SHA-256 anyway since it's not meaningfully slower on modern hardware.

**Where it must never be used:** password hashing, digital signatures, SSL/TLS certificates, or anywhere an attacker might benefit from forging a match. If you find MD5 protecting passwords in a legacy system, that's an immediate finding in a security audit.""",
        "furtherReading": [
            {"label": "NIST - Recommendation for Cryptographic Hash Algorithms", "url": "https://csrc.nist.gov/projects/hash-functions"},
            {"label": "CVE record on MD5 collision vulnerabilities", "url": "https://www.cve.org/"}
        ]
    },
    {
        "slug": "symmetric-vs-asymmetric-encryption",
        "category": "cryptography",
        "title": "Symmetric vs Asymmetric Encryption",
        "difficulty": "beginner",
        "readTime": 5,
        "mitreRefs": [],
        "interactive": None,
        "content": """Encryption falls into two fundamental categories, and understanding the difference explains why real systems (like TLS) use both together.

**Symmetric encryption** uses a single shared key for both encrypting and decrypting data. Algorithms like AES (Advanced Encryption Standard) are extremely fast and efficient, making them ideal for encrypting large amounts of data. The catch: both parties need the same secret key, and securely sharing that key in the first place is the hard problem.

**Asymmetric encryption** (public-key cryptography) uses a mathematically linked key pair - a public key that can be shared openly, and a private key that must stay secret. Data encrypted with the public key can only be decrypted with the matching private key. Algorithms like RSA and elliptic-curve cryptography (ECC) solve the key-distribution problem, but they're computationally slower than symmetric encryption.

**Why real systems use both:** TLS (the protocol behind HTTPS) uses asymmetric encryption briefly during the handshake to securely exchange a symmetric session key, then switches to fast symmetric encryption (typically AES) for the actual data transfer. You get the security of asymmetric key exchange without paying its performance cost for every byte transferred.""",
        "furtherReading": [
            {"label": "NIST FIPS 197 (AES Standard)", "url": "https://csrc.nist.gov/publications/detail/fips/197/final"},
            {"label": "Cloudflare - What is Public Key Cryptography?", "url": "https://www.cloudflare.com/learning/ssl/how-does-public-key-encryption-work/"}
        ]
    },
    {
        "slug": "password-hashing-bcrypt-argon2",
        "category": "cryptography",
        "title": "Password Hashing: bcrypt, Argon2, and Why Speed Is the Enemy",
        "difficulty": "intermediate",
        "readTime": 5,
        "mitreRefs": ["T1110"],
        "interactive": None,
        "content": """Storing passwords securely isn't about picking any cryptographic hash function - it's about picking one that's deliberately slow. This is counterintuitive at first, but it's the entire point.

**The problem with fast hashes:** if you hash passwords with something like SHA-256, an attacker who steals your password database can attempt billions of guesses per second using modern GPUs. Even reasonably complex passwords fall quickly under that kind of brute-force pressure.

**bcrypt** was designed specifically to resist this. It incorporates a configurable "work factor" that controls how computationally expensive each hash operation is, and it includes salting automatically - meaning even identical passwords produce different hashes, defeating precomputed rainbow-table attacks.

**Argon2** (winner of the 2015 Password Hashing Competition) goes further, adding configurable memory cost alongside computational cost. This specifically defends against attacks using specialized hardware (ASICs, GPU clusters) that can be built cheaply for computation but not as easily for memory bandwidth.

**The practical takeaway:** if you're building authentication (like Sentinel's own backend does), always use a purpose-built password hashing algorithm - bcrypt or Argon2, never raw SHA-256 or MD5 - and never write your own scheme.""",
        "furtherReading": [
            {"label": "OWASP Password Storage Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"},
            {"label": "Argon2 - Password Hashing Competition winner", "url": "https://www.password-hashing.net/"}
        ]
    },

    # ============================================================
    #  MALWARE
    # ============================================================
    {
        "slug": "ransomware-how-it-works",
        "category": "malware",
        "title": "Ransomware: How It Works",
        "difficulty": "beginner",
        "readTime": 5,
        "mitreRefs": ["T1486", "T1490"],
        "interactive": None,
        "content": """Ransomware is malware that denies access to a victim's data - typically through encryption - until a ransom is paid. It's one of the most financially destructive categories of cyberattack today, targeting everything from individual users to hospital systems and municipal governments.

**Typical execution flow:** after gaining initial access (often via phishing, exposed RDP, or exploiting an unpatched vulnerability), the malware moves laterally through the network to maximize impact before triggering. It commonly deletes or encrypts backup files first (T1490 - Inhibit System Recovery) specifically to remove the victim's ability to simply restore from backup instead of paying.

**Encryption stage (T1486):** files are encrypted using a combination of symmetric encryption for speed and asymmetric encryption to protect the symmetric key - meaning only the attacker holds the private key needed to decrypt, even if defenders fully analyze the malware's code.

**Double extortion:** modern ransomware groups increasingly exfiltrate sensitive data before encrypting it, threatening to publish it publicly even if the victim has clean backups and doesn't need to pay for decryption - adding pressure beyond simple data recovery.

**Defensive priorities:** offline/immutable backups, network segmentation to limit lateral movement, and rapid patching of internet-facing services remain the most effective controls.""",
        "furtherReading": [
            {"label": "CISA StopRansomware.gov", "url": "https://www.cisa.gov/stopransomware"},
            {"label": "MITRE ATT&CK - T1486 Data Encrypted for Impact", "url": "https://attack.mitre.org/techniques/T1486/"}
        ]
    },
    {
        "slug": "malware-types-overview",
        "category": "malware",
        "title": "Viruses, Worms, and Trojans: What's the Difference?",
        "difficulty": "beginner",
        "readTime": 4,
        "mitreRefs": [],
        "interactive": None,
        "content": """These terms get used interchangeably in casual conversation, but they describe distinct behaviors that matter for understanding how malware spreads and how to defend against it.

**Virus:** attaches itself to a legitimate file or program and requires human action (opening the infected file) to activate and spread. Without a host file to attach to, a true virus can't propagate - it's parasitic by definition.

**Worm:** self-replicating and self-propagating, spreading across networks without any human interaction required. Once a worm compromises one machine, it can automatically scan for and infect other vulnerable systems, which is why worm outbreaks (like WannaCry) can spread globally within hours.

**Trojan:** disguises itself as legitimate, desirable software to trick users into installing it voluntarily. Unlike viruses and worms, trojans don't self-replicate - they rely entirely on social engineering to gain initial access, often serving as the delivery mechanism for other malware like backdoors or ransomware.

**Why the distinction matters:** the propagation method determines the appropriate defense. Worms demand network segmentation and rapid patching; trojans demand user awareness training and application whitelisting; viruses demand file-integrity monitoring and antivirus scanning of shared files.""",
        "furtherReading": [
            {"label": "CISA - Understanding Malware", "url": "https://www.cisa.gov/topics/cyber-threats-and-advisories/malware-phishing-and-ransomware"}
        ]
    },
    {
        "slug": "rootkits-and-persistence",
        "category": "malware",
        "title": "Rootkits: Hiding in Plain Sight",
        "difficulty": "advanced",
        "readTime": 5,
        "mitreRefs": ["T1014", "T1547"],
        "interactive": None,
        "content": """A rootkit is malware specifically designed to hide its own presence - and often the presence of other malicious tools - from the operating system and security software. The name comes from Unix "root" access combined with "kit," a set of tools for maintaining that privileged access invisibly.

**How concealment works (T1014):** rootkits typically operate by intercepting and modifying the normal calls a system makes to list files, processes, or network connections, filtering out anything related to the attacker's presence before the results are ever displayed to the user or security tools. A well-built rootkit can make an infected system's file listing look completely clean, even while malicious processes actively run.

**Kernel-level vs user-level:** user-mode rootkits operate within normal application privilege levels and are comparatively easier to detect. Kernel-mode rootkits operate with the same privileges as the operating system core itself, making them far more dangerous and difficult to identify, since they can subvert the very tools meant to inspect them.

**Boot/firmware persistence (T1547):** the most advanced rootkits install themselves in the boot process or even device firmware, surviving a full OS reinstall - which is why highly sophisticated incidents sometimes require replacing hardware entirely rather than simply reformatting.

**Detection approaches:** since rootkits actively lie to the running OS, detection often requires comparing the system against a known-good baseline from outside the potentially compromised environment, such as booting from external trusted media.""",
        "furtherReading": [
            {"label": "MITRE ATT&CK - T1014 Rootkit", "url": "https://attack.mitre.org/techniques/T1014/"}
        ]
    },
    {
        "slug": "remote-access-trojans",
        "category": "malware",
        "title": "Remote Access Trojans (RATs)",
        "difficulty": "intermediate",
        "readTime": 4,
        "mitreRefs": ["T1219"],
        "interactive": None,
        "content": """A Remote Access Trojan gives an attacker interactive, hands-on-keyboard control over a compromised machine - effectively turning it into a remotely operated computer the attacker can use as if sitting in front of it.

**Typical capabilities:** file browsing and exfiltration, keystroke logging, webcam/microphone access, screen capture, and the ability to launch additional tools or pivot to other machines on the same network. Unlike simpler malware that runs a fixed set of actions, a RAT gives the attacker ongoing, flexible control.

**Legitimate tool abuse (T1219):** attackers increasingly favor abusing legitimate remote-access software (like TeamViewer, AnyDesk, or built-in Windows Remote Desktop) rather than custom malware, since traffic to well-known legitimate services is far less likely to be flagged by security tools than traffic to unknown custom infrastructure.

**Detection challenge:** because a RAT session can look identical to a legitimate remote support session at the network level, detection often relies on behavioral signals - unusual login times, unexpected geographic origin, or an employee reporting a support session they didn't request - rather than pure signature-based tools.""",
        "furtherReading": [
            {"label": "MITRE ATT&CK - T1219 Remote Access Software", "url": "https://attack.mitre.org/techniques/T1219/"}
        ]
    },

    # ============================================================
    #  NETWORK
    # ============================================================
    {
        "slug": "man-in-the-middle-attacks",
        "category": "network",
        "title": "Man-in-the-Middle Attacks",
        "difficulty": "beginner",
        "readTime": 4,
        "mitreRefs": ["T1557"],
        "interactive": None,
        "content": """A Man-in-the-Middle (MITM) attack occurs when an attacker secretly intercepts and potentially alters communication between two parties who believe they're communicating directly with each other.

**Where it happens:** commonly on unsecured public Wi-Fi networks, where an attacker positions themselves between a victim's device and the network gateway. Every request the victim sends - including logins, form submissions, and unencrypted traffic - passes through the attacker first.

**Why HTTPS matters:** properly implemented TLS encryption prevents an attacker from reading or modifying the actual content of intercepted traffic, even if they successfully position themselves in the communication path. This is precisely why browsers now aggressively warn users about non-HTTPS sites - without encryption, MITM interception exposes everything in plaintext.

**Certificate-based defenses:** attackers sometimes attempt to present a fraudulent certificate to trick a victim's browser into trusting a connection that's actually being intercepted. Certificate pinning and strict certificate validation help defend against this specific variant.

**Beyond Wi-Fi:** MITM techniques also apply to ARP spoofing on local networks, DNS spoofing, and rogue access points designed to mimic legitimate network names.""",
        "furtherReading": [
            {"label": "MITRE ATT&CK - T1557 Adversary-in-the-Middle", "url": "https://attack.mitre.org/techniques/T1557/"},
            {"label": "OWASP - Man-in-the-Middle Attack", "url": "https://owasp.org/www-community/attacks/Man-in-the-middle_attack"}
        ]
    },
    {
        "slug": "arp-spoofing-explained",
        "category": "network",
        "title": "ARP Spoofing: Poisoning the Local Network",
        "difficulty": "intermediate",
        "readTime": 4,
        "mitreRefs": ["T1557.002"],
        "interactive": None,
        "content": """ARP (Address Resolution Protocol) maps IP addresses to physical MAC addresses on a local network - and it was designed decades ago with no authentication built in, which is exactly what ARP spoofing exploits.

**How the attack works:** an attacker sends forged ARP messages onto the local network, associating their own MAC address with the IP address of a legitimate device - often the network gateway. Other devices on the network update their ARP tables based on these unauthenticated messages, unknowingly routing their traffic through the attacker instead.

**Why it works so reliably:** ARP has no built-in verification mechanism to confirm a response actually came from the device it claims to represent. Any device on the local network segment can claim to be any other device, and most systems will simply believe the most recent claim.

**Real-world impact:** once positioned as the traffic's man-in-the-middle, an attacker can intercept unencrypted data, redirect victims to malicious sites, or launch further attacks - making ARP spoofing a common first step in local network compromise, especially on shared networks like offices or public Wi-Fi.

**Defenses:** static ARP entries for critical infrastructure, dynamic ARP inspection on managed switches, and network segmentation all limit exposure.""",
        "furtherReading": [
            {"label": "MITRE ATT&CK - T1557.002 ARP Cache Poisoning", "url": "https://attack.mitre.org/techniques/T1557/002/"}
        ]
    },
    {
        "slug": "dns-poisoning",
        "category": "network",
        "title": "DNS Poisoning and Cache Spoofing",
        "difficulty": "intermediate",
        "readTime": 4,
        "mitreRefs": [],
        "interactive": None,
        "content": """DNS translates human-readable domain names into IP addresses. DNS poisoning (also called cache spoofing) corrupts this translation process, redirecting victims to attacker-controlled destinations while the victim believes they're reaching a legitimate site.

**How poisoning happens:** an attacker injects a forged DNS response into a resolver's cache - either by exploiting a vulnerability in the resolver software or by racing a legitimate response with a spoofed one. Once poisoned, every user relying on that resolver receives the fraudulent mapping until the cache entry expires or is corrected.

**Impact:** a victim typing a completely correct, legitimate URL can still land on a malicious server if the DNS resolution along the way has been poisoned - making this attack particularly dangerous since there's no obviously wrong URL for the victim to notice.

**DNSSEC as a defense:** DNS Security Extensions add cryptographic signatures to DNS responses, allowing resolvers to verify that a response genuinely came from the authoritative source and hasn't been tampered with in transit. Adoption remains incomplete across the internet, which is why poisoning attacks still succeed in practice.

**Practical mitigation:** using DNS-over-HTTPS or DNS-over-TLS protects the query itself from interception, while DNSSEC protects the integrity of the response.""",
        "furtherReading": [
            {"label": "CISA - Understanding DNS Security", "url": "https://www.cisa.gov/"},
            {"label": "ICANN - DNSSEC Explained", "url": "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"}
        ]
    },
    {
        "slug": "port-scanning-fundamentals",
        "category": "network",
        "title": "Port Scanning Fundamentals",
        "difficulty": "beginner",
        "readTime": 4,
        "mitreRefs": ["T1046"],
        "interactive": None,
        "content": """Port scanning identifies which network ports on a target system are open, closed, or filtered - giving an attacker (or a defender auditing their own network) a map of what services are running and potentially exploitable.

**Common scan types:** a TCP connect scan completes the full three-way handshake, making it reliable but easily logged. A SYN scan ("half-open" scan) sends only the initial connection request and never completes the handshake, making it faster and historically stealthier, though modern intrusion detection systems now commonly flag this pattern too.

**What defenders see:** a scan appears as a burst of connection attempts across many ports in a short window, often from a single source - a distinct pattern from normal traffic that well-tuned network monitoring should flag as reconnaissance activity (T1046).

**Why it matters early in an attack:** port scanning is typically one of the very first active steps an attacker takes after passive reconnaissance, since it reveals exactly which services (web servers, databases, remote access tools) are exposed and worth investigating further for vulnerabilities.

**Defensive posture:** minimizing the number of exposed ports in the first place, combined with rate-limiting and alerting on scan-like connection patterns, meaningfully raises the cost of this reconnaissance stage.""",
        "furtherReading": [
            {"label": "MITRE ATT&CK - T1046 Network Service Discovery", "url": "https://attack.mitre.org/techniques/T1046/"}
        ]
    },

    # ============================================================
    #  WEB APPLICATION ATTACKS
    # ============================================================
    {
        "slug": "sql-injection-basics",
        "category": "web",
        "title": "SQL Injection Basics",
        "difficulty": "beginner",
        "readTime": 5,
        "mitreRefs": ["T1190"],
        "interactive": None,
        "content": """SQL Injection occurs when untrusted user input is inserted directly into a database query without proper sanitization, allowing an attacker to manipulate the query's logic entirely.

**A classic example:** a login form that builds a query like `SELECT * FROM users WHERE username = '[input]' AND password = '[input]'`. If the application doesn't sanitize input, an attacker entering `' OR '1'='1` as the username can transform the query's logic into something that's always true, bypassing authentication entirely without ever knowing a real password.

**Beyond login bypass:** SQL injection can be used to extract entire database contents, modify or delete data, and in some database configurations, even execute operating system commands - making it one of the most consistently damaging vulnerability classes in web applications for decades.

**The fix - parameterized queries:** rather than building queries through string concatenation, parameterized queries (also called prepared statements) treat user input strictly as data, never as executable query logic, regardless of what characters the input contains. This single practice eliminates the vulnerability class entirely when applied consistently.

**Why it still happens:** despite being a well-understood, decades-old vulnerability with a well-understood fix, SQL injection remains common in real-world applications due to legacy code, third-party libraries, and inconsistent application of secure coding practices across large codebases.""",
        "furtherReading": [
            {"label": "OWASP SQL Injection Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
            {"label": "MITRE ATT&CK - T1190 Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"}
        ]
    },
    {
        "slug": "cross-site-scripting-xss",
        "category": "web",
        "title": "Cross-Site Scripting (XSS)",
        "difficulty": "beginner",
        "readTime": 5,
        "mitreRefs": [],
        "interactive": None,
        "content": """Cross-Site Scripting lets an attacker inject malicious JavaScript into a web page that other users then view - running the attacker's code in the victim's browser, in the context of the trusted site itself.

**Stored XSS:** the malicious script is permanently saved on the target server (for example, in a comment field that isn't properly sanitized) and served to every visitor who views that content - the most dangerous variant, since it requires no additional action from the victim beyond simply visiting the page.

**Reflected XSS:** the malicious script is embedded in a URL or form submission and only executes when a victim is tricked into clicking a crafted link, reflecting the attacker's input directly back into the page's response.

**DOM-based XSS:** the vulnerability exists entirely in client-side JavaScript that unsafely handles data from the URL or user input, without the malicious payload ever necessarily touching the server at all.

**What an attacker gains:** session cookie theft (enabling account takeover), keystroke logging, defacement, or redirecting victims to phishing pages - all executing with the full trust and permissions of the legitimate site in the victim's browser.

**The core fix:** proper output encoding - ensuring any user-controlled data rendered into HTML is treated as text, not executable markup - combined with a strong Content Security Policy (CSP) as a defense-in-depth layer.""",
        "furtherReading": [
            {"label": "OWASP XSS Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"}
        ]
    },
    {
        "slug": "csrf-explained",
        "category": "web",
        "title": "CSRF: Cross-Site Request Forgery",
        "difficulty": "intermediate",
        "readTime": 4,
        "mitreRefs": [],
        "interactive": None,
        "content": """CSRF tricks a victim's browser into submitting an unwanted, authenticated request to a site the victim is currently logged into - exploiting the fact that browsers automatically attach cookies to requests regardless of where the request originated.

**How the attack works:** an attacker crafts a malicious page containing a hidden form or auto-submitting request targeting a legitimate site (say, a bank's "transfer funds" endpoint). If a logged-in victim visits the attacker's page, their browser automatically includes their valid session cookie with the forged request, and the legitimate site has no way to distinguish it from a request the user genuinely intended to make.

**Why cookies alone aren't enough authentication:** the vulnerability exists precisely because session cookies are sent automatically by the browser on every request to a domain, with no built-in verification that the request was intentionally initiated by the user rather than triggered by a third-party page.

**Anti-CSRF tokens:** the standard defense embeds a unique, unpredictable token in each legitimate form, which the server verifies on submission. Since an attacker's forged page has no way to know or guess this token, forged requests fail validation even with a valid session cookie attached.

**SameSite cookies:** modern browsers support a `SameSite` cookie attribute that restricts when cookies are sent with cross-origin requests, providing meaningful built-in protection without requiring application-level token logic.""",
        "furtherReading": [
            {"label": "OWASP CSRF Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"}
        ]
    },
    {
        "slug": "ssrf-explained",
        "category": "web",
        "title": "SSRF: Server-Side Request Forgery",
        "difficulty": "advanced",
        "readTime": 5,
        "mitreRefs": ["T1190"],
        "interactive": None,
        "content": """SSRF tricks a server into making unintended requests on the attacker's behalf - often to internal systems the server can reach but the attacker never could directly from the outside.

**A common scenario:** an application feature that fetches a URL provided by the user (like generating a preview image from a link) is exploited by submitting an internal URL instead - `http://169.254.169.254/` (a common cloud metadata endpoint) or `http://localhost:8080/admin` - causing the server itself to make the request and often return the internal response back to the attacker.

**Why this is dangerous in cloud environments:** cloud provider metadata services often expose sensitive information - including temporary credentials - to any request originating from the instance itself, with no additional authentication required. An SSRF vulnerability can turn into full cloud infrastructure compromise if it reaches this endpoint.

**Beyond data exposure:** SSRF can be used to scan internal networks the server has access to, interact with internal-only services that were never meant to be internet-facing, or bypass firewall rules that only restrict external traffic - since the malicious request originates from a trusted internal server.

**Defenses:** strict allowlisting of permitted destination URLs, disabling unnecessary URL schemes, and network-level segmentation that limits what internal resources application servers can reach in the first place.""",
        "furtherReading": [
            {"label": "OWASP SSRF Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"}
        ]
    },

    # ============================================================
    #  SOCIAL ENGINEERING
    # ============================================================
    {
        "slug": "business-email-compromise",
        "category": "social-engineering",
        "title": "Business Email Compromise (BEC)",
        "difficulty": "intermediate",
        "readTime": 4,
        "mitreRefs": ["T1566", "T1534"],
        "interactive": None,
        "content": """Business Email Compromise is a targeted social engineering attack where an attacker impersonates a trusted figure - often an executive, vendor, or colleague - to convince a victim to transfer money or sensitive data, typically without any malware involved at all.

**Why it's so effective:** unlike broad phishing campaigns, BEC attacks are highly targeted and researched. An attacker might study a company's org chart, typical communication style, and current vendor relationships (via LinkedIn, press releases, or a prior compromised account) to craft a request that feels entirely routine.

**CEO fraud, a common variant:** an attacker impersonates a company executive, often urgently requesting an employee in finance authorize an unusual wire transfer - leveraging authority and urgency together, timed to catch someone during a busy moment or when the real executive is known to be traveling and unreachable for verification.

**Internal spearphishing (T1534):** once an attacker has already compromised one internal account, they can send BEC-style requests from a genuinely legitimate internal address, making them significantly more convincing than an external lookalike domain would be.

**Defenses:** out-of-band verification for any unusual financial request (a phone call to a known number, not one provided in the suspicious email), clear approval processes that can't be bypassed by urgency alone, and DMARC/SPF/DKIM email authentication to reduce domain spoofing.""",
        "furtherReading": [
            {"label": "FBI IC3 - Business Email Compromise", "url": "https://www.ic3.gov/"},
            {"label": "MITRE ATT&CK - T1534 Internal Spearphishing", "url": "https://attack.mitre.org/techniques/T1534/"}
        ]
    },
    {
        "slug": "pretexting-and-baiting",
        "category": "social-engineering",
        "title": "Pretexting and Baiting",
        "difficulty": "beginner",
        "readTime": 4,
        "mitreRefs": [],
        "interactive": None,
        "content": """Not every social engineering attack arrives as an email. Pretexting and baiting are two techniques built around fabricated scenarios and physical or psychological lures rather than a phishing link.

**Pretexting** involves an attacker inventing a fabricated scenario or false identity to extract information or access - for example, calling an employee while impersonating IT support and requesting their password "to fix an urgent issue," or posing as a new hire to get a colleague to hold a secure door open. The attacker builds a plausible story and relies on the target's instinct to be helpful.

**Baiting** offers something enticing to lure a victim into a trap. The classic physical example: leaving a USB drive labeled "Confidential - Salary Information" in a company parking lot, relying on curiosity to get an employee to plug it into a company machine, unknowingly executing malware.

**Why both work:** they exploit normal human tendencies - helpfulness, curiosity, respect for authority - rather than any technical vulnerability. No firewall or antivirus stops an employee from voluntarily plugging in a USB drive or holding a door for someone who looks like they belong.

**Defenses:** clear policies around unsolicited media (never plug in unknown devices), verified identity checks for sensitive requests regardless of how urgent or official they sound, and a security culture where employees feel comfortable questioning unusual requests without fear of seeming rude.""",
        "furtherReading": [
            {"label": "CISA - Social Engineering Guidance", "url": "https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors"}
        ]
    },

    # ============================================================
    #  KILL CHAIN FUNDAMENTALS
    # ============================================================
    {
        "slug": "privilege-escalation-techniques",
        "category": "kill-chain",
        "title": "Privilege Escalation: From Foothold to Full Control",
        "difficulty": "intermediate",
        "readTime": 5,
        "mitreRefs": ["T1068", "T1548"],
        "interactive": None,
        "content": """Gaining initial access to a system rarely gives an attacker everything they want immediately. Privilege escalation is the process of expanding limited access into broader control - turning a low-privilege foothold into administrator or root-level access.

**Vertical escalation:** moving from a lower privilege level to a higher one on the same system - for example, from a standard user account to full administrator rights, often by exploiting an unpatched vulnerability in the operating system or a privileged application (T1068).

**Horizontal escalation:** rather than gaining higher privileges on the same machine, the attacker gains access to a different account at a similar privilege level - useful for accessing resources tied to that specific account without needing full administrative control.

**Common technique - exploiting misconfigurations (T1548):** many privilege escalation paths don't rely on software vulnerabilities at all, but on misconfigured permissions - a scheduled task running as an administrator that a low-privilege user can modify, or overly permissive file system permissions on a sensitive binary.

**Why it matters in the kill chain:** privilege escalation often bridges Exploitation and Installation - an attacker with only user-level access typically can't install persistent backdoors or disable security tools, making this step essential for turning temporary access into a durable foothold.

**Defensive priority:** the principle of least privilege - ensuring accounts and processes only have the minimum permissions necessary - directly reduces the available escalation paths, regardless of which specific technique an attacker attempts.""",
        "furtherReading": [
            {"label": "MITRE ATT&CK - Privilege Escalation Tactic", "url": "https://attack.mitre.org/tactics/TA0004/"}
        ]
    },
    {
        "slug": "lateral-movement-fundamentals",
        "category": "kill-chain",
        "title": "Lateral Movement: Spreading Through the Network",
        "difficulty": "intermediate",
        "readTime": 4,
        "mitreRefs": ["T1021", "T1078"],
        "interactive": None,
        "content": """Once an attacker has a foothold on one machine, lateral movement is the process of expanding that access across the rest of the network - moving from an initial, often low-value compromised system toward higher-value targets like domain controllers or database servers.

**Using legitimate credentials (T1078):** rather than exploiting new vulnerabilities on each machine, attackers frequently reuse stolen or harvested credentials to authenticate to additional systems - a technique that's especially hard to detect since the resulting activity looks identical to a legitimate user logging in normally.

**Remote services abuse (T1021):** built-in administrative tools like RDP (Remote Desktop Protocol), SSH, or Windows Management Instrumentation (WMI) are frequently abused for lateral movement, since these are legitimate, expected tools in most environments - an attacker using them blends into normal administrative traffic far better than deploying custom malware to every machine.

**Why this stage matters:** initial access rarely lands an attacker directly on their real target. A phishing email might compromise a single employee's laptop, but the actual objective - financial records, intellectual property, domain-wide control - usually sits on different systems the attacker must reach through this expansion phase.

**Detection approach:** since lateral movement often uses legitimate credentials and legitimate tools, detection relies heavily on behavioral baselines - flagging authentication patterns that deviate from a user's normal behavior, such as an account suddenly accessing systems it's never touched before.""",
        "furtherReading": [
            {"label": "MITRE ATT&CK - Lateral Movement Tactic", "url": "https://attack.mitre.org/tactics/TA0008/"}
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

    print(f"\nBatch 2 complete - {len(articles)} articles processed.")
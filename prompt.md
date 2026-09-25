Build a production-style MVP called "APK Sentinel" — an AI-assisted Android APK static security analysis platform.

IMPORTANT:
This application analyzes potentially untrusted APK files. The system must NEVER install, execute, or dynamically run the uploaded APK in the MVP.

The MVP is STATIC ANALYSIS ONLY.

The frontend must be minimal, professional, clean, and security-tool oriented. Do NOT create a flashy SaaS landing page, excessive animations, gradients, neon colors, glassmorphism, or unnecessary UI elements.

==================================================
1. PROJECT OBJECTIVE
==================================================

Build a web application where a user uploads an Android APK.

The backend should:

1. Validate and quarantine the uploaded APK.
2. Calculate SHA-256.
3. Create an isolated analysis workspace.
4. Run APKTool to decode/decompile the APK.
5. Run JADX to produce readable Java-like source code where possible.
6. Parse AndroidManifest.xml.
7. Analyze permissions.
8. Analyze Android application components.
9. Detect exported components and potentially exposed attack surfaces.
10. Scan decompiled code for security-sensitive/suspicious APIs.
11. Extract URLs, domains, IP addresses, and potentially hardcoded secrets.
12. Detect basic obfuscation indicators.
13. Calculate a deterministic risk score using a transparent rule-based scoring engine.
14. Produce structured JSON findings.
15. Send ONLY the structured findings and relevant evidence to the Groq LLM API.
16. Ask the LLM to generate a human-readable security assessment.
17. Display the results in a professional dashboard.

The LLM must NOT be responsible for determining the raw security score.

The deterministic analysis engine calculates the score.

The LLM is an explanation/report-generation layer.

==================================================
2. HIGH-LEVEL ARCHITECTURE
==================================================

Use the following architecture:

Browser
   |
   v
Frontend
   |
   v
FastAPI Backend
   |
   v
Upload / Quarantine
   |
   v
Analysis Job
   |
   v
Isolated Docker Analyzer Container
   |
   +--> APKTool
   |
   +--> JADX
   |
   +--> Manifest Analyzer
   |
   +--> Permission Analyzer
   |
   +--> Component Analyzer
   |
   +--> Suspicious API Analyzer
   |
   +--> Secret/Indicator Analyzer
   |
   +--> Obfuscation Analyzer
   |
   +--> URL/IP Extractor
   |
   v
Deterministic Risk Engine
   |
   v
Structured Analysis JSON
   |
   v
Groq API
   |
   v
AI Security Report
   |
   v
Frontend Dashboard

Keep the architecture modular so dynamic analysis can be added later.

==================================================
3. TECHNOLOGY STACK
==================================================

Backend:
- Python
- FastAPI
- Pydantic
- SQLAlchemy
- SQLite for MVP
- Docker

Frontend:
- React
- TypeScript
- Vite
- Tailwind CSS
- Use a minimal professional design

APK analysis:
- APKTool
- JADX
- Python XML parsing
- Python static analysis utilities

AI:
- Groq API
- API key loaded from environment variables
- Never hardcode API keys

Testing:
- pytest
- backend unit tests
- analyzer tests
- scoring engine tests

==================================================
4. APK ANALYSIS ENVIRONMENT
==================================================

DO NOT decompile the APK directly on the host web server.

Create a dedicated Docker-based analyzer environment.

Example conceptual structure:

analyzer/
    Dockerfile
    entrypoint.sh
    tools/
    scripts/

The analyzer container should contain:

- Java runtime
- APKTool
- JADX
- Python
- required Python dependencies

The uploaded APK should be passed into a controlled analysis workspace.

Example:

/analysis/<analysis_id>/
    input/
        application.apk

    output/
        apktool/
        jadx/
        findings/
        metadata.json

    logs/

APKTool output:

output/apktool/
    AndroidManifest.xml
    smali/
    smali_classes2/
    res/
    assets/
    original/

JADX output:

output/jadx/
    sources/
    resources/

The analyzer must never execute the APK.

The APK is treated strictly as an untrusted archive/input file.

==================================================
5. SECURITY REQUIREMENTS
==================================================

Implement basic sandboxing for the analyzer container.

The analyzer container should:

- Run as a non-root user.
- Have CPU limits.
- Have memory limits.
- Have an analysis timeout.
- Have a maximum APK upload size.
- Have a controlled temporary filesystem/workspace.
- Never receive access to the Docker socket.
- Never mount the host root filesystem.
- Use controlled input/output directories.
- Have restricted network access.
- Clean analysis workspace after completion where appropriate.
- Never execute the APK.
- Never install the APK onto an Android device/emulator.

The backend should validate:

- file extension
- MIME type where practical
- file size
- SHA-256
- malformed uploads

Do not trust the filename supplied by the user.

Generate an internal UUID analysis ID.

Store uploaded files using generated filenames rather than user-controlled filenames.

==================================================
6. DATABASE MODEL
==================================================

Create an Analysis table.

Fields:

id
sha256
original_filename
file_size
status
created_at
started_at
completed_at
risk_score
risk_level
error_message

Possible status values:

QUEUED
RUNNING
COMPLETED
FAILED

Create tables/models for findings if useful, but keep the MVP architecture simple.

==================================================
7. APK METADATA ANALYSIS
==================================================

Extract:

- package name
- application label
- version name
- version code
- min SDK
- target SDK
- APK size
- SHA-256
- number of activities
- number of services
- number of receivers
- number of providers

Also attempt to extract signing/certificate information.

==================================================
8. ANDROID MANIFEST ANALYSIS
==================================================

Parse AndroidManifest.xml.

Analyze:

Permissions
Activities
Services
Broadcast Receivers
Content Providers
Intent filters
Exported components
Permissions protecting components

Detect:

- exported activities
- exported services
- exported receivers
- exported providers
- exported components without permission protection
- suspicious intent filters
- dangerous component exposure

Do not automatically classify every exported component as malicious.

Use appropriate severity and explainability.

==================================================
9. PERMISSION ANALYSIS
==================================================

Create a permission classification system.

Categories should include:

NORMAL
DANGEROUS
SPECIAL
HIGH_RISK

Examples of permissions to recognize:

INTERNET
READ_SMS
RECEIVE_SMS
SEND_SMS
READ_CONTACTS
WRITE_CONTACTS
READ_CALL_LOG
WRITE_CALL_LOG
RECORD_AUDIO
CAMERA
ACCESS_FINE_LOCATION
ACCESS_COARSE_LOCATION
ACCESS_BACKGROUND_LOCATION
READ_EXTERNAL_STORAGE
WRITE_EXTERNAL_STORAGE
REQUEST_INSTALL_PACKAGES
SYSTEM_ALERT_WINDOW
RECEIVE_BOOT_COMPLETED
PACKAGE_USAGE_STATS
BIND_ACCESSIBILITY_SERVICE

Do not claim that a permission alone means malware.

The analyzer should identify:

- individual risk
- excessive permission usage
- suspicious permission combinations

==================================================
10. PERMISSION CORRELATION
==================================================

Implement correlation rules.

Examples:

READ_SMS + INTERNET
RECEIVE_SMS + INTERNET
READ_CONTACTS + INTERNET
RECORD_AUDIO + INTERNET
ACCESS_FINE_LOCATION + INTERNET
RECEIVE_BOOT_COMPLETED + background service + INTERNET
REQUEST_INSTALL_PACKAGES + INTERNET

These combinations should increase the risk score.

The correlation engine must be transparent.

Every score contribution should contain:

rule_id
description
evidence
points
severity

==================================================
11. SUSPICIOUS API ANALYSIS
==================================================

Search JADX/decompiled source and/or smali code for security-sensitive APIs.

At minimum detect:

Runtime.exec
ProcessBuilder
DexClassLoader
PathClassLoader
System.loadLibrary
SmsManager
TelephonyManager
LocationManager
MediaRecorder
AudioRecord
Camera
Camera2
WebView
HttpURLConnection
URLConnection
Socket
DatagramSocket
Cipher
MessageDigest
SecretKeySpec
Base64
Reflection APIs

Group findings into categories:

PROCESS_EXECUTION
DYNAMIC_CODE_LOADING
SMS
TELEPHONY
LOCATION
AUDIO
CAMERA
NETWORKING
CRYPTOGRAPHY
WEBVIEW
REFLECTION

Do NOT label the API itself as malicious.

For each finding provide:

category
matched_api
file
line if available
severity
explanation

==================================================
12. URL / DOMAIN / IP EXTRACTION
==================================================

Extract potential:

- HTTP URLs
- HTTPS URLs
- domains
- IPv4 addresses
- IPv6 addresses where practical

Return:

indicator
type
source_file
context

Do not automatically label every IP/domain as malicious.

==================================================
13. HARD-CODED SECRET DETECTION
==================================================

Implement basic regex-based detection for potential:

- API keys
- access tokens
- JWTs
- passwords
- private keys
- cloud credentials
- authorization headers

Use entropy analysis where useful.

Clearly label these as:

"Potential hardcoded secret"

not as confirmed credentials.

Return:

type
matched pattern
source file
line
redacted evidence

Never expose an entire secret in the frontend report.

==================================================
14. OBFUSCATION ANALYSIS
==================================================

Implement basic static obfuscation indicators.

Examples:

- extremely short class names
- extremely short method names
- high proportion of meaningless identifiers
- unusually high string encoding
- suspicious use of Base64
- dynamic class loading

Generate an obfuscation score.

Do not claim obfuscation means malware.

Explain that legitimate applications also use obfuscation.

==================================================
15. RISK SCORING ENGINE
==================================================

Create a deterministic scoring engine.

The LLM must NOT calculate the raw score.

Suggested categories:

Permission Risk: 25%
Code/API Risk: 35%
Component Exposure: 20%
Indicators/Metadata: 20%

Normalize the total score to 0-100.

Risk levels:

0-20: LOW
21-40: MODERATE
41-60: MEDIUM
61-80: HIGH
81-100: CRITICAL

These thresholds are project-defined and must be clearly documented.

Every score must be explainable.

Example:

Permission Risk:
+8 READ_SMS
+8 RECEIVE_SMS
+2 INTERNET

Correlation:
+8 READ_SMS + INTERNET

API:
+7 SmsManager
+8 DexClassLoader

Component:
+6 exported component without protection

The frontend should display a "Why this score?" breakdown.

==================================================
16. STRUCTURED ANALYSIS JSON
==================================================

Create a canonical JSON schema.

Example:

{
  "analysis_id": "...",
  "apk": {
    "package": "...",
    "version": "...",
    "target_sdk": 28,
    "sha256": "..."
  },

  "permissions": [],

  "components": [],

  "suspicious_apis": [],

  "network_indicators": [],

  "potential_secrets": [],

  "obfuscation": {},

  "findings": [],

  "score": {
    "total": 76,
    "level": "HIGH",
    "breakdown": {}
  }
}

This JSON is the single source of truth for the report.

==================================================
17. GROQ LLM INTEGRATION
==================================================

Use Groq API.

Read the API key from:

GROQ_API_KEY

in environment variables.

Never commit the API key.

The LLM receives the structured analysis JSON.

Do NOT send the complete APK.

Do NOT send unnecessary decompiled source.

Only send relevant findings/evidence.

The LLM should generate:

1. Executive Summary
2. Overall Risk Assessment
3. Key Findings
4. Evidence
5. Explanation of each finding
6. Potential security implications
7. Recommended remediation
8. Limitations of static analysis

The LLM must explicitly distinguish:

OBSERVED FACT
from
INTERPRETATION
from
POTENTIAL RISK

It must never claim an APK is definitively malware based only on static indicators.

Use structured JSON output from the LLM where possible.

==================================================
18. FRONTEND DESIGN
==================================================

The frontend must be minimal and professional.

Avoid:

- excessive gradients
- flashy animations
- huge hero sections
- neon cyberpunk aesthetics
- unnecessary illustrations
- excessive cards
- glassmorphism

Use a professional security-console aesthetic.

Pages:

1. Dashboard
2. Upload APK
3. Analysis Progress
4. Analysis Results
5. Analysis History

Dashboard should show:

- total analyses
- recent analyses
- risk distribution
- latest analysis

Upload page:

- simple drag/drop or file selector
- APK validation
- file size
- SHA-256 after upload
- Analyze button

Results page:

Header:

APK name
Package name
SHA-256
Analysis timestamp

Risk section:

RISK SCORE
78/100
HIGH

Score breakdown:

Permissions
Code
Components
Indicators

Findings section:

CRITICAL
HIGH
MEDIUM
LOW

Each finding should show:

Title
Severity
Description
Evidence
Source file
Line number if available
Score contribution

Also include:

"Why this score?"

and

"AI Security Assessment"

==================================================
19. API ENDPOINTS
==================================================

Implement:

POST /api/analyses
Upload APK and create analysis.

GET /api/analyses
List analyses.

GET /api/analyses/{id}
Return analysis metadata/status.

GET /api/analyses/{id}/results
Return structured findings.

GET /api/analyses/{id}/report
Return AI report.

DELETE /api/analyses/{id}
Delete analysis data.

==================================================
20. BACKGROUND ANALYSIS
==================================================

Do not block the HTTP request while APK analysis is running.

Implement a simple background job system for MVP.

Flow:

POST /api/analyses
        |
        v
Create analysis record
        |
        v
QUEUED
        |
        v
RUNNING
        |
        v
Docker analyzer
        |
        v
Static analysis
        |
        v
Risk scoring
        |
        v
Groq report
        |
        v
COMPLETED

The frontend should poll the status endpoint.

Design the system so Celery/Redis can replace the MVP background worker later.

==================================================
21. LOGGING
==================================================

Use structured application logging.

Log:

analysis ID
stage
duration
success/failure
tool errors

Never log:

API keys
full secrets
sensitive extracted credentials

==================================================
22. ERROR HANDLING
==================================================

Handle:

- invalid APK
- corrupted APK
- APKTool failure
- JADX failure
- timeout
- analyzer container failure
- Groq API failure
- malformed LLM response

If Groq fails, the static analysis should still be available.

The system should not fail completely because AI report generation failed.

==================================================
23. TESTING
==================================================

Create tests for:

- APK hash generation
- permission classification
- permission correlation
- exported component detection
- suspicious API detection
- URL extraction
- secret detection
- obfuscation detection
- scoring engine
- risk levels
- API endpoints

Create a small set of safe test APK fixtures.

DO NOT use real malware as test fixtures.

==================================================
24. DOCUMENTATION
==================================================

Create a README containing:

- project overview
- architecture
- threat model
- security assumptions
- installation
- Docker setup
- environment variables
- APK analysis pipeline
- scoring methodology
- Groq integration
- API documentation
- limitations
- future dynamic-analysis architecture

Include a clear statement:

"This MVP performs static analysis only. Uploaded APKs are not installed or executed."

==================================================
25. FUTURE EXTENSIBILITY
==================================================

Design interfaces so future modules can be added:

StaticAnalyzer
ManifestAnalyzer
PermissionAnalyzer
ComponentAnalyzer
ApiAnalyzer
SecretAnalyzer
NetworkIndicatorAnalyzer
ObfuscationAnalyzer
YaraAnalyzer
DynamicAnalyzer

DynamicAnalyzer must NOT be implemented in the MVP.

Future dynamic analysis could use an isolated Android emulator/sandbox and observe:

- runtime API calls
- processes
- filesystem changes
- network traffic
- DNS
- permissions
- services

But keep this as a future module.

==================================================
26. DEVELOPMENT PRIORITY
==================================================

Implement in this order:

PHASE 1:
Project structure
FastAPI
React frontend
Docker
health endpoint

PHASE 2:
APK upload
SHA-256
quarantine
analysis database
analysis status

PHASE 3:
Analyzer Docker container
APKTool
JADX

PHASE 4:
Manifest analyzer
Permission analyzer
Component analyzer

PHASE 5:
Suspicious API analyzer
URL/IP extraction
Secret detection
Obfuscation analysis

PHASE 6:
Risk scoring engine

PHASE 7:
Groq integration

PHASE 8:
Professional results dashboard

PHASE 9:
Tests
Security hardening
Documentation

Do not over-engineer early phases.

==================================================
27. IMPORTANT ENGINEERING PRINCIPLES
==================================================

1. Static analysis first.
2. Never execute uploaded APKs.
3. Never let the LLM determine the raw risk score.
4. Every score must be explainable.
5. Every security finding must contain evidence.
6. Avoid false claims such as "this APK is malware."
7. Treat findings as indicators unless confirmed.
8. Keep analyzer execution isolated.
9. Never hardcode secrets.
10. Make the analyzer modular.
11. Keep the frontend professional and minimal.
12. Prioritize correctness over visual complexity.

Start by generating the complete repository structure and architecture.

Then implement Phase 1 and Phase 2.

Do not attempt to implement every feature in a single step.

After each phase, ensure the application runs successfully and provide clear instructions for testing it locally.
# ThreatLens AI

Malware Classification & Threat Detection System — Internship Project (Milestone 1)

## What's implemented
- JWT-based authentication (signup/login) with bcrypt password hashing
- File upload endpoint (protected, requires login)
- Static analysis: MD5/SHA-256 hashing, signature/keyword scanning, URL extraction
- Risk scoring and classification
- SQLite database with User, FileRecord, and AnalysisResult tables

## Tech stack
FastAPI, SQLAlchemy, SQLite, python-jose (JWT), bcrypt

## Run it
\`\`\`
pip install -r requirements.txt
uvicorn main:app --reload
\`\`\`
Then visit http://127.0.0.1:8000/docs

import hashlib
import re

SUSPICIOUS_KEYWORDS = [
    b"powershell",
    b"cmd.exe",
    b"CreateRemoteThread",
    b"VirtualAlloc",
    b"WinExec",
    b"URLDownloadToFile",
]

URL_PATTERN = re.compile(rb"https?://[^\s\"'<>]+")


def compute_hashes(file_bytes: bytes) -> dict:
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


def scan_signatures(file_bytes: bytes) -> dict:
    found_keywords = [kw.decode() for kw in SUSPICIOUS_KEYWORDS if kw in file_bytes]
    found_urls = list({m.decode(errors="ignore") for m in URL_PATTERN.findall(file_bytes)})
    return {"keywords": found_keywords, "urls": found_urls}
def calculate_risk_score(signature_results: dict) -> int:
    score = 0
    score += len(signature_results["keywords"]) * 20
    score += len(signature_results["urls"]) * 10
    return min(score, 100)


def classify(risk_score: int) -> str:
    if risk_score >= 60:
        return "Suspicious - High Risk"
    if risk_score >= 30:
        return "Suspicious - Low Risk"
    return "Likely Benign"


def analyze_file(file_bytes: bytes) -> dict:
    hashes = compute_hashes(file_bytes)
    signatures = scan_signatures(file_bytes)
    risk_score = calculate_risk_score(signatures)
    classification = classify(risk_score)

    return {
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
        "file_size": len(file_bytes),
        "keywords": signatures["keywords"],
        "urls": signatures["urls"],
        "risk_score": risk_score,
        "classification": classification,
    }
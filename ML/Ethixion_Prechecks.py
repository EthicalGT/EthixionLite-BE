import re
import time
import base64
from typing import Dict, Any, List
from collections import defaultdict
from hashlib import sha256

# --- In-memory history storage ---
HISTORY_DB = defaultdict(list)  # Stores past requests per IP/user/API

class EthixionMLSecurity:
    def __init__(self):
        self.patterns = [
            r"(?i)\bunion\s+select\b",
            r"(?i)<script.*?>.*?</script>",
            r"(?i)or\s+1\s*=\s*1",
            r"(?i)/etc/passwd",
            r"(?i)\.\./\.\./",
            r"(?i)\brm\s+-rf\s+/",
            r"(?i)wget\s+http",
            r"(?i)curl\s+http",
            r"(?i)base64_decode",
            r"(?i)php://input",
            r"(?i)data:text/html",
            r"(?i)<iframe.*?>",
            r"(?i)<img\s+src\s*=.*?onerror\s*=.*?>",
            r"(?i)file://",
            r"(?i)localhost",
            r"(?i)127\.\d+\.\d+\.\d+",
        ]
        self.max_uri_len = 2048
        self.max_body_len = 10000
        self.max_header_len = 512
        self.high_risk_ip_score = 5

    def decode_payloads(self, data: str) -> List[str]:
        decoded_variants = [data]
        # Try base64 decode
        try:
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            if decoded != data:
                decoded_variants.append(decoded)
        except:
            pass
        # Try hex decode
        try:
            if re.fullmatch(r"[0-9a-fA-F]+", data):
                decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
                if decoded != data:
                    decoded_variants.append(decoded)
        except:
            pass
        return decoded_variants

    def extract_features(self, request: Dict[str, Any]) -> Dict[str, Any]:
        features = {}
        features['method'] = request.get("method", "").upper()
        features['uri_len'] = len(request.get("uri", ""))
        features['body_len'] = len(request.get("body", ""))
        features['header_count'] = len(request.get("headers", {}))
        features['content_type'] = request.get("content_type", "")
        features['user_agent_len'] = len(request.get("headers", {}).get("user-agent", ""))
        features['ip_risk_score'] = request.get("ip_risk_score", 0)
        features['rate_limit_exceeded'] = request.get("rate_limit_exceeded", False)
        return features

    def check_patterns(self, data: str, threats_detected: List[str]):
        for variant in self.decode_payloads(data):
            for pat in self.patterns:
                if re.search(pat, variant):
                    threats_detected.append(f"Suspicious Pattern Detected: {pat}")

    def analyze_behavior(self, ip: str, user: str, api: str, threats_detected: List[str]):
        # Check timing and sequences
        now = time.time()
        history = HISTORY_DB[(ip, user, api)]
        if history:
            last_time = history[-1]['timestamp']
            delta = now - last_time
            if delta < 0.5:  # less than 0.5 sec between requests is suspicious
                threats_detected.append("Rapid repeated requests detected (possible bot/brute force)")
            if len(history) > 10:  # more than 10 requests in short span
                recent = [r['timestamp'] for r in history[-10:]]
                if now - recent[0] < 5:  # 10 requests within 5 sec
                    threats_detected.append("Burst of requests detected (possible DDoS attempt)")

    def analyze_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        threats_detected: List[str] = []

        features = self.extract_features(request)
        ip = request.get("ip", "0.0.0.0")
        user = request.get("user", "anon")
        api = request.get("apiname", "unknown_api")

        # --- Behavioral Analysis ---
        self.analyze_behavior(ip, user, api, threats_detected)

        # --- Rate limiting ---
        if features['rate_limit_exceeded']:
            threats_detected.append("Rate limit exceeded")

        # --- Method & header anomalies ---
        if features['method'] not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            threats_detected.append(f"Suspicious HTTP method: {features['method']}")
        if features['user_agent_len'] > self.max_header_len or features['user_agent_len']==0:
            threats_detected.append("Suspicious User-Agent detected")
        if "host" not in request.get("headers", {}) or not request["headers"]["host"]:
            threats_detected.append("Missing Host header")

        # --- URI & body checks ---
        if features['uri_len'] > self.max_uri_len:
            threats_detected.append(f"URI length unusually long ({features['uri_len']})")
        if features['body_len'] > self.max_body_len:
            threats_detected.append(f"Request body too large ({features['body_len']} bytes)")

        # --- Content & payload checks ---
        payload = request.get("uri", "") + " " + request.get("body", "")
        self.check_patterns(payload, threats_detected)

        # --- Historical / repeated attacks ---
        history = HISTORY_DB[(ip, user, api)]
        past_threat_count = sum(len(r['threats']) for r in history)
        if past_threat_count > 5:
            threats_detected.append("Repeated attacks from same IP/user/API detected")

        # --- Update history ---
        HISTORY_DB[(ip, user, api)].append({
            "timestamp": time.time(),
            "request_hash": sha256(payload.encode()).hexdigest(),
            "threats": threats_detected.copy()
        })

        status = "success" if not threats_detected else "unsafe"
        return {
            "status": status,
            "threats_detected": threats_detected
        }

# --- Example Usage ---
if __name__ == "__main__":
    ml_engine = EthixionMLSecurity()

    request_example = {
        "method": "GET",
        "uri": "/api/v1/data?user=1' OR 1=1 --",
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0", "host": "example.com", "referer": "127.0.0.1"},
        "ip": "192.168.1.1",
        "user": "testuser",
        "apiname": "my_api",
        "ip_risk_score": 3,
        "rate_limit_exceeded": False,
        "content_type": "application/json"
    }

    result = ml_engine.analyze_request(request_example)
    print(result)

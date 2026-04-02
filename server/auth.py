"""Agent token auth - HMAC signed tokens."""
import os, time, hmac, hashlib, base64, json
from fastapi import HTTPException

def _secret():
    s = os.environ.get("AGENT_SECRET","")
    if not s:
        try:
            for line in open("/opt/cibervault/server.env"):
                if line.strip().startswith("AGENT_SECRET="):
                    s = line.strip().split("=",1)[1]
                    break
        except: pass
    return (s or "cibervault-default").encode()

def create_token(agent_id):
    d = base64.urlsafe_b64encode(json.dumps({"agent_id":agent_id,"iat":int(time.time())}).encode()).decode()
    s = hmac.new(_secret(), d.encode(), hashlib.sha256).hexdigest()
    return f"{d}.{s}"

def verify_token(auth):
    try:
        scheme, token = auth.split(" ", 1)
        if scheme.lower() != "bearer": raise ValueError("not bearer")
        d, s = token.rsplit(".", 1)
        if not hmac.compare_digest(s, hmac.new(_secret(), d.encode(), hashlib.sha256).hexdigest()):
            raise ValueError("bad sig")
        return json.loads(base64.urlsafe_b64decode(d + "=="))["agent_id"]
    except HTTPException: raise
    except Exception as e: raise HTTPException(401, f"Invalid token: {e}")

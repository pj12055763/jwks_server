from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import jwt  # Requires PyJWT
import time

app = Flask(__name__)

# Generate two RSA key pairs
valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Helper to extract JWK components
def extract_jwk_components(key, kid):
    pub = key.public_key().public_numbers()
    n = base64.urlsafe_b64encode(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()
    e = base64.urlsafe_b64encode(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e
    }

# JWKS endpoint (only exposes valid key)
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    jwk = extract_jwk_components(valid_key, "valid-key")
    return jsonify({"keys": [jwk]})

# Reject unsupported methods for JWKS
@app.route("/.well-known/jwks.json", methods=["POST", "PUT", "DELETE", "PATCH", "HEAD"])
def jwks_invalid_methods():
    return jsonify({"error": "Method not allowed"}), 405

# Auth endpoint (returns valid or expired JWT)
@app.route("/auth", methods=["POST", "GET"])
def auth():
    expired = request.args.get("expired") == "true"
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "iat": now,
        "exp": now + (3600 if not expired else -3600)
    }
    signing_key = expired_key if expired else valid_key
    kid = "expired-key" if expired else "valid-key"
    token = jwt.encode(payload, signing_key, algorithm="RS256", headers={"kid": kid})
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return jsonify({"token": token})

# Reject unsupported methods for /auth
@app.route("/auth", methods=["PUT", "DELETE", "PATCH", "HEAD"])
def auth_invalid_methods():
    return jsonify({"error": "Method not allowed"}), 405

# Run server on port 8080 for Gradebot
if __name__ == "__main__":
    app.run(port=8080)

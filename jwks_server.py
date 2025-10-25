#jgp0127
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import jwt  # Requires PyJWT
import time
import sqlite3
from cryptography.hazmat.primitives import serialization


app = Flask(__name__)

conn = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS keys (
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    exp INTEGER NOT NULL
)
""")
conn.commit()


def generate_and_store_keys():
    now = int(time.time())
    future_exp = now + 3600
    past_exp = now - 3600

    for exp in [future_exp, past_exp]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp))
    conn.commit()

generate_and_store_keys()

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
    now = int(time.time())
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
    rows = cursor.fetchall()
    jwks = []
    for kid, pem in rows:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        jwks.append(extract_jwk_components(key, str(kid)))
    return jsonify({"keys": jwks})

# Reject unsupported methods for JWKS
@app.route("/.well-known/jwks.json", methods=["POST", "PUT", "DELETE", "PATCH", "HEAD"])
def jwks_invalid_methods():
    return jsonify({"error": "Method not allowed"}), 405

# Auth endpoint (returns valid or expired JWT)
@app.route("/auth", methods=["POST", "GET"])
def auth():
    expired = request.args.get("expired") == "true"
    now = int(time.time())
    query = "SELECT kid, key FROM keys WHERE exp <= ?" if expired else "SELECT kid, key FROM keys WHERE exp > ?"
    cursor.execute(query, (now,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "No matching key found"}), 404

    kid, pem = row
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    payload = {
        "sub": "test-user",
        "iat": now,
        "exp": now + (3600 if not expired else -3600)
    }
    token = jwt.encode(payload, key, algorithm="RS256", headers={"kid": str(kid)})
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

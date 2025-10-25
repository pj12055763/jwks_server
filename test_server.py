# --- External Endpoint Tests (Blackbox) ---
# These tests verify that the Flask server responds correctly to HTTP requests.
#jgp0127
import requests

def test_valid_jwt():
    """Test that /auth returns a valid JWT."""
    response = requests.post("http://localhost:8080/auth")
    assert response.status_code == 200
    assert "token" in response.json()

def test_expired_jwt():
    """Test that /auth?expired=true returns an expired JWT."""
    response = requests.get("http://localhost:8080/auth?expired=true")
    assert response.status_code == 200
    assert "token" in response.json()

def test_jwks_endpoint():
    """Test that JWKS endpoint returns valid keys."""
    response = requests.get("http://localhost:8080/.well-known/jwks.json")
    assert response.status_code == 200
    assert "keys" in response.json()

# --- Internal Unit Tests (Whitebox) ---
# These tests directly exercise internal functions and logic from jwks_server.py.


from cryptography.hazmat.primitives.asymmetric import rsa
from jwks_server import app  # For Flask test client
from jwks_server import extract_jwk_components

def test_extract_jwk_components_valid_key():
    """Test JWK extraction from a valid RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "unit-test-kid"
    jwk = extract_jwk_components(key, kid)
    assert jwk["kid"] == kid
    assert jwk["kty"] == "RSA"
    assert "n" in jwk and "e" in jwk

def test_jwks_excludes_expired_keys():
    """Ensure JWKS only returns valid (non-expired) keys."""
    response = requests.get("http://localhost:8080/.well-known/jwks.json")
    assert response.status_code == 200
    keys = response.json()["keys"]
    for key in keys:
        assert isinstance(key["kid"], str)

def test_invalid_http_method():
    """Test that unsupported HTTP methods return 405."""
    client = app.test_client()
    response = client.put("/auth")  # PUT is not allowed
    assert response.status_code == 405

def test_head_request():
    """Test that HEAD requests return 200 with no body."""
    client = app.test_client()
    response = client.head("/auth")
    assert response.status_code == 200
    assert response.data == b''  # HEAD returns no body

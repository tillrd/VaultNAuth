"""VaultNAuth: Generate and test JWT tokens with self-signed certificates for VaultN API authentication."""
import os
import sys
import subprocess
import datetime
import base64
import hashlib
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509


def generate_pfx_if_missing(pfx_path, password):
    """Generate a self-signed certificate and related files if missing."""
    if os.path.exists(pfx_path):
        return

    print("⚠️  .pfx file not found. Generating new self-signed certificate...")

    certs_dir = os.path.dirname(pfx_path)
    if certs_dir and not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    key_file = os.path.join(certs_dir, "temp_key.pem")
    cert_file = os.path.join(certs_dir, "temp_cert.pem")
    req_file = os.path.join(certs_dir, "temp_req.pem")

    subprocess.run([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_file, "-out", req_file,
        "-subj", "/CN=VaultN"
    ], check=True)

    subprocess.run([
        "openssl", "x509", "-req", "-days", "365",
        "-in", req_file, "-signkey", key_file,
        "-out", cert_file
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    subprocess.run([
        "openssl", "pkcs12", "-export",
        "-out", pfx_path,
        "-inkey", key_file, "-in", cert_file,
        "-passout", f"pass:{password.decode()}"
    ], check=True)

    base = os.path.splitext(pfx_path)[0]
    crt_path = base + ".crt"
    cer_path = base + ".cer"
    pub_pem_path = base + "_public_cert.pem"
    priv_pem_path = base + "_private_key.pem"

    with open(cert_file, "rb") as f:
        cert_data = f.read()
    with open(key_file, "rb") as f:
        key_data = f.read()

    with open(crt_path, "wb") as f:
        f.write(cert_data)
    with open(cer_path, "wb") as f:
        f.write(cert_data)
    with open(pub_pem_path, "wb") as f:
        f.write(cert_data)
    with open(priv_pem_path, "wb") as f:
        f.write(key_data)

    os.remove(cert_file)
    os.remove(key_file)
    os.remove(req_file)

    crt = x509.load_pem_x509_certificate(cert_data, backend=default_backend())
    pubkey_from_cert = crt.public_key()
    privkey = serialization.load_pem_private_key(
        key_data, password=None, backend=default_backend()
    )

    cert_modulus = pubkey_from_cert.public_numbers().n \
        if isinstance(pubkey_from_cert, rsa.RSAPublicKey) else None
    priv_modulus = privkey.private_numbers().public_numbers.n \
        if isinstance(privkey, rsa.RSAPrivateKey) else None

    if cert_modulus and priv_modulus:
        if cert_modulus == priv_modulus:
            print("🔗 Certificate and private key match ✔️")
        else:
            print("❌ WARNING: Certificate and private key DO NOT match!")
    else:
        print("⚠️ Could not verify key/certificate match (non-RSA key?)")

    print("\n📁 Certificate and Key Files Created:")
    print(" ├── 🔐 PFX:             ", pfx_path)
    print(" ├── 📄 CRT (cert):      ", crt_path)
    print(" ├── 📄 CER (cert):      ", cer_path)
    print(" ├── 📜 Public PEM:      ", pub_pem_path)
    print(" └── 🔑 Private PEM:     ", priv_pem_path)
    print("\n✅ Certificate generation complete.\n")


def test_vaultn_api(token):
    """Test connectivity and JWT authorization with VaultN API."""
    url = "https://sbx-api.vaultn.com/api/v1/ping"
    headers = {
        "Authorization": f"Bearer {token}",
        "accept": "application/json"
    }

    print("\n🌐 Testing VaultN API...")
    try:
        response = requests.get(url, headers=headers, timeout=10)
        status = response.status_code
        print(f"{'✅' if status == 200 else '❌'} Response Status: {status}")
        print("📄 Response Body:")
        print(response.text)
    except requests.RequestException as exc:
        print("❌ Failed to reach VaultN API:", exc)


def load_private_key_and_cert(pfx_path, password):
    """Load private key and certificate from a PFX file."""
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()
    private_key, cert, _ = load_key_and_certificates(
        pfx_data, password, backend=default_backend()
    )
    return private_key, cert


def get_jwt_payload(user_guid, issuer, audience):
    """Return the JWT payload dict."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "sub": user_guid,
        "iss": issuer,
        "aud": audience,
        "exp": now + datetime.timedelta(days=365),
        "iat": now
    }


def get_jwt_headers(cert):
    """Return JWT headers with x5t and kid from cert."""
    cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
    hash_sha1 = hashlib.sha1(cert_der).digest()
    x5t = base64.urlsafe_b64encode(hash_sha1).decode().rstrip('=')
    kid = hash_sha1.hex().upper()
    return {
        'alg': 'RS256',
        'typ': 'JWT',
        'kid': kid,
        'x5t': x5t
    }, kid


def print_thumbprint_info(kid):
    """Print thumbprint info and check against known uploaded certs."""
    fingerprint = ':'.join(a + b for a, b in zip(kid[::2], kid[1::2]))
    print(f"\n🔑 SHA-1 Certificate Thumbprint (VaultN): {fingerprint}")
    print(f"🔑 Raw Thumbprint (no colons): {kid}")
    known_uploaded = {
        "5625A9ED086B6EF60B45EAE95329F171615780B1",
        "230C09BD60E050E5E6DA6D3AC0B3B49C92560687",
        "9665D87B321BE24C58511F4A826F5C8F75DB1597",
        "CCB713A48BBCE086A73CFD08CB0333ECF6A25A1E",
        "0B010A41ABA29812DE87CDC834E071EE2F93C8BE"
    }
    if kid not in known_uploaded:
        print("⚠️ WARNING: This certificate thumbprint was NOT found in VaultN uploaded list.")
        print("   Upload `sample.crt` to VaultN, or verify the correct certificate is selected.")


def verify_certificate_in_vaultn(token, user_guid):
    """Loop until VaultN recognizes the certificate and token."""
    while True:
        try:
            print("\n🔍 Verifying certificate thumbprint in VaultN...")
            resp = requests.get(
                "https://sbx-api.vaultn.com/api/v1/ping",
                headers={
                    "Authorization": f"Bearer {token}",
                    "accept": "application/json"
                },
                timeout=10
            )
            if resp.status_code == 401 and "No certificate for owner" in resp.text:
                print(
                    "❌ VaultN did not recognize the certificate for this GUID and thumbprint."
                )
                print(
                    "   ➤ Make sure you've uploaded 'sample.crt' in the correct environment (Sandbox vs Prod)."
                )
                print("   ➤ Ensure the certificate is assigned to GUID:", user_guid)
                input(
                    "\nPlease check your upload and assignment, then press Enter to try again..."
                )
                continue
            if resp.status_code == 200:
                print("✅ VaultN recognized the certificate and the token is valid.")
            else:
                print(f"⚠️ Unexpected response from VaultN: {resp.status_code}")
                print(resp.text)
                input(
                    "\nPlease check your upload and assignment, then press Enter to try again..."
                )
                continue
            break
        except requests.RequestException as exc:
            print("❌ Error verifying certificate registration with VaultN:", exc)
            input(
                "\nPlease check your upload and assignment, then press Enter to try again..."
            )
            continue


def generate_token(user_guid, issuer, audience, pfx_path, pfx_password):
    """Generate a JWT token signed with the private key from the PFX file."""
    generate_pfx_if_missing(pfx_path, pfx_password)
    private_key, cert = load_private_key_and_cert(pfx_path, pfx_password)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    payload = get_jwt_payload(user_guid, issuer, audience)
    headers, kid = get_jwt_headers(cert)
    token = jwt.encode(
        payload,
        pem_private_key,
        algorithm="RS256",
        headers=headers
    )
    print_thumbprint_info(kid)
    verify_certificate_in_vaultn(token, user_guid)
    return token


def check_and_prepare_cert(crt_path, pfx_path, pfx_password):
    """Prompt for GUID and ensure certificate is present or generated."""
    user_guid = input("Enter your VaultN User GUID: ").strip()
    if not os.path.exists(crt_path):
        print(f"\n⚠️  Certificate file '{crt_path}' not found.")
        print("Attempting to generate a new certificate...")
        generate_pfx_if_missing(pfx_path, pfx_password)
        if not os.path.exists(crt_path):
            print(f"❌ Failed to generate '{crt_path}'. Please check permissions or OpenSSL installation.")
            sys.exit(1)
        print(f"\n✅ Certificate '{crt_path}' has been created.")
        print("\nPlease upload this certificate to the VaultN portal and assign it to your GUID.")
        input("Once uploaded, press Enter to continue...")
    print(f"\n✅ Certificate '{crt_path}' found. Proceeding...\n")
    return user_guid


def main():
    """Main entry point for VaultNAuth CLI."""
    pfx_path = os.path.join("certificates", "sample.pfx")
    crt_path = os.path.join("certificates", "sample.crt")
    pfx_password = b"password"
    audience = "VAULTN"
    issuer = "Self"
    user_guid = check_and_prepare_cert(crt_path, pfx_path, pfx_password)
    try:
        token = generate_token(user_guid, issuer, audience, pfx_path, pfx_password)
        print("\n🔐 Bearer Token (valid for 1 year):")
        print(" ┌────────────────────────────────────────────────────────────────────┐")
        print(" │  Use this token in Authorization headers as shown below:          │")
        print(" └────────────────────────────────────────────────────────────────────┘")
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        print(f"\nAuthorization: Bearer {token}\n")
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = datetime.datetime.fromtimestamp(decoded["exp"], tz=datetime.timezone.utc)
        iat = datetime.datetime.fromtimestamp(decoded["iat"], tz=datetime.timezone.utc)
        print("📆 Token Timestamps (UTC):")
        print(" ├─ Issued At (iat):", iat.isoformat())
        print(" └─ Expires At (exp):", exp.isoformat())
        test_vaultn_api(token)
    except Exception as exc:
        print(f"❌ Error generating token: {exc}")


if __name__ == "__main__":
    main()

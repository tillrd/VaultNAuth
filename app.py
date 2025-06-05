"""VaultNAuth: Generate and test JWT tokens with self-signed certificates for VaultN API authentication."""
import os
import sys
import subprocess
import datetime
import base64
import hashlib
import argparse
import configparser
from getpass import getpass, GetPassWarning
import warnings
import json

from jose import jwt as jose_jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

CONFIG_PATH = os.path.expanduser("~/.vaultnauthrc")

def load_config():
    """Load configuration from the config file."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    return config

def save_config(config):
    """Save configuration to the config file."""
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        config.write(f)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="VaultNAuth CLI")
    parser.add_argument("--env", choices=["sandbox", "production"], help="Environment to use")
    parser.add_argument("--guid", help="VaultN User GUID")
    parser.add_argument("--token-only", action="store_true", help="Only print the Bearer token and exit")
    parser.add_argument("--pfx-password", help="Password for the PFX file (will prompt if not provided)")
    return parser.parse_args()

# Environment configuration
ENVIRONMENTS = {
    "sandbox": {
        "api_base_url": "https://sbx-api.vaultn.com/",
        "cert_name": "sample",
        "desc": "Sandbox"
    },
    "production": {
        "api_base_url": "https://api.vaultn.com/",
        "cert_name": "prod_sample",
        "desc": "Production"
    }
}

def select_environment():
    """Prompt user to select environment (sandbox or production)."""
    print("\n🌍 Select environment:")
    print("  1. Sandbox (testing)")
    print("  2. Production (live)")
    while True:
        choice = input("Enter 1 for Sandbox or 2 for Production: ").strip()
        if choice == "1":
            return "sandbox"
        if choice == "2":
            return "production"
        print("Invalid choice. Please enter 1 or 2.")

def generate_pfx_if_missing(pfx_path, password):
    """Generate a self-signed certificate and related files if missing.

    Args:
        pfx_path (str): Path where the PFX file should be created
        password (bytes): Password to protect the PFX file
    """
    if os.path.exists(pfx_path):
        return

    print("⚠️  .pfx file not found. Generating new self-signed certificate...")

    certs_dir = os.path.dirname(pfx_path)
    if certs_dir and not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    key_file = os.path.join(certs_dir, "temp_key.pem")
    cert_file = os.path.join(certs_dir, "temp_cert.pem")
    req_file = os.path.join(certs_dir, "temp_req.pem")

    # Generate certificate files
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

    # Create additional certificate formats
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

    # Clean up temporary files
    os.remove(cert_file)
    os.remove(key_file)
    os.remove(req_file)

    # Verify key pair matches
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


def is_cloudflare_block(response_text):
    """Detect if the response is a Cloudflare block page (HTML)."""
    return response_text.strip().startswith("<!DOCTYPE html>") and "cloudflare" in response_text.lower()


def test_vaultn_api(token, api_base_url, env_desc):
    """Test connectivity and JWT authorization with VaultN API."""
    url = api_base_url.rstrip("/") + "/api/v1/ping"
    headers = {
        "Authorization": f"Bearer {token}",
        "accept": "application/json"
    }
    print(f"\n🌐 Testing VaultN API on {env_desc}...")
    try:
        response = requests.get(url, headers=headers, timeout=10)
        status = response.status_code
        print(f"{'✅' if status == 200 else '❌'} Response Status: {status}")
        print("📄 Response Body:")
        if is_cloudflare_block(response.text):
            print("Cloudflare blocked the request, probably IP is not whitelisted.")
        else:
            print(response.text)
    except requests.RequestException as exc:
        print("❌ Failed to reach VaultN API:", exc)


def load_private_key_and_cert(pfx_path, password):
    """Load private key and certificate from a PFX file.

    Args:
        pfx_path (str): Path to the PFX file
        password (bytes): Password to decrypt the PFX file

    Returns:
        tuple: (private_key, certificate)
    """
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()
    private_key, cert, _ = load_key_and_certificates(
        pfx_data, password, backend=default_backend()
    )
    return private_key, cert


def get_jwt_payload(user_guid, issuer, audience):
    """Return the JWT payload dictionary.

    Args:
        user_guid (str): The VaultN User GUID
        issuer (str): The token issuer
        audience (str): The token audience

    Returns:
        dict: The JWT payload
    """
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    exp = now + 60 * 60 * 24 * 365  # 1 year
    return {
        "sub": user_guid.upper(),
        "iss": issuer,
        "aud": audience,
        "exp": exp,
        "iat": now,
        "nbf": now
    }


def get_jwt_headers(cert):
    """Return JWT headers with x5t and kid from cert.

    Args:
        cert: The X.509 certificate object

    Returns:
        tuple: (headers_dict, kid_string)
    """
    cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
    hash_sha1 = hashlib.sha1(cert_der).digest()
    x5t = base64.urlsafe_b64encode(hash_sha1).decode().rstrip('=')
    kid = hash_sha1.hex().upper()  # Use hex, not base64url
    return {
        'alg': 'RS256',
        'typ': 'JWT',
        'kid': kid,
        'x5t': x5t
    }, kid


def print_thumbprint_info(kid):
    """Print thumbprint info and check against known uploaded certs."""
    # Print both base64url and hex for clarity
    # Convert base64url kid to hex for comparison
    try:
        kid_bytes = base64.urlsafe_b64decode(kid + '==')
        kid_hex = kid_bytes.hex().upper()
    except Exception:
        kid_hex = '(invalid base64)'
    fingerprint = ':'.join(a + b for a, b in zip(kid_hex[::2], kid_hex[1::2])) if kid_hex != '(invalid base64)' else kid_hex
    print(f"\n🔑 SHA-1 Certificate Thumbprint (VaultN, hex): {fingerprint}")
    print(f"🔑 Raw Thumbprint (hex, no colons): {kid_hex}")
    print(f"🔑 Thumbprint (base64url, JWT kid/x5t): {kid}")
    known_uploaded = {
        "5625A9ED086B6EF60B45EAE95329F171615780B1",
        "230C09BD60E050E5E6DA6D3AC0B3B49C92560687",
        "9665D87B321BE24C58511F4A826F5C8F75DB1597",
        "CCB713A48BBCE086A73CFD08CB0333ECF6A25A1E",
        "0B010A41ABA29812DE87CDC834E071EE2F93C8BE"
    }
    if kid_hex not in known_uploaded:
        print("⚠️ WARNING: This certificate thumbprint was NOT found in VaultN uploaded list.")
        print("   Upload `sample.crt` to VaultN, or verify the correct certificate is selected.")


def verify_certificate_in_vaultn(token, user_guid, api_base_url, env_desc):
    """Try to verify certificate and token with VaultN once, and print a clear message if blocked or not recognized."""
    url = api_base_url.rstrip("/") + "/api/v1/ping"
    try:
        print(f"\n🔍 Verifying certificate thumbprint in VaultN ({env_desc})...")
        resp = requests.get(
            url,
            headers={
                "Authorization": "Bearer " + token,
                "accept": "application/json"
            },
            timeout=10
        )
        if is_cloudflare_block(resp.text):
            print("Cloudflare blocked the request, probably IP is not whitelisted.")
            print("Please check your IP whitelisting and try again later.")
            return
        if resp.status_code == 401 and "No certificate for owner" in resp.text:
            print("❌ VaultN did not recognize the certificate for this GUID and thumbprint.")  # pylint: disable=W1309
            print("   ➤ Make sure you've uploaded the correct certificate in the " + env_desc + " environment (Sandbox vs Prod).")
            print("   ➤ Ensure the certificate is assigned to GUID: " + str(user_guid))
            print("Please check your upload and assignment and try again later.")
            return
        if resp.status_code == 200:
            print(f"✅ VaultN recognized the certificate and the token is valid in {env_desc}.")
        else:
            print(f"⚠️ Unexpected response from VaultN: {resp.status_code}")
            print(resp.text)
            print("Please check your upload and assignment and try again later.")
    except requests.RequestException as exc:
        print("❌ Error verifying certificate registration with VaultN:", exc)
        print("Please check your upload and assignment and try again later.")


def generate_token(user_guid, issuer, audience, pfx_path, pfx_password):
    """Generate a JWT token signed with the private key from the PFX file.

    Args:
        user_guid (str): The VaultN User GUID
        issuer (str): The token issuer
        audience (str): The token audience
        pfx_path (str): Path to the PFX file
        pfx_password (bytes): Password for the PFX file

    Returns:
        str: The generated JWT token
    """
    generate_pfx_if_missing(pfx_path, pfx_password)
    private_key, cert = load_private_key_and_cert(pfx_path, pfx_password)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    payload = get_jwt_payload(user_guid, issuer, audience)
    headers, kid = get_jwt_headers(cert)
    token = jose_jwt.encode(
        payload,
        pem_private_key,
        algorithm="RS256",
        headers=headers
    )
    print_thumbprint_info(kid)
    return token


def get_pfx_password(cli_password=None):
    """Get password for the PFX file, either from CLI argument or by prompting."""
    if cli_password:
        return cli_password.encode()
    try:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always", GetPassWarning)
            pw = getpass("Enter password for the PFX file (input hidden): ")
            if w and any(isinstance(warn.message, GetPassWarning) for warn in w):
                print("[Warning] Password input may be visible in this terminal.")
            return pw.encode()
    except (GetPassWarning, Exception):
        print("[Warning] Password input may be visible in this terminal.")
        pw = input("Enter password for the PFX file (input will be visible): ")
        return pw.encode()


def is_cert_expired(cert_path):
    """Check if a certificate is expired."""
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, backend=default_backend())
        if hasattr(cert, "not_valid_after_utc"):
            not_after = cert.not_valid_after_utc
        else:
            not_after = cert.not_valid_after
        return not_after < datetime.datetime.now(datetime.timezone.utc)
    except Exception:
        return True


def check_and_prepare_cert(crt_path, pfx_path, pfx_password, env_desc, user_guid=None):
    """Check certificate existence and validity, prepare if needed."""
    if user_guid is None:
        user_guid = input(f"Enter your VaultN User GUID for {env_desc}: ").strip()
    cert_created = False
    if not os.path.exists(crt_path):
        print(f"\n⚠️  Certificate file '{crt_path}' not found.")
        print("Attempting to generate a new certificate...")
        generate_pfx_if_missing(pfx_path, pfx_password)
        if not os.path.exists(crt_path):
            print(f"❌ Failed to generate '{crt_path}'. Please check permissions or OpenSSL installation.")
            sys.exit(1)
        print(f"\n✅ Certificate '{crt_path}' has been created.")
        print(f"\nPlease upload this certificate to the VaultN portal and assign it to your GUID in {env_desc} environment.")
        print("Once uploaded, press Enter to continue...")
        cert_created = True
    else:
        if is_cert_expired(crt_path):
            print(f"❌ Certificate '{crt_path}' is expired. Please generate a new one.")
            sys.exit(1)
    print(f"\n✅ Certificate '{crt_path}' found. Proceeding in {env_desc}...\n")
    return user_guid, cert_created


def print_production_checklist():
    """Display the production environment checklist."""
    print("\n🚦 Production Environment Checklist:")
    print("  1. Whitelist your server IPs in the VaultN portal.")
    print("  2. Upload your PRODUCTION certificate (not the sandbox one) and assign it to your GUID.")
    print("  3. Generate a new authentication token using the production certificate.")
    print("  4. Ensure you have active connections with your live VaultN partners.")
    print("  5. The sandbox and production tokens/certs are NOT interchangeable!\n")
    print("For any issues, contact support@vaultn.com.\n")


def prompt_guid(saved_guid=None, env_desc=None):
    """Prompt for GUID, showing the saved value as default."""
    prompt = f"Enter your VaultN User GUID"
    if env_desc:
        prompt += f" for {env_desc}"
    if saved_guid:
        prompt += f" [{saved_guid}]"
    prompt += ": "
    entered = input(prompt).strip()
    return entered if entered else saved_guid


def print_jwt_header(token):
    header_b64 = token.split('.')[0]
    header_b64 += '=' * (-len(header_b64) % 4)
    header_json = base64.urlsafe_b64decode(header_b64.encode('utf-8')).decode('utf-8')
    print("\nJWT Header:", header_json)


# Manual JWT payload decode (no signature verification, for display only)
def print_jwt_payload(token):
    payload_b64 = token.split('.')[1]
    payload_b64 += '=' * (-len(payload_b64) % 4)
    payload_json = base64.urlsafe_b64decode(payload_b64.encode('utf-8')).decode('utf-8')
    print("\nJWT Payload:", payload_json)
    return json.loads(payload_json)


def main():
    """Main entry point for VaultNAuth CLI."""
    # Always ask for environment first
    env = select_environment()
    args = parse_args()
    config = load_config()
    # CLI arg overrides, but prompt always comes first
    if args.env and args.env != env:
        env = args.env
    env_conf = ENVIRONMENTS[env]
    certs_dir = "certificates"
    cert_base = env_conf["cert_name"]
    pfx_path = os.path.join(certs_dir, f"{cert_base}.pfx")
    crt_path = os.path.join(certs_dir, f"{cert_base}.crt")
    pfx_password = get_pfx_password(args.pfx_password)
    audience = "VaultN"
    issuer = "Self"
    env_desc = env_conf["desc"]
    api_base_url = env_conf["api_base_url"]
    print(f"\n🔔 Active Environment: {env_desc}\n")
    if env == "production":
        print_production_checklist()
    saved_guid = args.guid or config.get("DEFAULT", "guid", fallback=None)
    user_guid = args.guid or prompt_guid(saved_guid, env_desc)
    if not user_guid:
        print("❌ GUID is required.")
        sys.exit(1)
    # Save config for next time
    config["DEFAULT"] = {"env": env, "guid": user_guid}
    save_config(config)
    user_guid, cert_created = check_and_prepare_cert(crt_path, pfx_path, pfx_password, env_desc, user_guid)
    try:
        token = generate_token(user_guid, issuer, audience, pfx_path, pfx_password)
        print_jwt_header(token if isinstance(token, str) else token.decode('utf-8'))
        payload = print_jwt_payload(token if isinstance(token, str) else token.decode('utf-8'))
        print(f"\n🔐 Bearer Token (valid for 1 year, {env_desc}):")
        # Box drawing for token usage info (retyped to ensure no f-string or hidden chars)
        print(" ┌────────────────────────────────────────────────────────────────────┐")
        print(" │  Use this token in Authorization headers as shown below:          │")
        print(" └────────────────────────────────────────────────────────────────────┘")
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        print(f"\nAuthorization: Bearer {token}\n")
        exp = datetime.datetime.fromtimestamp(payload["exp"], tz=datetime.timezone.utc)
        iat = datetime.datetime.fromtimestamp(payload["iat"], tz=datetime.timezone.utc)
        print("📆 Token Timestamps (UTC):")
        print(" ├─ Issued At (iat):", iat.isoformat())
        print(" └─ Expires At (exp):", exp.isoformat())
        if args.token_only:
            return
        if not cert_created:
            if input("\nWould you like to verify the certificate/token with VaultN now? (y/n): ").strip().lower() == "y":
                verify_certificate_in_vaultn(token, user_guid, api_base_url, env_desc)
        if input("\nWould you like to test the VaultN API with this token? (y/n): ").strip().lower() == "y":
            test_vaultn_api(token, api_base_url, env_desc)
        if env == "production":
            print("\n[TODO] Check partner connection status and catalog sharing in production.\n")
    except Exception as exc:
        print(f"❌ Error generating or decoding token: {exc}")


if __name__ == "__main__":
    main()

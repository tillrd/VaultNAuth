[![Build](https://github.com/tillrd/VaultNAuth/actions/workflows/python-app.yml/badge.svg)](https://github.com/tillrd/VaultNAuth/actions/workflows/python-app.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

# 🚀 VaultNAuth

A developer-friendly CLI tool for generating and testing JWT tokens with self-signed certificates for VaultN API authentication. Supports both Sandbox and Production environments with enhanced security features and user experience.

---

## ✨ Features
- 🔒 **Automatic Certificate Generation**: Creates self-signed certificates if missing
- 🗂️ **Certificate Management**: All certs are stored in the `certificates/` directory
- 🧑‍💻 **Environment Selection**: Choose between Sandbox and Production environments
- 🔄 **Configuration Persistence**: Saves your environment and GUID preferences
- 🛡️ **Enhanced Security**: Certificate expiration checking and secure password handling
- 🎯 **Smart Token Generation**: JWT tokens with automatic thumbprint verification
- 🌐 **Comprehensive API Testing**: Instant token verification and connectivity checks
- 📋 **Production Checklist**: Guided steps for production deployment
- 🔍 **Advanced Diagnostics**: Certificate verification and detailed error messages

---

## 🔗 How Verification Works

VaultNAuth provides a comprehensive verification process:

1. **Certificate Validation**: Checks for expiration and proper registration
2. **Token Generation**: Creates a JWT token with proper headers and claims
3. **API Verification**: Tests the token against VaultN's `/api/v1/ping` endpoint
4. **Response Analysis**: Provides detailed feedback on authentication status
5. **Troubleshooting**: Detects common issues like Cloudflare blocks or unregistered certificates

- **API Reference:** [VaultN /api/v1/ping](https://vaultn.readme.io/reference/get_api-v1-ping-3) 

---

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tillrd/VaultNAuth.git
   cd VaultNAuth
   ```
2. **Create a virtual environment and install dependencies:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

## 🐳 Docker Usage

You can run VaultNAuth directly from Docker:

```sh
docker pull ghcr.io/tillrd/vaultnauth:latest
docker run -it --rm ghcr.io/tillrd/vaultnauth:latest
```

This will launch the interactive CLI in a container.

### Persisting Certificates

To keep generated certificates on your host machine, run:

```sh
docker run -it --rm -v $PWD/certificates:/app/certificates ghcr.io/tillrd/vaultnauth:latest
```

All certificates will be available in the `certificates` folder in your current directory.

---

## 🚦 Usage

1. **Run the app:**
   ```bash
   source .venv/bin/activate
   python app.py
   ```

2. **Environment Selection:**
   - Choose between Sandbox (testing) and Production environments
   - Review the production checklist when selecting production

3. **Configuration:**
   - Enter your VaultN User GUID (saved for future use)
   - Provide PFX password (or generate new certificate if missing)
   - Upload certificate to VaultN portal when prompted

4. **Token Generation and Testing:**
   - Get your JWT token with full validity information
   - Verify certificate registration with VaultN
   - Test API connectivity
   - View detailed response analysis

---

## 📝 Example Output

```
🌍 Select environment:
  1. Sandbox (testing)
  2. Production (live)
Enter 1 for Sandbox or 2 for Production: 1

🔔 Active Environment: Sandbox

Enter your VaultN User GUID for Sandbox: 123e4567-e89b-12d3-a456-426614174000

✅ Certificate 'certificates/sample.crt' found. Proceeding in Sandbox...

🔑 SHA-1 Certificate Thumbprint (VaultN): AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12

🔐 Bearer Token (valid for 1 year, Sandbox):
 ┌────────────────────────────────────────────────────────────────────┐
 │  Use this token in Authorization headers as shown below:          │
 └────────────────────────────────────────────────────────────────────┘

Authorization: Bearer eyJhbGciOiJSUzI1NiIs...

📆 Token Timestamps (UTC):
 ├─ Issued At (iat): 2024-04-20T10:30:00+00:00
 └─ Expires At (exp): 2025-04-20T10:30:00+00:00

🔍 Verifying certificate thumbprint in VaultN (Sandbox)...
✅ VaultN recognized the certificate and the token is valid in Sandbox.

🌐 Testing VaultN API on Sandbox...
✅ Response Status: 200
📄 Response Body: "Hello user@example.com"
```

---

## 🛠️ Project Structure

```
VaultNAuth/
├── app.py              # Main application script
├── requirements.txt    # Python dependencies
├── .gitignore         # Ignores sensitive and unnecessary files
├── .pylintrc          # Pylint configuration
├── certificates/      # (Auto-created) Stores generated certs (ignored in git)
│   ├── sample.crt    # Sandbox certificate
│   └── prod_sample.crt # Production certificate
└── README.md          # This file
```

---

## 🧩 Requirements
- Python 3.8+
- OpenSSL (for certificate generation)
- Internet connection for API testing

---

## 🤝 Contributing
Pull requests and issues are welcome! Please open an issue to discuss your idea or bug before submitting a PR.

---

## 📄 License
MIT License. See [LICENSE](LICENSE) for details.

# trigger docker build

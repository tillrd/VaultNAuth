[![Build](https://github.com/tillrd/VaultNAuth/actions/workflows/python-app.yml/badge.svg)](https://github.com/tillrd/VaultNAuth/actions/workflows/python-app.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

# 🚀 VaultNAuth

A developer-friendly CLI tool for generating and testing JWT tokens with self-signed certificates for VaultN API authentication.

---

## ✨ Features
- 🔒 **Automatic Certificate Generation**: Creates self-signed certificates if missing.
- 🗂️ **Certificate Management**: All certs are stored in the `certificates/` directory (auto-ignored for safety).
- 🧑‍💻 **Manual GUID Input**: Enter your VaultN User GUID at runtime.
- 🛡️ **JWT Token Generation**: Securely signs tokens with your private key.
- 🌐 **VaultN API Integration**: Instantly tests your token against the VaultN Sandbox API.
- 🕵️ **Interactive Certificate Upload Flow**: Guides you to upload and assign your cert before proceeding.
- 🔁 **Retry Logic**: If VaultN doesn't recognize your cert, you can retry after uploading.

---

## 🔗 How Verification Works

After generating your JWT token, VaultNAuth automatically verifies your setup by making a request to the VaultN API `/api/v1/ping` endpoint. This endpoint checks both connectivity and the validity of your JWT authorization. If your certificate and token are correctly configured and uploaded, you will receive a successful response from VaultN.

- **API Reference:** [VaultN /api/v1/ping documentation](https://vaultn.readme.io/reference/get_api-v1-ping-3) 

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

---

## 🚦 Usage

1. **Run the app:**
   ```bash
   source .venv/bin/activate
   python app.py
   ```
2. **Follow the prompts:**
   - Enter your VaultN User GUID when asked.
   - If no certificate is found, the app will generate one for you in `certificates/`.
   - Upload `certificates/sample.crt` to the VaultN portal and assign it to your GUID.
   - Press Enter to continue and validate your setup.

3. **Copy your JWT token:**
   - The app will display a valid JWT token and show the VaultN API response.

---

## 📝 Example Output

```
Enter your VaultN User GUID: 123e4567-e89b-12d3-a456-426614174000

✅ Certificate 'certificates/sample.crt' found. Proceeding...

🔑 SHA-1 Certificate Thumbprint (VaultN): AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12
⚠️ WARNING: This certificate thumbprint was NOT found in VaultN uploaded list.
   Upload `sample.crt` to VaultN, or verify the correct certificate is selected.

🔍 Verifying certificate thumbprint in VaultN...
✅ VaultN recognized the certificate and the token is valid.

🔐 Bearer Token (valid for 1 year):
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...

🌐 Testing VaultN API...
✅ Response Status: 200
📄 Response Body:
"Hello user@example.com"
```

---

## 🛠️ Project Structure

```
VaultNAuth/
├── app.py              # Main application script
├── requirements.txt    # Python dependencies
├── .gitignore          # Ignores sensitive and unnecessary files
├── certificates/       # (Auto-created) Stores generated certs (ignored in git)
└── README.md           # This file
```

---

## 🧩 Requirements
- Python 3.8+
- OpenSSL (for certificate generation)

---

## 🤝 Contributing
Pull requests and issues are welcome! Please open an issue to discuss your idea or bug before submitting a PR.

---

## 📄 License
MIT License. See [LICENSE](LICENSE) for details.

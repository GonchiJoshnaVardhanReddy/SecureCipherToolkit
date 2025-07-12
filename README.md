
# 🔐 SecureCipherToolkit

**SecureCipherToolkit** is a Python-based command-line encryption and decryption tool designed for red teamers, cybersecurity students, and privacy advocates. It supports multiple encryption modes including Caesar Cipher, ROT13, XOR, Vigenère, and more. It also includes secure key storage, brute-force and frequency analysis, JSON message exporting, and insecure usage detection.

---

## 🚀 Features

- ✅ Caesar Cipher (Encrypt/Decrypt)
- ✅ Brute-force Caesar Cipher attack
- ✅ Frequency analysis Caesar decryption
- ✅ Secure Fernet key storage for Caesar shift
- ✅ Save and load messages from text files
- ✅ Export encrypted messages as JSON (with metadata)
- ✅ Detect insecure plaintext files
- ✅ Red team bonus tools:
  - ROT13 encryption
  - XOR encryption
  - Vigenère cipher
  - Live Caesar cracking with frequency scoring
- ✅ Update checker (simulated)
- ✅ Clean, menu-driven CLI interface

---

## 📦 Requirements

Python version: **3.6+**

### Install the required library

```bash
pip install cryptography
```

> ⚠️ If you are using Kali Linux and get a pip error (PEP 668), use a virtual environment:

```bash
sudo apt install python3-venv
python3 -m venv venv
source venv/bin/activate
pip install cryptography
```

---

## 🧰 Installation

1. **Clone this repo** or manually download `secure_cipher_toolkit.py`

```bash
git clone https://github.com/GonchiJoshnaVardhanReddy/SecureCipherToolkit.git
cd SecureCipherToolkit
```

2. **Run the toolkit**:

```bash
python secure_cipher_toolkit.py
```

Or (in venv):
```bash
venv/bin/python secure_cipher_toolkit.py
```

---

## 🧪 Example Usage

### Caesar Cipher Encryption

```
Input: Hello World
Shift: 3
Encrypted: Khoor Zruog
```

### Brute Force Decryption

```
Encrypted: Khoor Zruog
→ Shift 3: Hello World
```

### Export to JSON

Generates:

```json
{
  "timestamp": "2025-06-25T13:37:00",
  "method": "Caesar",
  "content": "Khoor Zruog",
  "meta": "Encrypted with shift 3"
}
```

---

## 📁 Folder/Structure Tips

- `.key` file is created when securely storing Caesar shift
- `.json` files are exported messages
- `.txt` files are message saves (secure or insecure)

---

## 🚨 Legal & Ethical Use

This tool is provided for **educational and authorized use only**.  
Do not use it to encrypt, transmit, or crack data without legal permission.

---

## 👨‍💻 Author

Developed by [GonchiJoshnaVardhanReddy](https://github.com/GonchiJoshnaVardhanReddy)

---

## ✅ To Do (Future Upgrades)

- [ ] Add AES & RSA encryption
- [ ] Add curses-based TUI
- [ ] Add GUI frontend

---

## 🧠 License

MIT License

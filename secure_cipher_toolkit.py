#!/usr/bin/env python3
import os
import json
import string
import base64
import hashlib
import random
from collections import Counter
from cryptography.fernet import Fernet
from datetime import datetime

# Constants
TOOL_VERSION = "1.0.0"
KEY_FILE = "secure_shift.key"
SECURE_FILES = ["encrypted_", "secure_message_"]

# ------------------- Caesar Cipher -------------------

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# ------------------- Frequency Analysis -------------------

def frequency_analysis(text):
    text = ''.join([c for c in text.upper() if c in string.ascii_uppercase])
    freq = Counter(text)
    most_common = freq.most_common(1)[0][0] if freq else 'E'
    assumed_shift = (ord(most_common) - ord('E')) % 26
    return caesar_decrypt(text, assumed_shift), assumed_shift

# ------------------- Brute Force -------------------

def brute_force(text):
    results = []
    for i in range(1, 26):
        decrypted = caesar_decrypt(text, i)
        results.append((i, decrypted))
    return results

# ------------------- Fernet Key Storage -------------------

def generate_key():
    return Fernet.generate_key()

def store_shift_key(shift):
    key = generate_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(str(shift).encode())
    with open(KEY_FILE, 'wb') as f:
        f.write(key + b'||' + encrypted)

def load_shift_key():
    with open(KEY_FILE, 'rb') as f:
        key, encrypted = f.read().split(b'||')
        fernet = Fernet(key)
        return int(fernet.decrypt(encrypted).decode())

# ------------------- Vigenère Cipher -------------------

def vigenere_encrypt(text, key):
    result = ""
    key = key.lower()
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            base = 'A' if char.isupper() else 'a'
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.lower()
    for i, char in enumerate(text):
        if char.isalpha():
            shift = -(ord(key[i % len(key)]) - ord('a'))
            base = 'A' if char.isupper() else 'a'
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result

# ------------------- XOR Cipher -------------------

def xor_encrypt(text, key):
    return ''.join(chr(ord(c) ^ key) for c in text)

def xor_decrypt(text, key):
    return xor_encrypt(text, key)  # XOR is reversible

# ------------------- ROT13 -------------------

def rot13(text):
    return caesar_encrypt(text, 13)

# ------------------- File Handling -------------------

def save_to_file(filename, content):
    with open(filename, 'w') as f:
        f.write(content)

def load_from_file(filename):
    with open(filename, 'r') as f:
        return f.read()

def detect_insecure_storage():
    files = [f for f in os.listdir() if f.endswith('.txt')]
    insecure = [f for f in files if not any(f.startswith(s) for s in SECURE_FILES)]
    return insecure

# ------------------- JSON Export -------------------

def export_json(text, method, meta=""):
    filename = f"secure_message_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    data = {
        "timestamp": str(datetime.now()),
        "method": method,
        "content": text,
        "meta": meta
    }
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Message exported to {filename}")

# ------------------- Version Check -------------------

def check_for_updates():
    local_version = TOOL_VERSION
    latest_version = "1.0.0"  # Simulate latest
    if local_version == latest_version:
        print("[✔] SecureCipherToolkit is up to date.")
    else:
        print(f"[!] Update available: {latest_version} (current: {local_version})")

# ------------------- Live Cracking Demo -------------------

def live_crack(text):
    print("[*] Starting live Caesar cipher crack...")
    scores = []
    common_words = ['the', 'and', 'is', 'you', 'of', 'to', 'in', 'it']
    for i in range(1, 26):
        decrypted = caesar_decrypt(text, i).lower()
        score = sum(decrypted.count(word) for word in common_words)
        scores.append((i, decrypted, score))
    best = sorted(scores, key=lambda x: x[2], reverse=True)[0]
    print(f"[+] Best guess (shift={best[0]}): {best[1]}")
    return best

# ------------------- Menu Interface -------------------

def menu():
    while True:
        print("\n📦 SecureCipherToolkit v1.0")
        print("1. Caesar Encrypt")
        print("2. Caesar Decrypt (with key)")
        print("3. Caesar Brute-force Crack")
        print("4. Caesar Frequency Analysis")
        print("5. Store Caesar Shift Key Securely")
        print("6. Load Caesar Key & Decrypt")
        print("7. Save/Load Message from File")
        print("8. Export Encrypted Message as JSON")
        print("9. Live Caesar Cracking (Red Team)")
        print("10. Bonus: ROT13 / XOR / Vigenère")
        print("11. Check for Insecure Storage")
        print("12. Check for Updates")
        print("0. Exit")

        choice = input("Select option: ").strip()
        try:
            if choice == "1":
                msg = input("Message to encrypt: ")
                shift = int(input("Shift (positive integer): "))
                if shift <= 0: raise ValueError
                encrypted = caesar_encrypt(msg, shift)
                print("Encrypted:", encrypted)
            elif choice == "2":
                msg = input("Message to decrypt: ")
                shift = int(input("Shift used: "))
                print("Decrypted:", caesar_decrypt(msg, shift))
            elif choice == "3":
                msg = input("Encrypted message: ")
                for s, result in brute_force(msg):
                    print(f"Shift {s}: {result}")
            elif choice == "4":
                msg = input("Encrypted message: ")
                result, shift = frequency_analysis(msg)
                print(f"Guessed Shift: {shift}\nDecrypted: {result}")
            elif choice == "5":
                shift = int(input("Shift to store securely: "))
                store_shift_key(shift)
                print("[+] Key stored securely.")
            elif choice == "6":
                msg = input("Message to decrypt: ")
                shift = load_shift_key()
                print(f"[+] Loaded shift: {shift}")
                print("Decrypted:", caesar_decrypt(msg, shift))
            elif choice == "7":
                sub = input("1=Save 2=Load: ")
                if sub == "1":
                    text = input("Text to save: ")
                    fname = input("Filename (.txt): ")
                    save_to_file(fname, text)
                    print("[+] Saved.")
                else:
                    fname = input("Filename to load: ")
                    text = load_from_file(fname)
                    print("Loaded Text:", text)
            elif choice == "8":
                msg = input("Message to encrypt: ")
                method = input("Method name: ")
                export_json(msg, method)
            elif choice == "9":
                msg = input("Enter Caesar-encrypted message: ")
                live_crack(msg)
            elif choice == "10":
                print("a. ROT13\nb. XOR\nc. Vigenère")
                sub = input("Select: ").strip().lower()
                if sub == 'a':
                    txt = input("Text: ")
                    print("ROT13:", rot13(txt))
                elif sub == 'b':
                    txt = input("Text: ")
                    key = int(input("XOR Key (int): "))
                    enc = xor_encrypt(txt, key)
                    print("Encrypted:", enc)
                    print("Decrypted:", xor_decrypt(enc, key))
                elif sub == 'c':
                    txt = input("Text: ")
                    key = input("Key (a-z): ")
                    enc = vigenere_encrypt(txt, key)
                    print("Encrypted:", enc)
                    print("Decrypted:", vigenere_decrypt(enc, key))
            elif choice == "11":
                bad = detect_insecure_storage()
                if bad:
                    print("[!] Insecure plaintext files detected:", bad)
                else:
                    print("[✔] No insecure files found.")
            elif choice == "12":
                check_for_updates()
            elif choice == "0":
                print("Goodbye.")
                break
            else:
                print("Invalid option.")
        except Exception as e:
            print(f"[Error] {e}")

# ------------------- Run Toolkit -------------------

if __name__ == "__main__":
    menu()

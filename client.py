#!/usr/bin/env python3
"""
LiteChat Terminal Client
-----------------------
A lightweight, **stateless** terminal client for the LiteChat server.

Features
========
1. Registration – generates an in-memory PGP key-pair, asks for a username and sends the public
   key to the server.
2. Authentication – proves key ownership using the challenge / response mechanism implemented on
   the server.
3. User lookup – search remote users by username or use any external public key directly.
4. End-to-end encrypted messaging – messages are encrypted with the recipient’s public key and
   signed with the sender’s private key. Nothing is persisted on disk – all keys live only for
   the lifetime of the process.

The script purposefully avoids writing **any** information to local storage.  When you exit, your
private key is lost.  Make sure to copy it somewhere safe after registration if you want to log in
again later.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime
from textwrap import dedent
from typing import Optional

import requests
from pgpy import (
    PGPKey,
    PGPMessage,
    PGPUID,
    PGPSignature,
)
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def print_hr(char: str = "-", width: int = 50) -> None:  # simple separator
    print(char * width)


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print("\nBye!")
        sys.exit(0)


# ---------------------------------------------------------------------------
# PGP helpers
# ---------------------------------------------------------------------------

def generate_keypair(username: str) -> tuple[str, str, PGPKey]:
    """Generate a new RSA 2048 keypair.

    Returns (public_key_str, private_key_str, private_key_obj)
    """
    print("Generating a fresh 2048-bit RSA key … this may take a few seconds …")
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = PGPUID.new(username)

    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )

    public_key_str = str(key.pubkey)
    private_key_str = str(key)
    return public_key_str, private_key_str, key


def load_private_key(armored: str) -> PGPKey:
    key, _ = PGPKey.from_blob(armored)
    if key.is_public:
        raise ValueError("Provided key is a public key, need a private key.")
    return key


def sign_data(priv: PGPKey, data: str) -> str:
    """Return a base64-encoded detached signature of *data*."""
    sig: PGPSignature = priv.sign(data, detached=True)
    return base64.b64encode(bytes(sig)).decode()


def encrypt_for(recipient_pub: str, plaintext: str) -> str:
    pub_key, _ = PGPKey.from_blob(recipient_pub)
    message = PGPMessage.new(plaintext)
    encrypted: PGPMessage = pub_key.encrypt(message)
    return str(encrypted)


# ---------------------------------------------------------------------------
# Client logic
# ---------------------------------------------------------------------------

class LiteChatClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.username: Optional[str] = None
        self.token: Optional[str] = None
        self.priv_key: Optional[PGPKey] = None

    # --------------------------- Registration & Auth ----------------------

    def register(self) -> bool:
        while True:
            username = ask("Choose a username: ")
            if username:
                break
            print("Username cannot be empty.")

        pub_key_str, priv_key_str, priv_key_obj = generate_keypair(username)
        print_hr()
        print("Your private key (copy & keep it secret – you will not see it again):\n")
        # Show key body only (omit BEGIN/END lines) to avoid copy issues
        key_body = "\n".join(priv_key_str.strip().splitlines()[1:-1])
        print(key_body)
        print_hr()

        resp = requests.post(
            f"{self.base_url}/users/register",
            json={"username": username, "public_key": pub_key_str},
        )
        if resp.status_code != 200:
            print(f"[!] Registration failed: {resp.text}")
            return False
        print("[✓] Registered successfully!")

        # Keep state in memory for immediate use
        self.username = username
        self.priv_key = priv_key_obj

        # Immediately authenticate so we can start chatting
        return self.authenticate(skip_key_input=True)

    def authenticate(self, skip_key_input: bool = False) -> bool:
        if not self.username:
            self.username = ask("Username: ")

        if self.priv_key is None and not skip_key_input:
            print("Paste your private key (without the BEGIN/END lines), then an empty line to finish:")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                # Skip potential armor header/footer if present
                if line.startswith("-----BEGIN") or line.startswith("-----END"):
                    continue
                lines.append(line)
            body = "\n".join(lines)
            header = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
            footer = "-----END PGP PRIVATE KEY BLOCK-----"
            armored = f"{header}\n{body}\n{footer}"
            try:
                self.priv_key = load_private_key(armored)
            except Exception as exc:
                print(f"[!] Failed to load private key: {exc}")
                self.priv_key = None
                return False

        if self.priv_key is None:
            print("[!] No private key available – cannot authenticate.")
            return False

        # Obtain challenge
        challenge_resp = requests.post(
            f"{self.base_url}/auth/challenge", json={"username": self.username}
        )
        if challenge_resp.status_code != 200:
            print(f"[!] Challenge request failed: {challenge_resp.text}")
            return False
        challenge = challenge_resp.json()["challenge"]

        # Sign challenge
        signature_b64 = sign_data(self.priv_key, challenge)

        verify_resp = requests.post(
            f"{self.base_url}/auth/verify",
            json={"username": self.username, "signature": signature_b64},
        )
        if verify_resp.status_code != 200:
            print(f"[!] Authentication failed: {verify_resp.text}")
            return False

        self.token = verify_resp.json()["token"]
        print("[✓] Authenticated!")
        return True

    # --------------------------- Messaging -------------------------------

    # Helper for auth header
    def _auth(self) -> dict[str, str]:
        assert self.token is not None, "Must be authenticated"
        return {"Authorization": f"Bearer {self.token}"}

    def send_message(self) -> None:
        target = ask("Recipient username (or leave blank to paste public key): ")
        if target:
            lookup_resp = requests.get(f"{self.base_url}/users/search", params={"username": target})
            if lookup_resp.status_code != 200:
                print(f"[!] User lookup failed: {lookup_resp.text}")
                return
            data = lookup_resp.json()
            recipient_pub = data["public_key"]
        else:
            print("Paste recipient public key (without the BEGIN/END lines), then an empty line to finish:")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                # Skip armor header/footer if present
                if line.startswith("-----BEGIN") or line.startswith("-----END"):
                    continue
                lines.append(line)
            body = "\n".join(lines)
            if not body:
                print("[!] No public key provided.")
                return
            header = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
            footer = "-----END PGP PUBLIC KEY BLOCK-----"
            recipient_pub = f"{header}\n{body}\n{footer}"
            # If sending directly via public key we still need a recipient username for server – use its fingerprint
            recipient_pub_key, _ = PGPKey.from_blob(recipient_pub)
            fingerprint = str(recipient_pub_key.fingerprint)
            # Attempt to look up user by fingerprint to obtain a username recognised by the server
            lookup_resp = requests.get(
                f"{self.base_url}/users/search", params={"fingerprint": fingerprint}
            )
            if lookup_resp.status_code == 200:
                data = lookup_resp.json()
                target = data["username"]  # mapped to registered username
            else:
                print("[!] No registered user with that public key fingerprint – cannot deliver via server.")
                return

        print("Compose your message. End with an empty line:")
        msg_lines: list[str] = []
        while True:
            line = input()
            if not line:
                break
            msg_lines.append(line)
        plaintext = "\n".join(msg_lines)
        if not plaintext:
            print("[!] Empty message – aborted.")
            return

        ciphertext = encrypt_for(recipient_pub, plaintext)
        signature_b64 = sign_data(self.priv_key, ciphertext)

        payload = {
            "recipient": target,
            "encrypted_message": ciphertext,
            "signature": signature_b64,
        }
        resp = requests.post(
            f"{self.base_url}/messages/send", json=payload, headers=self._auth()
        )
        if resp.status_code != 201:
            print(f"[!] Failed to send message: {resp.text}")
            return
        print("[✓] Message sent.")

    def check_inbox(self) -> None:
        resp = requests.get(f"{self.base_url}/messages/inbox", headers=self._auth())
        if resp.status_code != 200:
            print(f"[!] Failed to fetch inbox: {resp.text}")
            return
        messages = resp.json()["messages"]
        if not messages:
            print("(No messages)")
            return

        for msg in messages[::-1]:  # show oldest first
            sender = msg["sender"]
            ts = datetime.fromisoformat(msg["timestamp"])
            encrypted = msg["encrypted_message"]
            try:
                plaintext = self._decrypt(encrypted)
            except Exception as exc:
                plaintext = f"<Failed to decrypt: {exc}>"
            print_hr("=")
            print(f"From   : {sender}")
            print(f"At     : {ts}")
            print("Message:")
            print(plaintext)
        print_hr("=")

    def _decrypt(self, armored_cipher: str) -> str:
        cipher = PGPMessage.from_blob(armored_cipher)
        decrypted: PGPMessage = self.priv_key.decrypt(cipher)
        return decrypted.message  # type: ignore[attr-defined]

    # --------------------------- Main loop -------------------------------

    def run(self) -> None:
        while True:
            print_hr()
            print("LiteChat – Menu")
            print("1) Send message")
            print("2) Check inbox")
            print("3) Search user")
            print("4) Quit")
            choice = ask("> ")

            if choice == "1":
                self.send_message()
            elif choice == "2":
                self.check_inbox()
            elif choice == "3":
                self._search_user()
            elif choice == "4":
                print("Bye!")
                break

    def _search_user(self) -> None:
        term = ask("Username or fingerprint to search: ")
        if not term:
            print("Nothing to search.")
            return
        if all(c in "0123456789ABCDEFabcdef" for c in term) and len(term) >= 8:
            params = {"fingerprint": term}
        else:
            params = {"username": term}
        resp = requests.get(f"{self.base_url}/users/search", params=params)
        if resp.status_code != 200:
            print(f"[!] Search failed: {resp.text}")
            return
        data = resp.json()
        print_hr()
        print(f"Username    : {data['username']}")
        print(f"Fingerprint : {data['fingerprint']}")
        print("Public key  :\n")
        key_body = "\n".join(data["public_key"].strip().splitlines()[1:-1])
        print(key_body)
        print_hr()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("Welcome to LiteChat CLI!")
    base_url = ask("Server base URL [http://localhost:8000]: ") or "http://localhost:8000"

    client = LiteChatClient(base_url)

    while True:
        print_hr()
        print("1) Register\n2) Authenticate\n3) Quit")
        first = ask("> ")
        if first == "1":
            if client.register():
                break
        elif first == "2":
            if client.authenticate():
                break
        elif first == "3":
            sys.exit(0)
        else:
            print("Invalid choice.")

    # Enter main menu
    client.run()


if __name__ == "__main__":
    main()

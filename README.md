# LiteChat Terminal Client

LiteChat is an open-source, **stateless** chat application that keeps all private keys **in memory only** and never touches your disk.  
This repository contains the reference terminal client that talks to the [LiteChat Server](../LiteChat-Server/README.md) over a simple JSON/HTTP API.

---

## Features

* 🆕 **Registration** – generates a fresh 2048-bit RSA key-pair and registers the public key together with a unique username.
* ✅ **Challenge/response authentication** – proves ownership of your private key without ever sending it to the server.
* 🔍 **User lookup** – search for remote users by username or by OpenPGP fingerprint.
* 🔐 **End-to-end encrypted messaging** – messages are encrypted with the recipient’s public key **and** signed by your private key before leaving your machine.
* 🗑️ **Zero persistence** – nothing is written to disk; once you quit, your private key disappears (copy it somewhere safe if you want to login again).

---

## Quickstart

```bash
# 1. Clone the repository (if you have not done so already)
$ git clone https://github.com/Davidasx/LiteChat-Client.git && cd LiteChat-Client

# 2. (Recommended) Create a virtual environment
$ python3 -m venv .venv && source .venv/bin/activate

# 3. Install Python dependencies
$ pip install -r requirements.txt

# 4. Run the client
$ python client.py
```

The script will ask for the server base URL – hit **Enter** to accept the default `http://localhost:8000` (matches the default of the server) or provide your own.

---

## Typical Workflow

1. **Register** – choose a username when prompted. A brand-new OpenPGP key-pair will be generated.  
   ⚠️ **Important:** Your private key will be printed **once**. Copy it to a secure location if you ever want to authenticate again in the future.
2. **Authenticate** – the client fetches a challenge from the server and signs it using your private key, receiving a short-lived JWT token.
3. **Chat!** – from the main menu you can:
   * Send an encrypted message
   * Check your inbox (messages are decrypted locally)
   * Search for users by username or fingerprint
4. **Quit** – once you exit, all in-memory keys are destroyed.

---

## Command Overview

| Menu | Action |
|------|--------|
| 1 | **Send message** – pick a registered username _or_ paste any ASCII-armoured public key. Messages are encrypted & signed locally before being POSTed to `/messages/send`. |
| 2 | **Check inbox** – fetch encrypted messages from `/messages/inbox` and decrypt them locally. |
| 3 | **Search user** – call `/users/search` via username or fingerprint. |
| 4 | **Quit** – exit the application. |

---

## Dependencies

The client is pure-Python and only relies on:

```
requests==2.31.0
PGPy==0.5.6
```

Both are installed automatically when running `pip install -r requirements.txt`.

---

## Security Notice

* Your **private key never leaves** your machine and is **not** stored on the filesystem. Losing the key means losing access – keep a backup if you need persistent identities.
* All messages are encrypted end-to-end. The server only ever stores opaque ciphertext and associated metadata (sender, recipient, timestamp).
* Authentication relies on signing a random challenge with your private key. The server verifies the signature using your public key.

---

## Troubleshooting

* "`Failed to load private key`" – make sure you paste the **private**, not public, key when authenticating.
* "`Authentication failed`" – the signature might not match the public key registered for the username. Verify you pasted the correct key.
* "`Failed to decrypt`" when reading messages – the message might not be addressed to the key you currently have in memory.

---

## License

MIT

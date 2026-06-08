# End-to-End Encrypted (E2EE) Portfolio Chat Application

A secure, multi-threaded, real-time chat application featuring asynchronous networking, a thread-safe custom graphical user interface (GUI), and rigorous cryptographic architectures. Built from scratch using Python, this project demonstrates a production-grade implementation of network programming, database optimization, and modern security methodologies.

---

## 🚀 Key Features

*   **End-to-End Encryption (E2EE):** Incorporates Elliptic Curve Diffie-Hellman (ECDH) on the `SECP256R1` curve for dynamic key exchange, combined with authenticated AES-GCM 256-bit symmetric encryption for message payloads. The server handles routing but *never* has access to the plaintext content.
*   **Highly Resilient Multi-Threaded Engine:** Driven by an asynchronous TCP socket engine structured on Python's `threading` controller, capable of routing simultaneous data streams concurrently.
*   **Thread-Safe SQLite Layer:** Built utilizing an in-memory SQLite storage database managed through localized `threading.Lock()` controls and Write-Ahead Logging (WAL) mode to mitigate multi-writer race hazards.
*   **Modern Graphical Layout:** Crafted utilizing the `CustomTkinter` UI engine framework, utilizing thread-safe window loop scheduling via `.after()` hooks to display active peer dynamic streams seamlessly.
*   **Secure Authentication Pipeline:** Eliminates plain-text storage vulnerabilities by employing PBKDF2 cryptography using HMAC-SHA256 iterations combined with distinct 16-byte cryptographically-secure random salts.

---

## 🛡️ Architecture & Cryptographic Workflow

```text
+--------------+                   +--------------+                   +--------------+
|   Client A   |                   |    Server    |                   |   Client B   |
+-------+------+                   +-------+------+                   +-------+------+
        |                                  |                                  |
        |  1. Login / Sign Up Request      |                                  |
        +--------------------------------->|                                  |
        |  (Transmits Username & PubKey)   |                                  |
        |                                  |                                  |
        |  2. Broadcast Online Peers       |                                  |
        |<---------------------------------+--------------------------------->|
        |                                  |                                  |
        |  3. Select Peer B (Fetch Key)    |                                  |
        +--------------------------------->|                                  |
        |                                  |-- 4. Returns Peer B Public Key   |
        |<---------------------------------+                                  |
        |                                                                     |
        | ====== 5. ECDH Shared Key Derivation (Local Secret Math) ========== |
        |                                                                     |
        |  6. AES-GCM Encrypted Data Pipeline (Ciphertext + Unique Nonce)    |
        +-------------------------------------------------------------------->|


Handshake Registration: Upon initialization, clients generate an ephemeral Elliptic Curve keypair. The public key is serialized into a PEM string and registered with the server database upon successful authentication.

Symmetric Secret Derivation: Clicking a peer fetches their verified public key from the database. Each client locally performs a cryptographic scalar multiplication (ECDH) to derive an identical, shared 32-byte secret key.

Data Payload Protection: Messages are encrypted using Advanced Encryption Standard in Galois/Counter Mode (AES-GCM). Every transmission generates a unique, cryptographically secure 12-byte initialization vector (nonce) to guard against replay attacks.

📦 Project Directory Layout
Plaintext
├── client.py        # CustomTkinter GUI layout & client socket networking interface
├── server.py        # Multi-threaded connection broker, SQLite engine, & authentication pipeline
├── app.log          # Runtime logging tracker (Generated locally; excluded via .gitignore)
├── .gitignore       # Git tracking exclusions rules
└── README.md        # Technical project documentation
🛠️ Installation & Setup
1. Prerequisites
Ensure you have Python 3.10+ configured on your local machine.

2. Dependency Configuration
Install the required modern UI and cryptographic compilation dependencies via terminal:

Bash
pip install customtkinter cryptography
3. Execution Sequence
To simulate a multi-client live chat interface, execute the components across separate terminal windows in the following sequence:

Step A: Fire up the Backend Server Broker

Bash
python server.py
Step B: Instantiate Client Window 1 (e.g., Alice)

Bash
python client.py
Step C: Instantiate Client Window 2 (e.g., Bob)

Bash
python client.py
Note: The application filters out your own identity from the sidebar panel, meaning you must have at least two unique client processes actively authenticated simultaneously to trigger peer-to-peer session windows.

⚙️ Core Components Deep Dive
Server Lock Optimization
To completely eradicate SQLite database blocking conflicts (database internal engine lock), heavy CPU hashing overhead computations are executed entirely outside active transactional thread locks:

Python
# Compute heavy iterations prior to locking storage file structures
salt = os.urandom(16).hex()
pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex()

with self.lock:
    # Brief, high-speed atomic write operation
Socket Re-Initialization Resilience
Implements a safety loop to clear uninitialized file descriptor bugs (WinError 10057) if a user hits an authentication failure and immediately attempts another login without restarting:

Python
if self.client_socket.fileno() == -1:
    self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

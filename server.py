import socket
import threading
import sqlite3
import json
import logging
import hashlib
import os

# Set up logging configuration to output to file
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s", filename="app.log", filemode="a")

class Storage:
    def __init__(self):
        # SQLite Shared-Memory Engine & Lock Initialization
        self.db_uri = "file:server_mem_db?mode=memory&cache=shared"
        self.lock = threading.Lock()
        
        # Keep-Alive Persistent Connection Anchor
        # Retaining an active connection link in the main thread prevents SQLite from drops
        # or wiping its schema out of the shared RAM allocation whenever the context count hits 0.
        self.keep_alive_conn = sqlite3.connect(self.db_uri, uri=True, timeout=10.0)
        
        try:
            cursor = self.keep_alive_conn.cursor()
            # Force WAL (Write-Ahead Logging) mode for superior thread concurrency
            cursor.execute("PRAGMA journal_mode=WAL;")
            
            # Create persistent memory schema tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT,
                    salt TEXT,
                    public_key TEXT,
                    current_address TEXT
                )
            """)
            self.keep_alive_conn.commit()
            print("[Database] Shared memory cache initialized and anchored successfully.")
        except Exception as e:
            print(f"[Database Initialization Error]: {e}")

    def register_user(self, username, password, pub_key, address):
        # OPTIMIZATION: Heavy CPU crypto hashing math calculated OUTSIDE the database lock!
        salt = os.urandom(16).hex()
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex()

        # Thread Lock Allocation (Write Operation)
        with self.lock:
            conn = sqlite3.connect(self.db_uri, uri=True, timeout=10.0)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT username FROM users WHERE username=?", (username,))
                if cursor.fetchone():
                    return False, "Username already exists."
                
                cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)", 
                               (username, pw_hash, salt, pub_key, str(address)))
                conn.commit()
                return True, "Registration successful."
            except Exception as e:
                print(f"[Database Critical Error during Registration]: {e}")
                logging.error(f"DB Registration Error: {e}")
                return False, "Database internal engine lock."
            finally:
                conn.close()

    def authenticate_user(self, username, password):
        stored_hash = None
        salt = None

        # Thread Lock Allocation (Read Operation)
        with self.lock:
            conn = sqlite3.connect(self.db_uri, uri=True, timeout=10.0)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
                row = cursor.fetchone()
                if row:
                    stored_hash, salt = row
            except Exception as e:
                print(f"[Database Critical Error during Authentication Read]: {e}")
                logging.error(f"DB Auth Read Error: {e}")
                return False
            finally:
                conn.close()
                
        if not stored_hash or not salt:
            return False
            
        # Verification hashing computed safely outside database lock
        test_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex()
        return test_hash == stored_hash

    def get_user_key(self, username):
        with self.lock:
            conn = sqlite3.connect(self.db_uri, uri=True, timeout=10.0)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT public_key FROM users WHERE username=?", (username,))
                row = cursor.fetchone()
                return row[0] if row else None
            except Exception as e:
                print(f"[Database Critical Error during Key Retrieval]: {e}")
                logging.error(f"DB Read Error: {e}")
                return None
            finally:
                conn.close()

class SecureServer:
    def __init__(self, host="127.0.0.1", port=5555):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        self.db = Storage()
        self.clients = {}  # username -> socket object
        print(f"[*] Server listening on {host}:{port}")

    def broadcast_user_list(self):
        users = list(self.clients.keys())
        payload = json.dumps({"type": "USER_LIST", "users": users})
        for client_sock in self.clients.values():
            try:
                client_sock.sendall(payload.encode())
            except:
                pass

    def handle_client(self, client_socket, address):
        username = None
        while True:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                msg = json.loads(data)
                
                # Split Registration Handshake Logic
                if msg["type"] == "REGISTER":
                    success, reason = self.db.register_user(msg["username"], msg["password"], msg["pub_key"], address)
                    if success:
                        username = msg["username"]
                        # MODIFICATION: Save client to active tracking pool BEFORE transmitting response or broadcasting
                        self.clients[username] = client_socket
                        client_socket.sendall(json.dumps({"type": "AUTH_RESP", "status": "SUCCESS"}).encode())
                        logging.info(f"User {username} registered and logged in.")
                        self.broadcast_user_list()
                    else:
                        client_socket.sendall(json.dumps({"type": "AUTH_RESP", "status": "FAIL", "reason": reason}).encode())
                        
                # Interactive Login Handshake Verification Logic
                elif msg["type"] == "LOGIN":
                    if self.db.authenticate_user(msg["username"], msg["password"]):
                        username = msg["username"]
                        # MODIFICATION: Save client to active tracking pool BEFORE transmitting response or broadcasting
                        self.clients[username] = client_socket
                        client_socket.sendall(json.dumps({"type": "AUTH_RESP", "status": "SUCCESS"}).encode())
                        logging.info(f"User {username} logged in successfully.")
                        self.broadcast_user_list()
                    else:
                        client_socket.sendall(json.dumps({"type": "AUTH_RESP", "status": "FAIL", "reason": "Invalid credentials."}).encode())
                
                elif msg["type"] == "FETCH_KEY":
                    target = msg["target"]
                    target_key = self.db.get_user_key(target)
                    client_socket.sendall(json.dumps({"type": "KEY_RESP", "target": target, "key": target_key}).encode())
                    
                elif msg["type"] == "SECURE_MSG":
                    # --- ADD THIS LOGGING LINE TO CONFIRM SEARCH DATA ---
                    print(f"\n[SERVER INTERCEPT] Raw packet passing through: {json.dumps(msg, indent=2)}")
                    
                    target = msg["target"]
                    if target in self.clients:
                        self.clients[target].sendall(json.dumps(msg).encode())
                        
            except Exception as e:
                logging.error(f"Error handling client {username}: {e}")
                break

        if username in self.clients:
            del self.clients[username]
            logging.info(f"User {username} disconnected.")
            self.broadcast_user_list()
        client_socket.close()

    def start(self):
        while True:
            client_socket, address = self.server.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()

if __name__ == "__main__":
    server = SecureServer()
    server.start()
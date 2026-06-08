import socket
import threading
import json
import base64
import os
from datetime import datetime
import customtkinter as ctk
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class SecureChatClient(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("End-to-End Encrypted Portfolio Chat")
        self.geometry("700x500")

        # Crypto State
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.session_keys = {}  # target_user -> derived symmetric key bytes
        
        # Networking State
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.my_username = ""
        self.active_recipient = None

        self.build_login_ui()

    def serialize_my_public_key(self):
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    # Advanced Landing Page UI with Passwords and Feedback
    def build_login_ui(self):
        self.login_frame = ctk.CTkFrame(self)
        self.login_frame.pack(expand=True, fill="both", padx=20, pady=20)

        self.lbl = ctk.CTkLabel(self.login_frame, text="Secure Chat Authentication", font=("Arial", 20, "bold"))
        self.lbl.pack(pady=15)

        self.username_entry = ctk.CTkEntry(self.login_frame, width=280, placeholder_text="Username")
        self.username_entry.pack(pady=8)

        self.password_entry = ctk.CTkEntry(self.login_frame, width=280, placeholder_text="Password", show="*")
        self.password_entry.pack(pady=8)

        # Dynamic validation feedback label
        self.status_lbl = ctk.CTkLabel(self.login_frame, text="", text_color="red", font=("Arial", 12))
        self.status_lbl.pack(pady=5)

        btn_frame = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        btn_frame.pack(pady=10)

        self.btn_login = ctk.CTkButton(btn_frame, text="Log In", width=130, command=lambda: self.authenticate("LOGIN"))
        self.btn_login.grid(row=0, column=0, padx=10)

        self.btn_signup = ctk.CTkButton(btn_frame, text="Sign Up", width=130, fg_color="green", hover_color="darkgreen", command=lambda: self.authenticate("REGISTER"))
        self.btn_signup.grid(row=0, column=1, padx=10)

    # Client Authorization Bridge Handshake
    def authenticate(self, auth_type):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.status_lbl.configure(text="Username and password fields cannot be empty.")
            return
        
        self.my_username = username
        
        try:
            # Fix for WinError 10057 / Rebuilds descriptor loop cleanly if socket was closed
            if self.client_socket.fileno() == -1:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
            try:
                self.client_socket.connect(("127.0.0.1", 5555))
            except OSError:
                # Safe fallback if socket channel is already actively connected
                pass
            
            payload = {
                "type": auth_type,
                "username": username,
                "password": password,
                "pub_key": self.serialize_my_public_key()
            }
            
            self.client_socket.sendall(json.dumps(payload).encode())
            
            response_data = self.client_socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            
            if response.get("type") == "AUTH_RESP" and response.get("status") == "SUCCESS":
                # MODIFICATION: Spawn and initialize the background listener loop BEFORE switching frames.
                # This guarantees that the server's immediate USER_LIST broadcast packet is caught 
                # by the socket engine buffer instead of hitting a blank background thread.
                threading.Thread(target=self.listen_for_messages, daemon=True).start()
                
                self.build_chat_ui()
            else:
                error_reason = response.get("reason", "Authentication failed.")
                self.status_lbl.configure(text=error_reason)
                # Close down broken connection context cleanly so retry loop resets
                self.client_socket.close()
                
        except Exception as e:
            self.status_lbl.configure(text=f"Connection error: {e}")
            try:
                self.client_socket.close()
            except:
                pass

    def build_chat_ui(self):
        self.login_frame.pack_forget()

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=3)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=180, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self.user_list_lbl = ctk.CTkLabel(self.sidebar, text="Active Peers", font=("Arial", 14, "bold"))
        self.user_list_lbl.pack(pady=10)

        self.user_listbox_frame = ctk.CTkScrollableFrame(self.sidebar)
        self.user_listbox_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.chat_main_frame = ctk.CTkFrame(self)
        self.chat_main_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.chat_main_frame.grid_rowconfigure(0, weight=1)
        self.chat_main_frame.grid_rowconfigure(1, weight=0)

        self.text_display = ctk.CTkTextbox(self.chat_main_frame, state="disabled", wrap="word")
        self.text_display.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)

        self.entry_msg = ctk.CTkEntry(self.chat_main_frame, placeholder_text="Type your secure message here...")
        self.entry_msg.grid(row=1, column=0, sticky="ew", padx=10, pady=10)

        self.btn_send = ctk.CTkButton(self.chat_main_frame, text="Send Secure", width=80, command=self.send_secure_message)
        self.btn_send.grid(row=1, column=1, sticky="e", padx=10, pady=10)

    def listen_for_messages(self):
        while True:
            try:
                data = self.client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                msg = json.loads(data)
                
                if msg["type"] == "USER_LIST":
                    # Thread-Safe Main Loop Scheduling Fix via self.after()
                    self.after(0, lambda: self.update_peer_list(msg["users"]))
                    
                elif msg["type"] == "KEY_RESP":
                    self.compute_shared_session_key(msg["target"], msg["key"])
                    
                elif msg["type"] == "SECURE_MSG":
                    # Thread-Safe Deferral for Message Decryption and Insertion
                    self.after(0, lambda m=msg: self.decrypt_incoming_message(m))
            except Exception as e:
                print(f"Network error: {e}")
                break

    def update_peer_list(self, users):
        for widget in self.user_listbox_frame.winfo_children():
            widget.destroy()

        for user in users:
            if user != self.my_username:
                btn = ctk.CTkButton(
                    self.user_listbox_frame, 
                    text=user, 
                    fg_color="transparent", 
                    text_color=("black", "white"),
                    anchor="w",
                    command=lambda u=user: self.select_recipient(u)
                )
                btn.pack(fill="x", pady=2)

    def select_recipient(self, username):
        self.active_recipient = username
        self.text_display.configure(state="normal")
        self.text_display.insert("end", f"\n--- Initiating Secure Session with {username} ---\n")
        self.text_display.configure(state="disabled")
        
        if username not in self.session_keys:
            fetch_payload = {"type": "FETCH_KEY", "target": username}
            self.client_socket.sendall(json.dumps(fetch_payload).encode())

    def compute_shared_session_key(self, peer_name, peer_pub_key_pem):
        peer_public_key = serialization.load_pem_public_key(peer_pub_key_pem.encode('utf-8'))
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        self.session_keys[peer_name] = shared_key[:32]
        print(f"[Crypto] Shared Key derived for peer: {peer_name}")

    def send_secure_message(self):
        if not self.active_recipient or self.active_recipient not in self.session_keys:
            return
        
        plain_text = self.entry_msg.get()
        if not plain_text:
            return

        aesgcm = AESGCM(self.session_keys[self.active_recipient])
        
        # Dynamic Cryptographically Secure Nonce Generation via os.urandom
        nonce_bytes = os.urandom(12)
        
        ciphertext = aesgcm.encrypt(nonce_bytes, plain_text.encode('utf-8'), None)
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce_bytes).decode('utf-8')
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        payload = {
            "type": "SECURE_MSG",
            "sender": self.my_username,
            "target": self.active_recipient,
            "ciphertext": ciphertext_b64,
            "nonce": nonce_b64,
            "timestamp": timestamp
        }
        
        self.client_socket.sendall(json.dumps(payload).encode())
        self.entry_msg.delete(0, "end")
        
        self.text_display.configure(state="normal")
        self.text_display.insert("end", f"[{timestamp}] Me -> {self.active_recipient}: {plain_text}\n")
        self.text_display.configure(state="disabled")

    def decrypt_incoming_message(self, msg_container):
        sender = msg_container["sender"]
        if sender not in self.session_keys:
            return
        
        aesgcm = AESGCM(self.session_keys[sender])
        ciphertext = base64.b64decode(msg_container["ciphertext"])
        nonce = base64.b64decode(msg_container["nonce"])
        
        try:
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            plain_text = decrypted_bytes.decode('utf-8')
            ts = msg_container["timestamp"]
            
            self.text_display.configure(state="normal")
            self.text_display.insert("end", f"[{ts}] {sender}: {plain_text}\n")
            self.text_display.configure(state="disabled")
        except Exception as e:
            print(f"Decryption Fail: {e}")

if __name__ == "__main__":
    app = SecureChatClient()
    app.mainloop()
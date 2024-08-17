import os
import socket
import threading
import base64
import hashlib
import cryptography.fernet
from cryptography.fernet import Fernet
from colorama import init, Fore, Style
import tkinter as tk
from tkinter import scrolledtext, messagebox
import argparse



class EncryptedChatClient:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key
        self.client_socket = None
        self.username = None
        self.message_lock = threading.Lock()
        self.setup_cipher()

        # Initialize GUI elements
        self.root = tk.Tk()
        self.root.title("Encrypted Chat Client")
        self.root.geometry("700x500")
        
        self.top_frame = tk.Frame(self.root, width=600, height=50, bg='gray')
        self.top_frame.pack(side=tk.TOP, fill=tk.X)

        self.middle_frame = tk.Frame(self.root, width=600, height=300, bg='black')
        self.middle_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.bottom_frame = tk.Frame(self.root, width=600, height=50, bg='gray')
        self.bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.username_label = tk.Label(self.top_frame, text="Enter your alias:", font=("Helvetica", 14), bg='gray', fg='white')
        self.username_label.pack(side=tk.LEFT, padx=10)

        self.username_textbox = tk.Entry(self.top_frame, font=("Helvetica", 14), bg='black', fg='white', width=23)
        self.username_textbox.pack(side=tk.LEFT)

        self.username_button = tk.Button(self.top_frame, text="Join", font=("Helvetica", 12), bg='sky blue', fg='white', command=self.get_username)
        self.username_button.pack(side=tk.LEFT, padx=15)

        self.message_box = scrolledtext.ScrolledText(self.middle_frame, font=("Helvetica", 12), bg='black', fg='white', state=tk.DISABLED)
        self.message_box.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Configure tags for left and right alignment
        self.message_box.tag_config('left', justify='left')
        self.message_box.tag_config('right', justify='right')

        # Message entry box and send button
        self.message_textbox = tk.Entry(self.bottom_frame, font=("Helvetica", 14), bg='black', fg='white', width=48)
        self.message_textbox.pack(side=tk.LEFT, padx=10, pady=5)

        self.send_button = tk.Button(self.bottom_frame, text="Send", font=("Helvetica", 12), bg='sky blue', fg='white', command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=10, pady=5)

        # Bind the "Enter" key to the appropriate function based on the current input focus
        self.root.bind('<Return>', self.handle_enter)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_cipher(self):
        hashed_key = hashlib.sha256(self.key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(hashed_key)
        self.cipher = Fernet(fernet_key)

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.add_message("[SERVER] Successfully connected to the server.")
        except ConnectionRefusedError as e:
            messagebox.showerror("Connection Error", f"An unknown error occurred: {e}")
            return False
        return True

    def get_username(self):
        if self.connect():
            try:
                encrypted_username_prompt = self.client_socket.recv(1024)
                username_prompt = self.cipher.decrypt(encrypted_username_prompt).decode('utf-8')
                self.add_message(f"[SERVER] {username_prompt}")

                username = self.username_textbox.get()
                if not username:
                    messagebox.showerror("Invalid Username", "Username cannot be empty.")
                    return False

                encrypted_username = self.cipher.encrypt(username.encode('utf-8'))
                self.client_socket.send(encrypted_username)
                encrypted_response = self.client_socket.recv(1024)
                response = self.cipher.decrypt(encrypted_response).decode('utf-8')

                if "Please enter a different name." in response:
                    self.add_message(f"[SERVER] {response}")
                    return False

                self.username = username
                self.username_textbox.config(state=tk.DISABLED)
                self.username_button.config(state=tk.DISABLED)
                self.add_message(f"Welcome {self.username} to our secure room")
                self.add_message("\t/help -> Help menu")
                threading.Thread(target=self.listen_to_server, daemon=True).start()
                return True
            except cryptography.fernet.InvalidToken:
                messagebox.showerror("Encryption Error", "The encryption key is invalid or data is corrupted.")
                return False

    def add_message(self, message, sent_by_user=False):
        self.message_box.config(state=tk.NORMAL)
        tag = 'right' if sent_by_user else 'left'
        self.message_box.insert(tk.END, message + '\n', tag)
        self.message_box.config(state=tk.DISABLED)
        self.message_box.yview(tk.END)  # Auto-scroll to the latest message

    def listen_to_server(self):
        while True:
            try:
                encrypted_data = self.client_socket.recv(1024)
                decrypted_data = self.cipher.decrypt(encrypted_data).decode('utf-8')

                if decrypted_data == "/clear":
                    self.message_box.config(state=tk.NORMAL)
                    self.message_box.delete('1.0', tk.END)
                    self.message_box.config(state=tk.DISABLED)
                    continue

                with self.message_lock:
                    self.add_message(decrypted_data, sent_by_user=False)
            except cryptography.fernet.InvalidToken:
                continue
            except BrokenPipeError as e:
                if e.errno == 32:
                    continue
                else:
                    self.add_message(f"Error: {e}")
                    break

    def send_message(self):
        message = self.message_textbox.get()
        if message:
            self.message_textbox.delete(0, tk.END)
            encrypted_message = self.cipher.encrypt(message.encode('utf-8'))
            self.client_socket.send(encrypted_message)
            self.add_message(f"You: {message}", sent_by_user=True)
            if message == "/exit":
                self.on_closing()
        else:
            messagebox.showerror("Empty Message", "Message cannot be empty.")

    def on_closing(self):
        try:
            self.client_socket.send(self.cipher.encrypt("/exit".encode('utf-8')))
        except:
            pass
        self.root.destroy()

    def handle_enter(self, event):
        if self.username_textbox['state'] == tk.NORMAL:
            self.get_username()
        else:
            self.send_message()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect to the chat server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--key", default="mysecretpassword")
    args = parser.parse_args()

    client = EncryptedChatClient(args.host, args.port, args.key)
    client.run()

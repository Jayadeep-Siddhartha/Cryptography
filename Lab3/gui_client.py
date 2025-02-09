import tkinter as tk
from tkinter import ttk, filedialog
import socket
from threading import Thread
from AES import encrypt, decrypt
import json

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")

        self.message_label = ttk.Label(root, text="Enter your message:")
        self.message_label.pack()
        self.message_entry = ttk.Entry(root, width=50)
        self.message_entry.pack()

        self.send_button = tk.Button(root, text="Send Message", command=self.send_message, state=tk.DISABLED)
        self.send_button.pack()

        self.file_button = tk.Button(root, text="Send File", command=self.send_file, state=tk.DISABLED)
        self.file_button.pack()

        self.text_area = tk.Text(root, height=15, width=50)
        self.text_area.pack()

        self.status_label = ttk.Label(root, text="Status: Connecting to server...")
        self.status_label.pack()

        self.client_socket = None
        self.key = None

        self.connect_thread = Thread(target=self.connect_to_server)
        self.connect_thread.start()

    def connect_to_server(self):
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect(('127.0.0.1', 12345))

            key_data = temp_socket.recv(4096).decode()
            key_json = json.loads(key_data)
            if key_json['type'] == 'key':
                self.key = bytes.fromhex(key_json['key'])
                print(f"🔑 Received AES Key: {self.key.hex()}")

                self.root.after(0, self.update_status, "Connected to server")
                self.root.after(0, self.enable_send_button)

            temp_socket.close()

        except Exception as e:
            print(f"⚠️ Connection Error: {e}")
            self.root.after(0, self.update_status, f"Error connecting: {str(e)}")

    def update_status(self, status):
        self.status_label.config(text=f"Status: {status}")

    def enable_send_button(self):
        self.send_button.config(state=tk.NORMAL)
        self.file_button.config(state=tk.NORMAL)

    def send_message(self):
        if not self.key:
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        # Display message before encryption
        self.text_area.insert(tk.END, f"📨 You: {message}\n")

        encrypted_message = encrypt(message, self.key)

        send_thread = Thread(target=self.send_encrypted_data, args=("TEXT", encrypted_message))
        send_thread.start()

    def send_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path or not self.key:
            return

        with open(file_path, "r", encoding="utf-8") as f:
            file_data = f.read()

        encrypted_data = encrypt(file_data, self.key)

        self.text_area.insert(tk.END, f"📁 Sent Encrypted File: {file_path}\n")

        send_thread = Thread(target=self.send_encrypted_data, args=("FILE", encrypted_data))
        send_thread.start()

    def send_encrypted_data(self, data_type, encrypted_message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(('127.0.0.1', 12345))
                sock.sendall(json.dumps({"type": data_type, "data": encrypted_message}).encode())

                response = sock.recv(4096)

                # Display **decrypted** message from server
                if data_type == "FILE":
                    self.text_area.insert(tk.END, f"📜 Server Decrypted File Content:\n{response}\n\n")
                else:
                    self.text_area.insert(tk.END, f"📩 Server Response (Decrypted): {response}\n\n")

                self.text_area.yview(tk.END)

        except Exception as e:
            print(f"⚠️ Error: {e}")

root = tk.Tk()
ClientApp(root)
root.mainloop()

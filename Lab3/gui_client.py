import tkinter as tk
from tkinter import ttk
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

        self.text_area = tk.Text(root, height=10, width=50)
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

            key_data = temp_socket.recv(2048).decode()
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

    def send_message(self):
        if not self.key:
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        # Display message before encryption
        self.text_area.insert(tk.END, f"📨 You: {message}\n")

        encrypted_message = encrypt(message, self.key)

        send_thread = Thread(target=self.send_encrypted_message, args=(encrypted_message,))
        send_thread.start()

    def send_encrypted_message(self, encrypted_message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(('127.0.0.1', 12345))
                sock.sendall(encrypted_message.encode())

                response = sock.recv(2048).decode()
                decrypted_response = decrypt(response, self.key)

                # Display server's decrypted response
                self.text_area.insert(tk.END, f"📩 Server: {decrypted_response}\n\n")
                self.text_area.yview(tk.END)

        except Exception as e:
            print(f"⚠️ Error: {e}")

root = tk.Tk()
ClientApp(root)
root.mainloop()

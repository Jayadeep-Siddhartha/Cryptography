import tkinter as tk
from threading import Thread
import socket
from AES import encrypt, decrypt, generate_key
import json

class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Server")

        self.text_area = tk.Text(root, height=15, width=60)
        self.text_area.pack()

        self.start_button = tk.Button(root, text="Start Server", command=self.start_server)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack()

        self.server_socket = None
        self.running = False

        # Generate AES key
        self.key = generate_key()
        print(f"🔑 Server AES Key: {self.key.hex()}")

    def start_server(self):
        self.text_area.delete(1.0, tk.END)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('127.0.0.1', 12345))
        self.server_socket.listen(5)

        self.text_area.insert(tk.END, "✅ Server started. Waiting for clients...\n")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.running = True

        self.accept_thread = Thread(target=self.accept_connections)
        self.accept_thread.start()

    def accept_connections(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.text_area.insert(tk.END, f"🔵 Connected to {addr}\n")

                # Send AES key to client
                conn.sendall(json.dumps({'type': 'key', 'key': self.key.hex()}).encode())

                client_thread = Thread(target=self.handle_client, args=(conn,))
                client_thread.start()
            except Exception as e:
                if self.running:
                    self.text_area.insert(tk.END, f"❌ Connection Error: {str(e)}\n")

    def handle_client(self, conn):
        try:
            data = conn.recv(2048).decode()
            if not data:
                return

            # Decrypt received message
            decrypted_msg = decrypt(data, self.key)

            # Display encrypted & decrypted message
            self.text_area.insert(tk.END, f"🔒 Encrypted: {data}\n🔓 Decrypted: {decrypted_msg}\n\n")
            self.text_area.yview(tk.END)

            # Encrypt and send back
            encrypted_response = encrypt(decrypted_msg, self.key)
            conn.sendall(encrypted_response.encode())

        except Exception as e:
            print(f"⚠️ Error: {e}")

        conn.close()

    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.text_area.insert(tk.END, "⛔ Server stopped.\n")

root = tk.Tk()
ServerApp(root)
root.mainloop()

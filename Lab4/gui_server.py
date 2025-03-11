from RC4 import rc4_decrypt
from Crypto.Util.Padding import pad, unpad
import binascii
import tkinter as tk
from threading import Thread
import socket

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

    def start_server(self):
        self.text_area.delete(1.0, tk.END)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('127.0.0.1', 12345))
        self.server_socket.listen(5)

        self.text_area.insert(tk.END, "Server started. Waiting for connection...\n")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.running = True

        self.accept_thread = Thread(target=self.accept_connections)
        self.accept_thread.start()

    def accept_connections(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.text_area.insert(tk.END, f"Connection established with {addr}\n")
                client_thread = Thread(target=self.handle_client, args=(conn,))
                client_thread.start()
            except Exception as e:
                if self.running:
                    self.text_area.insert(tk.END, f"Error: {str(e)}\n")

    def handle_client(self, conn):
        while self.running:
            try:
                data = conn.recv(4096).decode()
                if not data:
                    break
                
                parts = data.split("|", 3)  # Split into up to 4 parts
                if len(parts) == 3:  
                    algorithm, encrypted_msg_hex, key = parts
                    data_type = "TEXT"
                elif len(parts) == 4:  
                    algorithm, data_type, encrypted_msg_hex, key = parts
                else:
                    continue  

                try:
                    if len(encrypted_msg_hex) % 2 != 0:
                        encrypted_msg_hex += "0" 

                    encrypted_msg = binascii.unhexlify(encrypted_msg_hex.encode())
                except binascii.Error:
                    self.text_area.insert(tk.END, "Error: Invalid hex data received.\n")
                    continue

                decrypted_msg = ""

                encrypted_msg = binascii.unhexlify(encrypted_msg_hex.encode())

                decrypted_msg = rc4_decrypt(key.encode(), encrypted_msg)
            
                if data_type == "FILE":
                    self.text_area.insert(tk.END, f"Received Encrypted File Content:\n{encrypted_msg}\n")
                    self.text_area.insert(tk.END, f"Decrypted File Content:\n{decrypted_msg}\n\n")
                else:
                    self.text_area.insert(tk.END, f"Encrypted: {encrypted_msg_hex}\nDecrypted: {decrypted_msg}\n\n")

                self.text_area.yview(tk.END)

                conn.sendall(decrypted_msg.encode())

            except Exception as e:
                self.text_area.insert(tk.END, f"Error: {str(e)}\n")
                break
        conn.close()


    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.text_area.insert(tk.END, "Server stopped.\n")

root = tk.Tk()
ServerApp(root)
root.mainloop()
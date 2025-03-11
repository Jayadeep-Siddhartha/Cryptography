import socket
import tkinter as tk
from threading import Thread
from RC4 import rc4_decrypt
import binascii
import random


n = 23
g = 5

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
        self.shared_key = None  

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

                self.shared_key = self.diffie_hellman_key_exchange(conn)
                self.text_area.insert(tk.END, f"Shared Key Established: {self.shared_key}\n")

                client_thread = Thread(target=self.handle_client, args=(conn,))
                client_thread.start()
            except Exception as e:
                if self.running:
                    self.text_area.insert(tk.END, f"Error: {str(e)}\n")

    def diffie_hellman_key_exchange(self, conn):
        """ Perform Diffie-Hellman key exchange with the client """
        try:
            private_key = random.randint(1, n-1)

            client_public_key = int(conn.recv(1024).decode())

            server_public_key = pow(g, private_key, n)
            conn.sendall(str(server_public_key).encode())

            shared_key = pow(client_public_key, private_key, n)
            print("Shared Key Established:", shared_key)

            return shared_key
        except Exception as e:
            print(f"Key Exchange Error: {e}")
            return None

    def handle_client(self, conn):
        while self.running:
            try:
                data = conn.recv(1024).decode()
                if not data:
                    break

                encrypted_msg = binascii.unhexlify(data.encode())

                rc4_key = str(self.shared_key).encode()
                decrypted_msg = rc4_decrypt(rc4_key, encrypted_msg)

                self.text_area.insert(tk.END, f"Decrypted Message: {decrypted_msg}\n\n")

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

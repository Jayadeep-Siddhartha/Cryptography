import tkinter as tk
from threading import Thread
import socket
from Encryption.caesar_cipher import caesar_decipher
from Encryption.vigenere_cipher import vigenere_decrypt
from Encryption.hill_cipher import hill_decrypt, key_matrix
from Encryption.playfair_cipher import playfair_decrypt

class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Server")

        self.text_area = tk.Text(root, height=10, width=50)
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
                client_thread = Thread(target=self.handle_client, args=(conn,))
                client_thread.start()
            except Exception as e:
                if self.running:
                    self.text_area.insert(tk.END, f"Error: {str(e)}\n")

    def handle_client(self, conn):
        while self.running:
            try:
                data = conn.recv(1024).decode()
                if not data:
                    break
                
                algorithm, encrypted_msg = data.split("|", 1)
                if algorithm == "Caesar":
                    decrypted_msg = caesar_decipher(encrypted_msg, 3)
                elif algorithm == "Vigenere":
                    decrypted_msg = vigenere_decrypt(encrypted_msg, "KEY")
                elif algorithm == "Hill":
                    decrypted_msg = hill_decrypt(encrypted_msg, key_matrix)
                elif algorithm == "Playfair":
                    decrypted_msg = playfair_decrypt(encrypted_msg, "MONARCHY")

                self.text_area.insert(tk.END, f"Encrypted: {encrypted_msg}\nDecrypted: {decrypted_msg}\n\n")
                self.text_area.yview(tk.END)

                # Send decrypted message back to client
                conn.sendall(decrypted_msg.encode())

            except Exception as e:
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

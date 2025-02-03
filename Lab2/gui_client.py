import tkinter as tk
from tkinter import ttk, filedialog
import socket
from threading import Thread
from DESLibrary import des_encrypt, des_decrypt, encrypt_file, decrypt_file
from DES3Library import des3_encrypt, des3_decrypt

DES_KEY = b'8bytekey'
DES3_KEY = b'16byteslongkey!!'

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")
        
        self.algorithm = tk.StringVar(value="DES")

        ttk.Label(root, text="Encryption Algorithm:").pack()
        self.algorithm_combo = ttk.Combobox(root, textvariable=self.algorithm, values=["DES", "3DES"])
        self.algorithm_combo.pack()

        self.message_label = ttk.Label(root, text="Enter your message:")
        self.message_label.pack()
        self.message_entry = ttk.Entry(root, width=50)
        self.message_entry.pack()

        self.send_button = tk.Button(root, text="Send Message", command=self.send_message)
        self.send_button.pack()

        self.file_button = tk.Button(root, text="Send File", command=self.send_file)
        self.file_button.pack()

        self.text_area = tk.Text(root, height=10, width=50)
        self.text_area.pack()
        
        self.client_socket = None
        self.receive_thread = Thread(target=self.receive_messages)
        self.receive_thread.start()

    def send_message(self):
        message = self.message_entry.get()
        algorithm = self.algorithm.get()
        
        if message == "":
            return

        if algorithm == "DES":
            encrypted_message = des_encrypt(message, DES_KEY)
        else:
            encrypted_message = des3_encrypt(message, DES3_KEY)

        self.text_area.insert(tk.END, f"Your Message Sent: {message}\n")
        self.text_area.yview(tk.END)
        self.message_entry.delete(0, tk.END)
        
        send_thread = Thread(target=self.send_encrypted_message, args=(algorithm, encrypted_message,))
        send_thread.start()

    def send_encrypted_message(self, algorithm, encrypted_message):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 12345))
            self.client_socket.sendall(f"{algorithm}|{encrypted_message}|{DES_KEY.decode() if algorithm == 'DES' else DES3_KEY.decode()}".encode())


            decrypted_message = self.client_socket.recv(1024).decode()
            self.text_area.insert(tk.END, f"Decrypted Message from Server: {decrypted_message}\n\n")
            self.text_area.yview(tk.END)

            self.client_socket.close()
        except Exception as e:
            print(f"Error sending message: {e}")

    def send_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        algorithm = self.algorithm.get()
        encrypted_file_path = file_path + ".enc"
        encrypt_file(file_path, encrypted_file_path, DES3_KEY if algorithm == "3DES" else DES_KEY, use_3des=(algorithm == "3DES"))
        self.text_area.insert(tk.END, f"File encrypted and saved: {encrypted_file_path}\n")
        
    def receive_messages(self):
        while True:
            try:
                if self.client_socket:
                    decrypted_message = self.client_socket.recv(1024).decode()
                    self.text_area.insert(tk.END, f"Decrypted Message from Server: {decrypted_message}\n\n")
                    self.text_area.yview(tk.END)
            except:
                break

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
                
                if algorithm == "DES":
                    decrypted_msg = des_decrypt(encrypted_msg, DES_KEY)
                else:
                    decrypted_msg = des3_decrypt(encrypted_msg, DES3_KEY)

                self.text_area.insert(tk.END, f"Encrypted: {encrypted_msg}\nDecrypted: {decrypted_msg}\n\n")
                self.text_area.yview(tk.END)
                
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

if __name__ == "__main__":
    root = tk.Tk()
    if "server" in root.tk.call("info", "commands"):
        app = ServerApp(root)
    else:
        app = ClientApp(root)
    root.mainloop()

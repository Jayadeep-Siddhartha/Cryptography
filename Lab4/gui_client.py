import tkinter as tk
from tkinter import ttk, filedialog
import socket
from threading import Thread
from RC4 import rc4_encrypt
import binascii
RC4_Key = b'Secret'

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")
        
        self.algorithm = tk.StringVar(value="RC4")

        ttk.Label(root, text="Encryption Algorithm:").pack()
        self.algorithm_combo = ttk.Combobox(root, textvariable=self.algorithm, values=["RC4"])
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

        encrypted_message = rc4_encrypt(RC4_Key, message)
        
        self.text_area.insert(tk.END, f"Your Message Sent: {message}\n")
        self.text_area.yview(tk.END)
        self.message_entry.delete(0, tk.END)
        
        send_thread = Thread(target=self.send_encrypted_message, args=(algorithm, encrypted_message,))
        send_thread.start()

    def send_encrypted_message(self, algorithm, encrypted_message):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 12345))

            encrypted_hex = binascii.hexlify(encrypted_message).decode()

            self.client_socket.sendall(f"{algorithm}|{encrypted_hex}|{RC4_Key.decode()}".encode())


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

        # Read file content
        with open(file_path, "rb") as f:
            file_data = f.read()

        encrypted_data = rc4_encrypt(RC4_Key,file_data.decode()) 
        
        encrypted_hex = binascii.hexlify(encrypted_data).decode()
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 12345))

            self.client_socket.sendall(f"{algorithm}|FILE|{encrypted_hex}|{RC4_Key.decode()}".encode())

            decrypted_message = self.client_socket.recv(4096).decode()
            self.text_area.insert(tk.END, f"Decrypted File Content from Server:\n{decrypted_message}\n\n")
            self.text_area.yview(tk.END)

            self.client_socket.close()
        except Exception as e:
            print(f"Error sending file: {e}")

        
    def receive_messages(self):
        while True:
            try:
                if self.client_socket:
                    decrypted_message = self.client_socket.recv(1024).decode()
                    self.text_area.insert(tk.END, f"Decrypted Message from Server: {decrypted_message}\n\n")
                    self.text_area.yview(tk.END)
            except:
                break


if __name__ == "__main__":
    root = tk.Tk()   
    app = ClientApp(root)
    root.mainloop()

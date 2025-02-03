import tkinter as tk
from tkinter import ttk
import socket
from threading import Thread
from Encryption.caesar_cipher import caesar_cipher
from Encryption.vigenere_cipher import vigenere_encrypt
from Encryption.hill_cipher import hill_encrypt, key_matrix
from Encryption.playfair_cipher import playfair_encrypt

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")

        self.algorithm = tk.StringVar(value="Caesar")

        ttk.Label(root, text="Encryption Algorithm:").pack()
        self.algorithm_combo = ttk.Combobox(root, textvariable=self.algorithm, values=["Caesar", "Vigenere", "Hill", "Playfair"])
        self.algorithm_combo.pack()

        self.message_label = ttk.Label(root, text="Enter your message:")
        self.message_label.pack()
        self.message_entry = ttk.Entry(root, width=50)
        self.message_entry.pack()

        self.send_button = tk.Button(root, text="Send Message", command=self.send_message)
        self.send_button.pack()

        self.text_area = tk.Text(root, height=10, width=50)
        self.text_area.pack()

        # Start listening thread for receiving messages from the server
        self.client_socket = None
        self.receive_thread = Thread(target=self.receive_messages)
        self.receive_thread.start()

    def send_message(self):
        message = self.message_entry.get()
        algorithm = self.algorithm.get()

        if message == "":
            return  # Do nothing if the message is empty

        # Encrypt the message based on selected algorithm
        if algorithm == "Caesar":
            encrypted_message = caesar_cipher(message, 3)
        elif algorithm == "Vigenere":
            key = "KEY"
            encrypted_message = vigenere_encrypt(message, key)
        elif algorithm == "Hill":
            encrypted_message = hill_encrypt(message, key_matrix)
        elif algorithm == "Playfair":
            key = "MONARCHY"
            encrypted_message = playfair_encrypt(message, key)

        self.text_area.insert(tk.END, f"Your Message Sent: {message}\n")
        self.text_area.yview(tk.END)
        self.message_entry.delete(0, tk.END)

        send_thread = Thread(target=self.send_encrypted_message, args=(algorithm, encrypted_message,))
        send_thread.start()

    def send_encrypted_message(self, algorithm, encrypted_message):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 12345))
            self.client_socket.sendall(f"{algorithm}|{encrypted_message}".encode())

            # Wait for the response from server
            decrypted_message = self.client_socket.recv(1024).decode()
            self.text_area.insert(tk.END, f"Decrypted Message from Server: {decrypted_message}\n\n")
            self.text_area.yview(tk.END)

            self.client_socket.close()
        except Exception as e:
            print(f"Error sending message: {e}")

    def receive_messages(self):
        while True:
            try:
                if self.client_socket:
                    decrypted_message = self.client_socket.recv(1024).decode()
                    self.text_area.insert(tk.END, f"Decrypted Message from Server: {decrypted_message}\n\n")
                    self.text_area.yview(tk.END)
            except:
                break

root = tk.Tk()
ClientApp(root)
root.mainloop()

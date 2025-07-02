import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
import json
from tkinter import filedialog
import os
from PIL import Image, ImageTk


HOST = '127.0.0.1'
PORT = 5000

class ChatClient:
    def __init__(self, master):
        # Initialize the client GUI and connection to server
        self.master = master
        self.master.title("Python Chat")

        # Socket
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # GUI Layout
        self.left_frame = tk.Frame(master) # left (contacts) 
        self.left_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.Y)

        self.right_frame = tk.Frame(master) # right (chat)
        self.right_frame.pack(side=tk.RIGHT, padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Contacts list
        self.contacts_label = tk.Label(self.left_frame, text="Contacts")
        self.contacts_label.pack()

        self.contacts_listbox = tk.Listbox(self.left_frame, width=20)
        self.contacts_listbox.pack(fill=tk.Y, expand=True)
        self.contacts_listbox.bind('<<ListboxSelect>>', self.on_contact_select)

        # Chat area
        self.chat_area = scrolledtext.ScrolledText(self.right_frame, wrap=tk.WORD, state='disabled', height=20, width=50)
        self.chat_area.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Input box, send and send file buttons
        self.entry = tk.Entry(self.right_frame, width=40)
        self.entry.pack(side=tk.LEFT, padx=(5, 0), pady=5)
        self.entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.right_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5)

        self.send_file_button = tk.Button(self.right_frame, text="Send File", command=self.send_file)
        self.send_file_button.pack(side=tk.LEFT, padx=5)

        # Ask for username
        self.username = simpledialog.askstring("Username", "Enter your username:", parent=master)
        if not self.username:
            master.destroy()
            return

        # Selected chat
        self.selected_contact = None

        self.connect_to_server()

        # Store chat history per contact 
        self.chats = {}

        # Make sure images don't get deleted
        self.image_refs = []


    def connect_to_server(self):
        try:
            self.client.connect((HOST, PORT)) 
            self.client.send(self.username.encode()) # send username to server
            threading.Thread(target=self.receive_messages, daemon=True).start() # start thread to receive messages
        except Exception as e:
            messagebox.showerror("Connection Error", f"Cannot connect to server: {e}")
            self.master.destroy()

    def on_contact_select(self, event):
        if not self.contacts_listbox.curselection():
            return
        index = self.contacts_listbox.curselection()[0]
        contact = self.contacts_listbox.get(index)
        self.selected_contact = contact
        self.load_chat(contact) # load chat

    def load_chat(self, contact):
        self.chat_area.config(state='normal')
        self.chat_area.delete('1.0', tk.END)
        messages = self.chats.get(contact, [])
        for msg in messages:
            self.chat_area.insert(tk.END, msg + "\n") #load messages
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END) # go to the bottom on open

    # Extensions recognized as images
    IMAGE_EXTENSIONS = [".png", ".jpg", ".jpeg", ".gif", ".bmp"]

    def receive_messages(self):
        while True:
            try:
                data = self.client.recv(1024)
                if not data: # if server disconnects, break loop
                    break 

                msg_obj = json.loads(data.decode()) # parse JSON

                if msg_obj["type"] == "user_list":
                    self.update_user_list(msg_obj["users"]) # update list of users in UI

                elif msg_obj["type"] == "chat": # if it is a regular text message
                    sender = msg_obj["sender"]
                    message = msg_obj["message"] 
                    self.chats.setdefault(sender, []).append(f"[{sender}]: {message}") # store message in chat

                    if sender == self.selected_contact: # if it is for this chat
                        self.chat_area.config(state='normal')
                        self.chat_area.insert(tk.END, f"[{sender}]: {message}\n") # show message 
                        self.chat_area.config(state='disabled')
                        self.chat_area.yview(tk.END)

                if msg_obj["type"] == "file": # if it is a file
                    sender = msg_obj["sender"]
                    filename = msg_obj["filename"]
                    filesize = msg_obj["filesize"]

                    # receive file bytes in chunks
                    bytes_received = 0
                    file_bytes = b""
                    while bytes_received < filesize:
                        chunk = self.client.recv(min(4096, filesize - bytes_received))
                        if not chunk:
                            break
                        file_bytes += chunk
                        bytes_received += len(chunk)

                    # save file
                    downloads_dir = os.path.join(os.path.dirname(__file__), "downloads")
                    os.makedirs(downloads_dir, exist_ok=True)
                    file_path = os.path.join(downloads_dir, filename)

                    with open(file_path, "wb") as f:
                        f.write(file_bytes)

                    ext = os.path.splitext(filename)[1].lower()
                    self.chats.setdefault(sender, [])

                    if ext in self.IMAGE_EXTENSIONS: # check if file is an image
                        try:
                            # show image in chat
                            img = Image.open(file_path)
                            img.thumbnail((200, 200))
                            photo = ImageTk.PhotoImage(img)

                            # avoid garbage collection
                            if not hasattr(self, "image_refs"):
                                self.image_refs = []
                            self.image_refs.append(photo)

                            # show image in chat if it is from current contact
                            if sender == self.selected_contact:
                                self.chat_area.config(state='normal')
                                self.chat_area.insert(tk.END, f"[{sender} sent image]: {filename}\n")
                                self.chat_area.image_create(tk.END, image=photo)
                                self.chat_area.insert(tk.END, "\n")
                                self.chat_area.config(state='disabled')
                                self.chat_area.yview(tk.END)

                            self.chats[sender].append(f"[{sender} sent image]: {filename}")
                        except Exception as e:
                            print("Failed to display image:", e)
                            self.chats[sender].append(f"[{sender} sent file]: {filename} (couldn't display)")
                    else:
                        # not an image, regular file
                        self.chats[sender].append(f"[{sender} sent file]: {filename}")
                        if sender == self.selected_contact:
                            self.chat_area.config(state='normal')
                            self.chat_area.insert(tk.END, f"[{sender} sent file]: {filename} (saved to {file_path})\n")
                            self.chat_area.config(state='disabled')
                            self.chat_area.yview(tk.END)

            except Exception as e:
                print("Error receiving message:", e)
                break

    

    def update_user_list(self, users):
        # Remove self from contact list
        users = [u for u in users if u != self.username]
        self.contacts_listbox.delete(0, tk.END)
        for user in users:
            self.contacts_listbox.insert(tk.END, user)

        # Select first contact if none selected
        if not self.selected_contact and users:
            self.contacts_listbox.selection_set(0)
            self.selected_contact = users[0]
            self.load_chat(self.selected_contact)

    def send_message(self, event=None):
        if not self.selected_contact:
            messagebox.showwarning("No Contact Selected", "Please select a contact to send message.")
            return
        message = self.entry.get().strip()
        if not message:
            return # not allowing to send an empty message
        
        # message object
        msg_obj = {
            "type": "chat",
            "sender": self.username,
            "receiver": self.selected_contact,
            "message": message
        }
        try:
            self.client.send(json.dumps(msg_obj).encode()) # send message to server

            # show in own chat
            self.chats.setdefault(self.selected_contact, []).append(f"[You]: {message}")
            if self.selected_contact == self.selected_contact:
                self.chat_area.config(state='normal')
                self.chat_area.insert(tk.END, f"[You]: {message}\n")
                self.chat_area.config(state='disabled')
                self.chat_area.yview(tk.END)
            self.entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")
    
    def send_file(self):
        if not self.selected_contact:
            messagebox.showwarning("No Contact Selected", "Please select a contact to send file.")
            return

        filepath = filedialog.askopenfilename() # file selection
        if not filepath:
            return # cancelled by user

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        file_header = {
            "type": "file",
            "sender": self.username,
            "receiver": self.selected_contact,
            "filename": filename,
            "filesize": filesize
        }

        try:
            # send file header
            self.client.send(json.dumps(file_header).encode())

            # send file bytes in chunks
            with open(filepath, "rb") as f:
                while True:
                    bytes_read = f.read(4096)
                    if not bytes_read:
                        break
                    self.client.send(bytes_read)

            self.chats.setdefault(self.selected_contact, [])

            ext = os.path.splitext(filename)[1].lower()
            if ext in self.IMAGE_EXTENSIONS: # check if it is an image
                try:
                    # show image in chat
                    image = Image.open(filepath)
                    image.thumbnail((200, 200))
                    photo = ImageTk.PhotoImage(image)

                    # keep reference to image
                    if not hasattr(self, "image_refs"):
                        self.image_refs = []
                    self.image_refs.append(photo)


                    if self.selected_contact == self.selected_contact:
                        self.chat_area.config(state='normal')
                        self.chat_area.insert(tk.END, f"[You sent image]: {filename}\n")
                        self.chat_area.image_create(tk.END, image=photo)
                        self.chat_area.insert(tk.END, "\n")
                        self.chat_area.config(state='disabled')
                        self.chat_area.yview(tk.END)

                    self.chats[self.selected_contact].append(f"[You sent image]: {filename}")
                except Exception as e:
                    print("Failed to show sent image:", e)
                    self.chat_area.config(state='normal')
                    self.chat_area.insert(tk.END, f"[You sent file]: {filename} (couldn't display)\n")
                    self.chat_area.config(state='disabled')
            else: # not an image, show send notification
                self.chats[self.selected_contact].append(f"[You sent file]: {filename}")
                self.chat_area.config(state='normal')
                self.chat_area.insert(tk.END, f"[You sent file]: {filename}\n")
                self.chat_area.config(state='disabled')

            self.chat_area.yview(tk.END)

        except Exception as e:
            messagebox.showerror("Send File Error", f"Failed to send file: {e}")


def main():
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()

if __name__ == "__main__":
    main()

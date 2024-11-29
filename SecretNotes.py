from tkinter import *
import os
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import base64, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



window = Tk()
window.title("Secret Notes")
window.minsize(width=450,height=750)
window.config(padx=40,pady=20)

#importing logo image
logo = Image.open("top_secret_logo.png")
resize_logo = logo.resize((220,200))
img = ImageTk.PhotoImage(resize_logo)

#logo label
logo_label = Label(image=img)
logo_label.image = img
logo_label.pack()

#title label
title_label = Label(text="Enter Your Title",font=("bold",12))
title_label.pack()

#title entry
title_entry = Entry(width=30)
title_entry.pack()

#text title
text_title = Label(text="Enter Your Secret",font=("bold",12))
text_title.pack()

#text
secret_text = Text(width=30,height=18)
secret_text.pack()

#master key title
masterKey_title = Label(text="Enter master key",font=("bold",12))
masterKey_title.pack()

#master key entry
master_entry = Entry(width=30)
master_entry.pack()

encrypted = Entry()

Input = "mysecrets"
SecretNotes = str("" + Input + ".txt")
TextFile = open(SecretNotes, "w")
with open(SecretNotes, mode="w") as txt_title:
    txt_title.write("My Secret Notes:")

def gen_fernet_key(passcode:bytes) -> bytes:
    assert isinstance(passcode, bytes)
    hlib = hashlib.md5()
    hlib.update(passcode)
    return base64.urlsafe_b64encode(hlib.hexdigest().encode('latin-1'))

key1 = b'u8RAvUKIPE3w3VLklEqXv4466uCeEvlKxCvdvEjxDUs='
key = Fernet.generate_key()
fernet = Fernet(key)
#token = 0

encryption = "0"
passcode = "0"
#key = gen_fernet_key(passcode.encode('utf-8'))

def encrypt_button():
    global encryption
    global key
    global passcode
    global fernet

    passcode = master_entry.get()
    key = gen_fernet_key(passcode.encode('utf-8'))
    fernet = Fernet(key)
    data_in = secret_text.get("1.0",END)
    encryption = fernet.encrypt(data_in.encode('utf-8'))
    encrypted.insert(0, encryption)

    with open(SecretNotes,mode="a") as append_note:
        append_note.write("\n"+title_entry.get() + "\n" + encrypted.get())

    title_entry.delete(0,END)
    secret_text.delete("1.0",END)
    master_entry.delete(0,END)

"""    message = secret_text.get("1.0",END)
    x = message.encode()
    encryption = f.encrypt(x)
    encrypted.insert(0, encryption)""" \
 \
"""    password = bytes(master_entry.get(), "utf-8")
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    token = f.encrypt(bytes(secret_text.get("1.0",END),"utf-8"))
    encrypted.insert(0, token)"""

def decrypt_button():
    #fernet = Fernet(key)
    if master_entry.get() == passcode:
        fernet = Fernet(key)
        decryption = fernet.decrypt(encryption).decode('utf-8')
        secret_text.delete("1.0", END)
        secret_text.insert("1.0", decryption)

    else:
        fernet = Fernet(key1)
        secret_text.delete("1.0",END)
        secret_text.insert("1.0","Wrong Master Key")

    """decryption = fernet.decrypt(encryption).decode('utf-8')
    secret_text.delete("1.0", END)
    secret_text.insert("1.0", decryption)"""

    """f = Fernet(key)
    message2 = secret_text.get("1.0", END)
    decryption = f.decrypt(message2.encode())
    secret_text.delete("1.0",END)
    secret_text.insert("1.0",decryption)"""

#encrypt and save button
save_encrypt = Button(text="Save & Encrypt",command=encrypt_button)
save_encrypt.pack()

#decrypt button
decrypt_button = Button(text="Decrypt",command=decrypt_button)
decrypt_button.pack()


window.mainloop()

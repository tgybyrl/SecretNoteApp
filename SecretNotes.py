from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import base64, hashlib

#window
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

encrypted = Text(width=30,height=18)

"""with open(SecretNotes, mode="a") as txt_title:
    txt_title.write("My Secret Notes:")"""

def gen_fernet_key(passcode:bytes) -> bytes:
    assert isinstance(passcode, bytes)
    hlib = hashlib.md5()
    hlib.update(passcode)
    return base64.urlsafe_b64encode(hlib.hexdigest().encode('latin-1'))

#key variables
key1 = b'u8RAvUKIPE3w3VLklEqXv4466uCeEvlKxCvdvEjxDUs='
key = Fernet.generate_key() #or key = gen_fernet_key(passcode.encode('utf-8'))

fernet = Fernet(key)

# encryption and passcode variable to use in function
encryption = "0"
passcode = "0"


def encrypt_button():
    global passcode
    global key
    global fernet
    global encryption
    global encrypted

    passcode = master_entry.get()
    key = gen_fernet_key(passcode.encode('utf-8'))
    fernet = Fernet(key)
    data_in = secret_text.get("1.0",END)
    encryption = fernet.encrypt(data_in.encode('utf-8'))
    encrypted.insert("1.0", encryption)

    Input = "mysecrets"
    SecretNotes = str("" + Input + ".txt")
    TextFile = open(SecretNotes, "a")

    with open(SecretNotes,mode="a") as append_note:
        append_note.write("\n"+title_entry.get() + "\n" + encrypted.get("1.0",END))

    title_entry.delete(0,END)
    """print(secret_text.get("1.0",END))
    print(encryption)
    print(encrypted.get())"""
    secret_text.delete("1.0",END)
    master_entry.delete(0,END)
    print(encrypted.get("1.0",END))

def decrypt_button():
    data_in = secret_text.get("1.0", END)
    if data_in == encrypted.get("1.0",END):
        if master_entry.get() == passcode:
            decryption = fernet.decrypt(encryption).decode('utf-8')
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decryption)
        else:
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", "Wrong Master Key")
    else:
        messagebox.showerror(title="Wrong Input", message="Please make sure of encrypted info")

    print(data_in)
    print(encrypted.get("1.0",END))

    """    data_in = secret_text.get("1.0", END)
    if master_entry.get() == passcode and data_in == encrypted.get("1.0",END):
        decryption = fernet.decrypt(encryption).decode('utf-8')
        secret_text.delete("1.0", END)
        secret_text.insert("1.0", decryption)
    else:
        secret_text.delete("1.0",END)
        secret_text.insert("1.0","Wrong Master Key")"""


    """if secret_text.get("1.0", END) == encrypted:
        if master_entry.get() == passcode:
            decryption = fernet.decrypt(encryption).decode('utf-8')
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decryption)
        else:
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", "Wrong Master Key")
    else:
        messagebox.showerror(title="Wrong Input", message="Please make sure of encrypted info")"""


    """if master_entry.get() == passcode:
            fernet = Fernet(key)
            decryption = fernet.decrypt(encryption).decode('utf-8')
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decryption)
        else:
            fernet = Fernet(key1)
            secret_text.delete("1.0",END)
            secret_text.insert("1.0","Wrong Master Key")"""


#encrypt and save button
save_encrypt = Button(text="Save & Encrypt",command=encrypt_button)
save_encrypt.pack()

#decrypt button
decrypt_button = Button(text="Decrypt",command=decrypt_button)
decrypt_button.pack()


window.mainloop()

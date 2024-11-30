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

#File creation
Input = "mysecrets"
SecretNotes = str("" + Input + ".txt")
"""with open(SecretNotes, mode="a") as txt_title:
    txt_title.write("My Secret Notes:")"""
"""with open(SecretNotes, mode="w") as txt_title:
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

#for insert encryption in function
encrypted = Text(width=30,height=18)

def encrypt_button():
    global passcode
    global key
    global fernet
    global encryption
    global encrypted

    if title_entry.get() == "" or  secret_text.get("1.0", END) == "" or master_entry.get() == "":
        messagebox.showerror(title="Warning",message="Please enter all of the information")
    else:
        passcode = master_entry.get()
        key = gen_fernet_key(passcode.encode('utf-8'))
        fernet = Fernet(key)
        data_in = secret_text.get("1.0",END)
        encryption = fernet.encrypt(data_in.encode('utf-8'))
        encrypted.insert("1.0", encryption)


        with open(SecretNotes,mode="a") as append_note:
            append_note.write("\n"+title_entry.get() + "\n" + encrypted.get("1.0",END))

        title_entry.delete(0,END)
        secret_text.delete("1.0",END)
        master_entry.delete(0,END)

def decrypt_button():
    data_in = secret_text.get("1.0", END)
    if master_entry.get() == "":
        messagebox.showerror(title="Empty Input",message="Please enter all of the information")
    elif data_in == encrypted.get("1.0", END):
        if master_entry.get() == passcode:
            decryption = fernet.decrypt(encryption).decode('utf-8')
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decryption)
        else:
            messagebox.showerror(title="Wrong Key",message="Wrong master key!")
    else:
        messagebox.showerror(title="Wrong Input", message="Please make sure of encrypted info")


    """data_in = secret_text.get("1.0", END)

    if master_entry.get() != passcode:
        secret_text.delete("1.0", END)
        secret_text.insert("1.0", "Wrong Master Key")

    elif data_in != encrypted.get("1.0",END):
        messagebox.showerror(title="Wrong Input", message="Please make sure of encrypted info")

    else:
        fernet = Fernet(key)
        decryption = fernet.decrypt(encryption).decode('utf-8')
        secret_text.delete("1.0", END)
        secret_text.insert("1.0", decryption)"""




#encrypt and save button
save_encrypt = Button(text="Save & Encrypt",command=encrypt_button)
save_encrypt.pack()

#decrypt button
decrypt_button = Button(text="Decrypt",command=decrypt_button)
decrypt_button.pack()


window.mainloop()

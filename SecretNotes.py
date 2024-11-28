from tkinter import *
from PIL import Image, ImageTk
from cryptography.fernet import Fernet



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

key1 = b'u8RAvUKIPE3w3VLklEqXv4466uCeEvlKxCvdvEjxDUs='


Input = "mysecrets"
SecretNotes = str("" + Input + ".txt")
TextFile = open(SecretNotes, "w")
with open(SecretNotes, mode="w") as txt_title:
    txt_title.write("My Secret Notes:")
def encrypt_button():
    global key1
    f = Fernet(key1)
    message = secret_text.get("1.0",END)
    x = message.encode()
    encryption = f.encrypt(x)
    encrypted.insert(0, encryption)

    with open(SecretNotes,mode="a") as append_note:
        append_note.write("\n"+title_entry.get() + "\n" + encrypted.get())


    title_entry.delete(0,END)
    secret_text.delete("1.0",END)
    master_entry.delete(0,END)

"""    def keycreator():
        global key1
        key1 = Fernet.generate_key()
        password = 0
        password = bytes(master_entry.get())

    keycreator()"""

def decrypt_button():
    f = Fernet(key1)
    message2 = secret_text.get("1.0",END)
    decryption = f.decrypt(message2.encode())
    secret_text.delete("1.0",END)
    secret_text.insert("1.0",decryption)

#encrypt and save button
save_encrypt = Button(text="Save & Encrypt",command=encrypt_button)
save_encrypt.pack()

#decrypt button
decrypt_button = Button(text="Decrypt",command=decrypt_button)
decrypt_button.pack()


window.mainloop()

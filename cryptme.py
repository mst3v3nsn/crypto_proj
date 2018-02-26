# programming project for CS563 - Fall2017
# written by Matthew Stevenson
#
# any questions please email: mstev019@odu.du

from Tkinter import *
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import tkMessageBox

# Asymmetric class
class Asymmetric:

# Asymmetric initializer
    def __init__(self):
        self.frame = Frame(root)
        self.frame.pack()
        text_a = StringVar()
        self.label1 = Label(root, text="Asymmetric Encryption")
        self.label1.grid(row=0, column=0)
        self.label1.pack()
        self.label2 = Label(root, text="Enter Phrase to Generate Public Key and Private Keys:")
        self.label2.grid(row=1, column=0)
        self.label2.pack()
        self.display = Entry(root, textvariable=text_a)
        self.display.grid(row=1, column=1)
        self.display.pack()
        self.text = text_a
        self.gen_key = Button(root, text="Generate Key", command=self.generate_keys)
        self.gen_key.pack()

# Asymmetric generate private and public key pairs
    def generate_keys(self):
        plain_text = self.text.get()
        self.key = RSA.generate(2048)
        self.priv_key = self.key.exportKey(passphrase=plain_text, pkcs=8)
        self.priv_key1 = self.key.exportKey(passphrase=plain_text, pkcs=8)
        alert1 = tkMessageBox.showinfo("Private Key for Sender", self.priv_key)
        alert2 = tkMessageBox.showinfo("Private Key for Receiver", self.priv_key1)
        alert3 = tkMessageBox.showinfo("Public Key", self.key.publickey().exportKey())
        self.mess = StringVar()
        self.enterMessage = Label(root, text="Enter message you would like to encrypt:")
        self.enterMessage.grid(row=1, column=5, sticky=W)
        self.enterMessage.pack()
        self.message = Entry(root, textvariable=self.mess).pack()
        self.enc_but = Button(root, text="Encrypt", command=self.lets_encrypt)
        self.enc_but.pack()
        self.output = Text(root, width=50, height=7, wrap=WORD)
        self.output.grid(row=3, column=0, columnspan=2, sticky=W)
        self.output.pack()

# Asymmetric encryption
    def lets_encrypt(self):
        self.public_key = self.key.publickey()
        phrase = self.mess.get()
        self.new_phrase = phrase.encode('ascii')
        self.enc_data = self.public_key.encrypt(self.new_phrase, 32)
        self.output.insert(0.0, self.enc_data)
        self.signage = Button(root, text="Sign Message", command=self.sign).pack()

# Asymmetric decryption
    def decrypt(self):
        self.dec_data = self.key.decrypt(self.enc_data)
        self.output1 = Text(root, width=50, height=7, wrap=WORD)
        self.output1.grid(row=3, column=0, columnspan=2, sticky=W)
        self.output1.pack()
        self.output1.insert(0.0, self.dec_data)
        self.verific = Button(root, text="Verify", command=self.verify).pack()

# Asymmetric signing
    def sign(self):
        self.hash = SHA256.new(self.new_phrase).digest()
        self.signature = self.key.sign(self.hash, '')
        self.signed = tkMessageBox.showinfo("Signed Message with Hash", self.signature)
        self.dec_but = Button(root, text="Decrypt Message", command=self.decrypt).pack()

# Asymmetric Verification
    def verify(self):
        self.isVerified = self.public_key.verify(self.hash, self.signature)
        if self.isVerified == True:
            self.tlabel = Label(root, text="Message has been verified!").pack()
        else:
            self.tlabel1 = Label(root, text="Message has not been verified!").pack()

# Symmetric Class
class Symmetric:

# initializer for Symmetric class
    def __init__(self):
        self.frame = Frame(root)
        self.frame.pack()
        text_s = StringVar()
        self.label1 = Label(root, text="Symmetric Encryption")
        self.label1.grid(row=0, column=0)
        self.label1.pack()
        self.label2 = Label(root, text="Enter Message to Encrypt:")
        self.label2.grid(row=1, column=0)
        self.label2.pack()
        self.display = Entry(root, textvariable=text_s)
        self.display.grid(row=1, column=1)
        self.display.pack()
        self.text = text_s
        self.key = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa25\x05(\xd5\x18'
        self.enc_mess = Button(root, text="Encrypt", command=self.encrypt)
        self.enc_mess.pack()

# Symmetric Encryption
    def encrypt(self):
        plain_text = self.text.get()
        self.label = Label(root, text="Encrypting using the Key:").pack()
        self.mykeyt = Text(root, width=25, height=1, wrap=WORD)
        self.mykeyt.grid(row=3, column=0, columnspan=2, sticky=W)
        self.mykeyt.pack()
        self.mykeyt.insert(0.0, self.key)
        self.cipher = AES.new(self.key)
        self.ciphertext = self.cipher.encrypt(pad(plain_text))
        self.label1 = Label(root, text="Encrypted Message:").pack()
        self.ciphert = Text(root, width=50, height=5, wrap=WORD)
        self.ciphert.grid(row=3, column=0, columnspan=2, sticky=W)
        self.ciphert.pack()
        self.ciphert.insert(0.0, self.ciphertext)
        self.dec_but = Button(root, text="Decrypt Message", command=self.decrypt).pack()

# Symmetic decryption
    def decrypt(self):
        self.label = Label(root, text="Decrypting using the Key:").pack()
        self.mykeyt = Text(root, width=25, height=1, wrap=WORD)
        self.mykeyt.grid(row=3, column=0, columnspan=2, sticky=W)
        self.mykeyt.pack()
        self.mykeyt.insert(0.0, self.key)
        self.mess = self.cipher.decrypt(self.ciphertext).decode('utf-8')
        l = self.mess.count('{')
        newmess = self.mess[:len(self.mess)-l]
        self.labelnew = Label(root, text="Decrypted Message:").pack()
        self.tbox = Text(root, width=50, height=5, wrap=WORD)
        self.tbox.grid(row=3, column=0, columnspan=2, sticky=W)
        self.tbox.pack()
        self.tbox.insert(0.0, newmess)

# needed for AES to pad blocks in 16 lengths
def pad(s):
    return s + ((16-len(s) % 16) * '{')

# add Asymmetric object on menu option click
def add_asymm():
    asymm = Asymmetric()

# add Symmetric object on menu option click
def add_symm():
    symm = Symmetric()

# main loop
root = Tk()
text = StringVar()

# create drop down menu
menu = Menu(root)
root.config(menu=menu)
subMenu = Menu(menu)
menu.add_cascade(label="Algorithm", menu=subMenu)
subMenu.add_command(label="Symmetric", command=add_symm)
subMenu.add_command(label="Asymmetric", command=add_asymm)

# heading and window size
root.title("CS563 Project - Fall 2017 - Matthew Stevenson")
root.minsize(width=500, height=500)
root.maxsize(width=500, height=500)
root.configure(background='grey')

# loop the mainloop
root.mainloop()

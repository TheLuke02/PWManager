import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
import tkinter.font as font


class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.__master = master
        self.__master.geometry("400x300")
        self.__master.title("Password manager")
        self.__myFont = font.Font(family='Helvetica', size=17, weight='bold')
        self.__master.protocol("WM_DELETE_WINDOW", self.handler)
        self.pack()
        self.create_start()

    def handler(self):
        print("Non puoi chiudere la finestra")

    def create_start(self, fernet=None, Name=None):
        for self.__widget in self.__master.winfo_children():
            self.__widget.destroy()

        self.__fernet = fernet
        self.__Name = Name

        if self.__fernet != None:
            with open("account/" + str(self.__Name) + ".txt", "rb") as f:
                self.__data = f.read()

            self.__encrypted = self.__fernet.encrypt(self.__data)
            with open("account/" + self.__Name + ".txt", "wb") as f:
                f.write(self.__encrypted)

        self.__TextHome = tk.Label(self.__master, text="LOGIN")
        self.__TextHome.pack()
        self.__TextHome["font"] = self.__myFont

        self.__Space1 = tk.Label(self.__master, text="\n")
        self.__Space1.pack()

        self.__TextName = tk.Label(self.__master, text="Inserisci il Nome")
        self.__TextName.pack()
        self.__NameField = tk.Entry(self.__master)
        self.__NameField.pack()

        self.__TextPW = tk.Label(self.__master, text="Inserisci la Password")
        self.__TextPW.pack()
        self.__PWField = tk.Entry(self.__master, show="*")
        self.__PWField.pack()

        self.__Space3 = tk.Label(self.__master, text="     ")
        self.__Space3.pack(side="right")
        self.__Space4 = tk.Label(self.__master, text="                        ")
        self.__Space4.pack(side="left")

        self.__NewUser = tk.Button(self.__master, text="Nuovo utente", command=self.newuserpage)
        self.__NewUser.pack(side="right")
        self.__NewUser["font"] = font.Font(size=12, weight='bold')

        self.__Login = tk.Button(self.__master, text="Accedi", command=lambda: self.login(self.__NameField.get(), self.__PWField.get()))
        self.__Login.pack(side="left")
        self.__Login["font"] = font.Font(size=12, weight='bold')

        self.__Space5 = tk.Label(self.__master, text="\n")
        self.__Space5.pack(side="bottom")

        self.__Quit = tk.Button(self.__master, text="Chiudi", command=lambda: self.__master.destroy())
        self.__Quit.pack(side="bottom")
        self.__Quit["font"] = font.Font(size=12, weight='bold')

    def newuserpage(self):
        for self.__widget in self.__master.winfo_children():
            self.__widget.destroy()

        self.__TextHome = tk.Label(self.__master, text="Nuovo utente")
        self.__TextHome.pack()
        self.__TextHome["font"] = self.__myFont

        self.__Space1 = tk.Label(self.__master, text="\n")
        self.__Space1.pack()

        self.__TextName = tk.Label(self.__master, text="Inserisci il Nome")
        self.__TextName.pack()
        self.__NameFieldNU = tk.Entry(self.__master)
        self.__NameFieldNU.pack()

        self.__TextPW = tk.Label(self.__master, text="Inserisci la Password")
        self.__TextPW.pack()
        self.__PWFieldNU = tk.Entry(self.__master, show="*")
        self.__PWFieldNU.pack()

        self.__Space2 = tk.Label(self.__master, text="                             ")
        self.__Space2.pack(side="left")
        self.__Space3 = tk.Label(self.__master, text="                              ")
        self.__Space3.pack(side="right")

        self.__SubmitNU = tk.Button(self.__master, text="Crea", command=lambda: self.createnewuser(self.__NameFieldNU.get(), self.__PWFieldNU.get()))
        self.__SubmitNU.pack(side="right")
        self.__SubmitNU["font"] = font.Font(size=12, weight='bold')

        self.__BackToHome = tk.Button(self.__master, text="Indietro", command=self.create_start)
        self.__BackToHome.pack(side="left")
        self.__BackToHome["font"] = font.Font(size=12, weight='bold')

    def createnewuser(self, Name, PW):
        self.__password_provided = str(PW)  # This is input in the form of a string
        self.__password = self.__password_provided.encode()  # Convert to type bytes
        self.__salt = b"salt_"  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        self.__kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.__salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(self.__kdf.derive(self.__password))  # Can only use kdf once

        self.__fernet = Fernet(key)
        self.__password += bytes(", ", "utf-8")
        self.__encrypted = self.__fernet.encrypt(self.__password)
        with open("account/" + Name + ".txt", "wb") as f:
            f.write(self.__encrypted)
        self.create_start()

    def login(self, Name, PW):
        self.__Name = Name
        self.__PW = PW

        with open("account/" + Name + ".txt", "rb") as f:
            self.__data = f.read()

        self.__password_provided = str(PW)  # This is input in the form of a string
        self.__password = self.__password_provided.encode()  # Convert to type bytes
        self.__salt = b"salt_"  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        self.__kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.__salt,
            iterations=100000,
            backend=default_backend()
        )

        self.__key = base64.urlsafe_b64encode(self.__kdf.derive(self.__password))  # Can only use kdf once
        self.__fernet = Fernet(self.__key)
        try:
            self.__decrypted = self.__fernet.decrypt(self.__data)
            with open("account/" + self.__Name + ".txt", "wb") as f:
                f.write(self.__decrypted)
            print("Valid Key - Successfully decrypted")

            self.successfull_login(self.__fernet, self.__Name)
        except InvalidToken:
            print("Invalid Key - Unsuccessfully decrypted")

    def successfull_login(self, fernet, UserName):
        for self.__widget in self.__master.winfo_children():
            self.__widget.destroy()

        self.__UserName = UserName
        self.__fernet = fernet

        self.__Space1 = tk.Label(self.__master, text="\n\n")
        self.__Space1.pack()

        self.__TextHome = tk.Label(self.__master, text="Profilo utente")
        self.__TextHome.pack()
        self.__TextHome["font"] = self.__myFont

        self.__Space1 = tk.Label(self.__master, text="                           ")
        self.__Space1.pack(side="left")

        self.__GoBack = tk.Button(self.__master, text="Indietro", command=lambda: self.create_start(self.__fernet, UserName))
        self.__GoBack.pack(side="left")
        self.__GoBack["font"] = font.Font(size=12, weight='bold')

        self.__Space2 = tk.Label(self.__master, text="                           ")
        self.__Space2.pack(side="right")

        self.__Search = tk.Button(self.__master, text="Cerca", command=lambda: self.searchpage(self.__fernet, self.__UserName))
        self.__Search.pack(side="right")
        self.__Search["font"] = font.Font(size=12, weight='bold')

        self.__Space3 = tk.Label(self.__master, text="\n\n\n\n\n")
        self.__Space3.pack()

        self.__Add = tk.Button(self.__master, text="Aggiungi", command=lambda: self.addpage(self.__fernet, self.__UserName))
        self.__Add.pack(side="left")
        self.__Add["font"] = font.Font(size=12, weight='bold')

    def addpage(self, fernet, UserName):
        for self.__widget in self.__master.winfo_children():
            self.__widget.destroy()

        self.__UserName = UserName
        self.__fernet = fernet

        self.__TextHome = tk.Label(self.__master, text="Aggiungi una password")
        self.__TextHome.pack()
        self.__TextHome["font"] = self.__myFont

        self.__Space1 = tk.Label(self.__master, text="\n")
        self.__Space1.pack()

        self.__TextName = tk.Label(self.__master, text="Inserisci il Nome del sito o gioco")
        self.__TextName.pack()
        self.__NameField = tk.Entry(self.__master)
        self.__NameField.pack()

        self.__TextPW = tk.Label(self.__master, text="Inserisci la Password")
        self.__TextPW.pack()
        self.__PWField = tk.Entry(self.__master, show="*")
        self.__PWField.pack()

        self.__Space2 = tk.Label(self.__master, text="                             ")
        self.__Space2.pack(side="left")
        self.__Space3 = tk.Label(self.__master, text="                              ")
        self.__Space3.pack(side="right")

        self.__BackToHome = tk.Button(self.__master, text="Indietro", command=lambda: self.successfull_login(self.__fernet, self.__UserName))
        self.__BackToHome.pack(side="left")
        self.__BackToHome["font"] = font.Font(size=12, weight='bold')

        self.__AddPW = tk.Button(self.__master, text="Aggiungi", command=lambda: self.add(self.__fernet, self.__NameField.get(), self.__PWField.get(), self.__UserName))
        self.__AddPW.pack(side="right")
        self.__AddPW["font"] = font.Font(size=12, weight='bold')

    def add(self, fernet, Name, PW, UserName):
        self.__fernet = fernet
        self.__Name = Name
        self.__PW = PW
        self.__UserName = UserName

        with open("account/" + self.__UserName + ".txt", "rb") as f:
            self.__data = f.read()

        self.__data += bytes(self.__Name + ", " + self.__PW + ", ", "utf-8")
        with open("account/" + self.__UserName + ".txt", "wb") as f:
            f.write(self.__data)
        self.successfull_login(self.__fernet, self.__UserName)

    def searchpage(self, fernet, UserName):
        for self.__widget in self.__master.winfo_children():
            self.__widget.destroy()

        self.__UserName = UserName
        self.__fernet = fernet

        self.__TextHome = tk.Label(self.__master, text="Aggiungi una password")
        self.__TextHome.pack()
        self.__TextHome["font"] = self.__myFont

        self.__Space1 = tk.Label(self.__master, text="\n")
        self.__Space1.pack()

        self.__TextName = tk.Label(self.__master, text="Inserisci gioco o password da cercare")
        self.__TextName.pack()
        self.__NameField = tk.Entry(self.__master)
        self.__NameField.pack()

        self.__Space2 = tk.Label(self.__master, text="                     ")
        self.__Space2.pack(side="left")
        self.__Space3 = tk.Label(self.__master, text="                       ")
        self.__Space3.pack(side="right")

        self.__BackToHome = tk.Button(self.__master, text="Indietro", command=lambda: self.successfull_login(self.__fernet, self.__UserName))
        self.__BackToHome.pack(side="left")
        self.__BackToHome["font"] = font.Font(size=12, weight='bold')

        self.__GoSearch = tk.Button(self.__master, text="Cerca", command=lambda: self.search(self.__fernet, self.__NameField.get(), self.__UserName))
        self.__GoSearch.pack(side="right")
        self.__GoSearch["font"] = font.Font(size=12, weight='bold')

    def search(self, fernet, Name, UserName):
        self.__Name = Name
        self.__UserName = UserName
        self.__fernet = fernet

        with open("account/" + self.__UserName + ".txt", "rb") as f:
            self.__file = f.read()

        self.__file = self.__file.decode("utf-8")
        self.__file = list(self.__file.split(', '))

        for i in range(len(self.__file) - 1):
            if self.__file[i] == self.__Name and i != 0:
                self.__TextPW.pack_forget()
                if i % 2 != 0:
                    self.__TextPW = tk.Label(self.__master, text="La password è:\n" + str(self.__file[i + 1]))
                    self.__TextPW.pack()
                else:
                    self.__TextPW = tk.Label(self.__master, text="Il gioco o sito è:\n" + str(self.__file[i - 1]))
                    self.__TextPW.pack()
                self.__TextPW["font"] = font.Font(size=10, weight='bold')

root = tk.Tk()
app = Application(master=root)
app.mainloop()

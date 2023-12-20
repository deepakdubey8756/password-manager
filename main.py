import json
import random
import string
import os
from cryptography import Fernet

LOW = 8
HIGH = 15
CHARACTERS = string.ascii_letters + string.digits + "!@#$%^&*()_+~//*"



class PasswordManager:
    def __init__(self):
        
        self.accounts = {}
        self.salt = None
        self.key = None

    #utilities
    def encrypt(self, text:str):
        """
            Encrypt any text with stored key
            Return : Bytes or None
        """
        cipher_suite = Fernet(self.key)
        return cipher_suite.encrypt(text.encode()).decode()

    def decrypt(self, encrypted_text:str):
        """
            Decrypt encrypted_text with stored key.
            Note: Decryption depends upon stored key.
            return: None or bytes.
        """
        cipher_suite = Fernet(self.key)
        return cipher_suite.decrypt(encrypted_text.encode()).decode()
    
    def update_salt(self):
        self.salt = os.urandom(16)

    
    

    #Credentials and files related functionalities

    def derive_key(self, password):
        "Derive key based on given salt value and entered password"
        try:
            kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
            )
            self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
        except Exception as e:
            print("Error! ", e)
        
    def get_master_password(self):
        """Get password from user of generate new"""
        master_password = input("Enter password (leave blank to generate new): ")
        is_generated = False
        if master_password == " " or master_password = "":
            print("""
            Note: Changing or adding new password will remove all store credentials.
        """)
            confirm = input("Enter yes(y/Y) or no(n/N) to confirm: ")
            if confirm.lower() == "yes" or confirm.lower() == "y":
                master_password = PasswordManager.generate_random_pass()
                is_generated = True
            else:
                self.get_master_password()
        return master_password, is_generated
        

    def set_accounts(self, encrypted_account):
        try:
            encrypted_account = 
        except Exception as e:
            pass

    def set_keys(self):
        """ Get salt and password, derive key based on it.
            Set key, then check if password is correct. If password is correct. """
        encrypted_account = None
        if self.salt == None:
            encrypted_account = self.fetch_accounts()

        master_password, is_generated = self.get_master_password()
        self.key = self.derive_key(master_password)

        if encrypted_account not None:
            if is_generated

        



    
    def add_account(self):
        """
            First take account name and check if it already exits.
            If it exists then return.
            Else, take password or generate it.
            encrypt password and store it. then return

            Note: account will store in str. So we have to encode/decode it while using
        """
        # return if account with same key is already present
        account = input("account name: ")
        
        encrypted_account = self.encrypt(account)
        if encrypted_account in self.accounts:
            print("Account already availble. Delete it first")
            return

        password = input("password (blank to auto generate): ")
        if password == " " or password == "":
            password = PasswordManager.gen_pass()
        
        encrypted_password = self.encrypt(password)
        self.accounts[encrypted_account] = encrypted_password
        print("Password added successfully")

    def delete_account(self):
        """
            Get account name, check key and delete account
        """
        account = input("account: ")
        encrypted_account = self.encrypt(account)
        
        if encrypted_account in self.accounts:
            del self.accounts[encrypted_account]
        else:
            print("Account not found!")

    def get_password(self):
        """
            print req password else print account not availble
        """
        account = input("account name: ")
        # account is first encrypted and then used as index to store password.
        encrypted_account = self.encrypt(account)
        if encrypted_account not in self.accounts:
            print("Account Not Found!")
        else:
            #decrepting encrypted password before printing
            print(self.decrypt(self.accounts[encrypted_account]))

    def fetch_accounts(self):
        """load encrypted account, set salt and return encrypted_account as bytes.
        Else: set new salt value and set new password file and return None"""
        try:
            encrypted_file = None
            with open("passwords.txt", "rb") as f:
                encrypted_file = f.read()
            
            #salt is stored as bytes
            self.salt = encrypted_file[:16]
            # encrypted accounts is in bytes
            return encrypted_file[16:]

        except Exception as E:
            self.update_salt()
            print("Error! Unable to find passwords.txt.\nCreating new file.")
            with open("passwords.txt", 'w') as f:
                f.write()


    def available_accounts(self):
        print("\nCurrent Accounts: ")
        index = 0
        for encrypted_account in  self.accounts.keys():
            try:
                account = self.decrypt(encrypted_account)
                print(index, ". ", account)
                index += 1
            except Exception:
                pass
        
        if index == 0:
            print("None")
        

    @staticmethod
    def features():
        print("\nWhat to do : ")
        print("""
        1. add new account
        2. delete an account
        3. change ( or add new) key
        4. Get password
        0. exit
        """)
        choice = input(">>>")
        return choice
    
    def update_accounts(self):
        with open("passwords.json", 'w') as f:
            json.dump(self.accounts, f)



if __name__ == "__main__":
    manager = PasswordManager()
    while True:
        # check if user is logged in
        if manager.key == None:
            manager.set_keys()
            continue

        manager.available_accounts()

        choice = manager.features()
        os.system("clear")
        if choice == "0":
            break
        elif choice == "1":
            manager.add_account()
        elif choice == "2":
            manager.delete_account()
        elif choice == "3":
            manager.change_key()
        elif choice == "4":
            manager.get_password()
        else:
            print("Enter valid choice")
        manager.update_accounts()
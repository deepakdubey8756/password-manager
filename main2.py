import json
import random
import string
import os
from cryptography import Fernet

# Passswords will work only when we have some data stored.

class PasswordManager:

    def __init__(self):
        # store saved accounts and it's credentials
        self.accounts = {}
        # data type: bytes
        self.key = None
        # data type: bytes
        self.salt = None

    def encrypt(self, text:str, key=None):
        if key == None:
            key = self.key
        
        cipher_suite = Fernet(key)
        # return data type: string
        return cipher_suite.encrypt(text.encode()).decode()
    
    def decrypt(self, encrypted_text:str, key = None):
        if key== None:
            key = self.key

        cipher_suite = Fernet(key)
        # return data type: str
        return cipher_suite.decrypt(encrypted_text.encode()).decode()

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

    @staticmethod
    def generate_random_pass():
        """
            Returned password string will be of arbitrary length 
            containing punctuations + alpha numeric character.
        """
        # password will be of arbitrary length
        pass_length = random.randint(LOW, HIGH)
        random_pass = "".join(random.choice(CHARACTERS) for i in range(pass_length))
        return random_pass
    
    @staticmethod
    def password_strenght(password):
        """ check password strength """
        pass

    def signup(self, message = None):
        """set key based on master password"""

        # print message
        if message not None:
            print(message)

        # set password
        master_password = input("Password (or leave blank to auto-generate): ")

        if master_password == " " or master_password = "":
            master_password = PasswordManager.generate_random_pass()
            print("your password is: ", master_password)
        else:
            # checks for entered password
            confirm_master_password = input("Confirm password: ")
            if confirm_master != master_password:
                return self.signup(message = "Error! passwords are not matching")
            if not PasswordManager.password_strenght(master_password):
                return self.signup(message = "Weak password. Enter at least 8 digit of alpha numeric password")

        # generate key
        self.key = self.derive_key(master_password)
        print("password set successfully")


    def verify_password(self, master_password, encrypted_accounts:str):
        """ verify password by generating correct key. 
        return key and accounts as string """
        
        # generate key with given password
        key = self.derive_key(master_password)
        try:
            # check if the key is correct
            account = self.decrypt(encrypted_accounts)
            # return decrypted account with key
            return account, key

        except Exception as E:
            return None, None

    def login(self, message = None, encrypted_accounts:str):
        """take password, verify it and login user. Else re-login"""
        # print message 
        if message not None:
            print(message)
        
        # get password
        master_password = input("Enter password: ")
        # verify password and return correct key and account details
        accounts, self.key = self.verify_password(encrypted_accounts)

        if self.key == None:
            return self.login("Wrong password")
        else:
            print("Login successful")
        return accounts


    def set_keys_accounts(self):
        """it will setup necessary credentials and load saved and ecrypted data from file"""
        #load saved accounts and salt
        encrypted_accounts = self.fetch_accounts().decode()
        accounts = '{}'

        # setup key and decrypted account
        if encrypted_accounts == None:
            self.signup()
        else:
            accounts = self.login(encrypted_accounts)
        
        # parsing through json will convert it into dict from string
        self.accounts = json.loads(accounts)

if __name__ == "__main__":
    manager = PasswordManager()

    while True:
        if manager.key == None:
            manager.set_keys_accounts()
            continue
        print("Account creation is successful")

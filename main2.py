import re
import json
import random
import string
import os
from cryptography.fernet import Fernet

LOW = 8
HIGH = 15
CHARACTERS = string.ascii_letters + string.digits + "@#$%^&*"

class PasswordManager:

    def __init__(self):
        # store saved accounts and it's credentials
        self.accounts = {}
        # data type: bytes
        self.key = None
        # data type: bytes
        self.salt = None

    def encrypt(self, text:str, key:bytes=None)->str:
        if key == None:
            key = self.key
        
        cipher_suite = Fernet(key)
        # return data type: string
        return cipher_suite.encrypt(text.encode()).decode()
    
    def decrypt(self, encrypted_text:str, key:bytes = None)->str:
        if key== None:
            key = self.key

        cipher_suite = Fernet(key)
        # return data type: str
        return cipher_suite.decrypt(encrypted_text.encode()).decode()

    def derive_key(self, password:str):
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
    def generate_random_pass()->str:
        """
            Returned password string will be of arbitrary length 
            containing symbols + alpha numeric character.
        """
        # password will be of arbitrary length
        pass_length = random.randint(LOW, HIGH)
        random_pass = "".join(random.choice(CHARACTERS) for i in range(pass_length))
        return random_pass
    
    @staticmethod
    def password_strength(password:str)->bool:
        """ check password strength """

        has_digit = bool(re.search(r'\d', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_symbol = bool(re.search(r'[@#$%^&*]', password))
        
        return len(password) > 7 and has_digit and has_uppercase and has_lowercase and has_symbol
         

    def signup(self, message:str = None):
        """signup user and set key based on given password"""

        # print message
        if message:
            print(message)

        # passwords validity credentials
        password_validity = """Password should be at least of:
                            8 characters.
                            1 number.
                            1 uppercase
                            1 lowercase
                            1 symbol(@#$%^&*())"""
        print(password_validity)
        # set password
        master_password = input("Password (or leave blank to auto-generate): ")

        if master_password == " " or master_password == "":
            # a randome password with arbitrary length
            master_password = PasswordManager.generate_random_pass()
            print("your password is(please store it somewhere ): ", master_password)

        else:
            # checks for entered password
            confirm_master_password = input("Confirm password: ")
            if confirm_master != master_password:
                return self.signup(message = "Error! passwords are not matching")
            if not PasswordManager.password_strenght(master_password):
                password_checks = "Password should be of 8 digit "
                return self.signup(message = "Weak password. Enter again")

        # generate key
        self.key = self.derive_key(master_password)
        print("password set successfully")


    def verify_password(self, master_password:str, encrypted_accounts:str):
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

    def login(self, encrypted_accounts:str, message:str=None):
        """take password, verify it and login user. Else re-login"""
        # print message 
        if message:
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

    def update_salt(self)->bytes:
        self.salt = os.urandom(16)
        return self.salt

    def fetch_accounts(self)->str:
        """load encrypted account, set salt and return encrypted_account as string.
        Else: set new salt value and set new password file and return None"""
        try:
            encrypted_file = None
            with open("passwords.txt", "rb") as f:
                encrypted_file = f.read()
            
            #salt is stored as bytes
            self.salt = encrypted_file[:16]
            # encrypted accounts is in string
            return encrypted_file[16:].decode()

        except Exception as E:
            self.update_salt()
            print("Cann't find any stored password. Setting new account.")
            with open("passwords.txt", 'w') as f:
                f.write()

    def set_keys_accounts(self):
        """it will setup necessary credentials and load saved and ecrypted data from file"""
        #load saved accounts and salt
        encrypted_accounts = self.fetch_accounts()
        accounts = '{}'

        # setup key and decrypted account
        if encrypted_accounts == None:
            self.signup()
        else:
            accounts = self.login(encrypted_accounts)
        
        # parsing through json will convert it into dict from string
        self.accounts = json.loads(accounts)

if __name__ == "__main__":
#Note: passwords will only work when we have any data stored.
    manager = PasswordManager()

    while True:
        # Don't go further if user is not login.
        if manager.key == None:
            manager.set_keys_accounts()
            continue
        print("Account creation is successful")

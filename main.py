"""
Working:
It will store account and it's password in json file. 
Password will be encrypted with a parent key and account name.
When displaying password, it will first decrypt it and then display it.
"""

import json
import random
import string
from cryptography.fernet import Fernet

LOW = 10
HIGH = 25
CHARACTERS = string.ascii_letters + string.digits + "!@#$%^&*()_+~//*"

class PasswordManager:
    def __init__(self):
        # to store all of accounts from file
        self.accounts = {}
        # key will be used to encrypt and decrypt accounts and passwords.
        self.key = None

        
    def encrypt(self, text):
        """
            Encrypt any text with stored key
        """
        cipher_suite = Fernet(self.key)
        encrypted_text = cipher_suite.encrypt(text.encode())
        return encrypted_text

    def decrypt(self, encrypted_text):
        """
            Decrypt encrypted_text with stored key.
            Note: Decryption depends upon stored key.
        """
        cipher_suite = Fernet(self.key)
        decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
        return decrypted_text

    def gen_pass(self):
        """
            Returned password string will be of arbitrary length 
            containing punctuations + alpha numeric character.
        """
        # password will be of arbitrary length
        pass_length = random.randint(LOW, HIGH)
        random_pass = "".join(random.choice(CHARACTERS) for i in range(pass_length))
        return random_pass

    def store_custom(self, account, password):
        """
            store password given by user.
        """
        # Encrypt account
        encrypted_account = self.encrypt(account)
        # Encrypt password with key
        encrypted_pass = self.encrypt(password)
        # Checking for encrypted account instead of normal account
        if encrypted_account not in self.accounts:
            self.accounts[encrypted_account] = encrypted_pass

        # finally update json file
        self.updateAccounts()
        print("Password stored successfully")

    def store_auto(self, account):
        """
            Store auto generate password signed by key.
        """
        # Encrypt Account
        encrypted_account = self.encrypt(account)
        if encrypted_account in self.account:
            print("There is already a password for this account. \n try changing it if you want new.")
            return
        # generate random string of random length
        random_pass = self.gen_pass()
        # encrypt generated random password
        encrypted_random_pass = self.encrypt(random_pass)
        # store it
        self.accounts[encrypted_account] = encrypted_pass
        print("Password added successfully")
    
    def retrieve(self, account):
        """
            return decrypted password if key is correct and account exists
            else return None
        """
        # account is first encrypted and then used as index to store password.
        encrypted_account = self.encrypt(account)
        if encrypted_account not in self.accounts:
            return None
        #decrepting encrypted password and returning
        return self.decrypt(self.accounts[encrypted_account])

    def update_key(self):
        """ this will update encryption key"""
        key = input("Enter key (or press enter to generate new ): ")
        if key == "" or key == " ":
            key = Fernet.generate_key()
            print("\nNew key: (keep it safe) :", key.decode())
        
        else:
            key = key.encode()

        try:
            key = Fernet(key)
            self.key = key
            return True
        except Exception:
            print("\nError! Wrong key")
        return False

    def available_accounts(self):
        print("\nCurrent Accounts: ")

    def features(self):
        print("\nWhat to do : ")
        print("""
        1. add new account
        2. delete an account
        3. change ( or add new) key
        0. exit
        """)
        choice = input(">>>")
        return choice
    
    def update_accounts(self):
        pass

if __name__ == "__main__":
    manager = PasswordManager()
    while True:
        # check if user is logged in
        if manager.key == None:
            manager.update_key()
            continue

        # It will display only those accounts that are signed by given key
        print(manager.available_accounts())

        choice = manager.features()

        if choice == "0":
            break
        elif choice == "1":
            manager.add_account()
        elif choice == "2":
            manager.delete_account()
        elif choice == "3":
            print("""
            Note: Changing key will not affect your old accounts.
                  You can still access them with your old key.
                  To remove them, login with old key.
            """)
            success = False
            while not success:
                success = manager.update_key()
            print("Successfully added new key")
        else:
            print("Enter valid choice")
        manager.update_accounts()
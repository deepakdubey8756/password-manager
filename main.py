"""
Working:
It will store account and it's password in json file. 
Password will be encrypted with a parent key and account name.
When displaying password, it will first decrypt it and then display it.
"""

import json
import random
import string
import os

LOW = 8
HIGH = 15
CHARACTERS = string.ascii_letters + string.digits + "!@#$%^&*()_+~//*"

class PasswordManager:
    def __init__(self):
        
        # fetch accounts from file and store it
        self.accounts = {}
        def fetch_passwords():
            try:
                with open("passwords.json", "r") as f:
                    # key and value will in str. We have to change encode / decode while using it.
                    self.accounts = json.load(f)
            except Exception as e:
                print("Error! Unable to find passwords.json.\nCreating new file.")
                with open("passwords.json", 'w') as f:
                    json.dump({}, f)
        fetch_passwords()
        # key will be used to encrypt and decrypt accounts and passwords.
        self.key = None

    

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
        

    @staticmethod
    def gen_pass():
        """
            Returned password string will be of arbitrary length 
            containing punctuations + alpha numeric character.
        """
        # password will be of arbitrary length
        pass_length = random.randint(LOW, HIGH)
        random_pass = "".join(random.choice(CHARACTERS) for i in range(pass_length))
        return random_pass
    
    
    def add_account(self):
        """
            First take account name and check if it already exits.
            If it exists then return.
            Else,take password or generate it.
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

    def update_key(self):
        """ this will update encryption key"""
        key = input("Key (press enter to generate new ): ")
        if key == "" or key == " ":
            # key will be encoded
            key = Fernet.generate_key()
            print("\nNew key: (keep it safe) :", key.decode())
        
        else:
            # encode the user entered key.
            key = key.encode()

        try:
            # check if current key is valid
            check_key = Fernet(key)
            #set key
            self.key = key
            return True
        except Exception:
            print("\nError! Wrong key")
        return False

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

    def change_key(self):
        print("""
        Note: Changing key will not affect your old accounts.
        You can still access them with your old key.
        To remove them, login with old key.
        """)
        success = False
        while not success:
            success = manager.update_key()
        print("Successfully added new key")



if __name__ == "__main__":
    manager = PasswordManager()
    while True:
        # check if user is logged in
        if manager.key == None:
            manager.update_key()
            continue

        print("Current key: ", manager.key)
        # It will display only those accounts that are signed by given key
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
from pickle import loads
import pickle
import os
import random
import hashlib
__author__ = "Ben"
current_path = os.getcwd()
new_path = os.path.join(current_path, "database")
pepper_path = os.path.join(current_path,"pepper")
#hash with: pepper+password+salt
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

class sqlpy():
    def __init__(self):
        if os.path.getsize(new_path) == 0:
            empty = True
        else:
            empty = False
        with open(new_path, 'rb') as f:
            if not empty:
                # key in users is user.
                # value in users is [password,gmail,salt,restpassword]
                self.users = loads(f.read())
            else:
                self.users = {}
        with open(pepper_path,"r") as f:
            self.pepper = f.read()
        self.not_avilable = []
    def gen_selt(self):
        return ''.join(random.choice(ALPHABET) for i in range(16))

    def GetUserEmail(self,user):
        return self.users[user][1]
    def IsuserExixst(self,user,pw):
        if user in list(self.users.keys()):
            if hashlib.sha256((self.pepper + pw + self.users[user][2]).encode()).hexdigest() == self.users[user][0]:
                return True
            else:
                return False
        else:
            return False
    def Saveuser(self,user,password,email):
        to_save_key = user
        salt = self.gen_selt()
        to_save_value = [(hashlib.sha256((self.pepper + password + salt).encode())).hexdigest(),email,salt,None]
        with open(new_path, "rb") as f:
            try:
                data = pickle.load(f)
            except EOFError:
                data = {}  # If file is empty
        data[to_save_key] = to_save_value
        with open(new_path, "wb") as f:
            pickle.dump(data, f)
        with open(new_path, "rb") as f:
            self.users = pickle.load(f)
    def usernotavilable(self,user):
        return user in self.not_avilable
    def setnotavilable(self,user):
        self.not_avilable.append(user)
    def SetEmailPassword(self,user,password):
        if user in self.users.keys():
            self.users[user][3] = password
    def GetEmailPassword(self,user):
        if user in self.users.keys():
            return self.users[user][3]
    def DeleteEmailPassword(self,user):
        if user in self.users.keys():
            self.users[user][3] = None

    def ResetUserPassword(self, user, new_password):
        if user in self.users:
            salt = self.gen_selt()
            self.users[user][0] = hashlib.sha256((self.pepper + new_password + salt).encode()).hexdigest()
            self.users[user][2] = salt
            with open(new_path, "wb") as f:
                pickle.dump(self.users, f)
    def IsuserExixst_byname(self,user):
        return user in self.users
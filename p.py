import os
import hashlib
import pickle
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"  # SQL Injection risk
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

def run_system_command():
    command = input("Enter a command to run: ")  # User input directly used
    os.system(command)  # Potential command injection

def store_password(password):
    hashed_password = hashlib.md5(password.encode()).hexdigest()  # MD5 is insecure
    print(f"Stored password hash (insecure!): {hashed_password}")

def load_data(serialized_data):
    return pickle.loads(serialized_data)  # Untrusted data deserialization risk

username = input("Enter username: ")
print(get_user_data(username))

run_system_command()

password = input("Enter password: ")
store_password(password)

malicious_data = b"cos\nsystem\n(S'rm -rf /'\ntR."
print("Deserialized Data:", load_data(malicious_data))
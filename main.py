#https://github.com/Emran1873/Encryption-App

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64


salt = b'10d6994a31e35007c6874ba9b647a2d8'
kdf = PBKDF2HMAC(
	algorithm=hashes.SHA256(),
	length=32,
	salt=salt,
	iterations=100000,
	backend=default_backend()
)
password = "emransawft"
directory = "C:\\exa\\" #Replaced by file picker in Tkinter lib
files = [] #Files in a folder
include_subfolder = True #Encrypt the files in subfolder [True by default]

def encryptfile():
	key = kdf.derive(password.encode())
	fernet_key = base64.urlsafe_b64encode(key)
	cipher = Fernet(fernet_key)
	for root, dirs, files in os.walk(directory):
	    for file in files:
	        encFile = os.path.join(root, file)
	        splited = encFile.split('\\')
	        try:
	        	with open(encFile, 'rb') as file:
	        		data = file.read()
	        except:
	        	print("Problem with Opening file - ", encFile)

	        encrypted_data = cipher.encrypt(data)
	        print("Encrypting - ",splited[-1])
	        try:
	        	with open(encFile, 'wb') as file:
	        		file.write(encrypted_data)
	        except:
	        	print("Problem with Encrypting - ", encFile)


def decryptfile():
	key = kdf.derive(password.encode())
	fernet_key = base64.urlsafe_b64encode(key)
	cipher = Fernet(fernet_key)
	for root, dirs, files in os.walk(directory):
	    for file in files:
	        encFile = os.path.join(root, file)
	        splited = encFile.split('\\')
	        try:
	        	with open(encFile, 'rb') as file:
	        		data = file.read()
	        except:
	        	print("Problem with reading file - ", encFile)

	        decrypted_data = cipher.decrypt(data)
	        print("Decrypting - ",splited[-1])
	        try:
	        	with open(encFile, 'wb') as file:
	        		file.write(decrypted_data)
	        except:
	        	print("Problem With Decrypting - ", encFile)


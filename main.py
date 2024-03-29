from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


def encryptfile(filepath, password):
	salt = b'10d6994a31e35007c6874ba9b647a2d8'
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
       	length=32,
       	salt=salt,
       	iterations=100000,
       	backend=default_backend()
	)
	key = kdf.derive(password.encode())
	fernet_key = base64.urlsafe_b64encode(key)
	cipher = Fernet(fernet_key)
	with open(filepath, 'rb') as file:
		data = file.read()

	encrypted_data = cipher.encrypt(data)
	with open(filepath, 'wb') as file:
		file.write(encrypted_data)


def decryptfile(filepath, password):
	salt = b'10d6994a31e35007c6874ba9b647a2d8'
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
       	length=32,
       	salt=salt,
       	iterations=100000,
       	backend=default_backend()
	)
	key = kdf.derive(password.encode())
	fernet_key = base64.urlsafe_b64encode(key)
	cipher = Fernet(fernet_key)
	with open(filepath, 'rb') as file:
		data = file.read()

	decrypted_data = cipher.decrypt(data)
	with open(filepath, 'wb') as file:
		file.write(decrypted_data)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket, threading, hashlib

#initialize client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

#Generate RSA keys pair
client_key = RSA.generate(2048)

#receive server's public key
server_public_key = RSA.import_key(client_socket.recv(2048))

#send client's public key to server
client_socket.send(client_key.publickey().export_key(format='PEM'))

#receive encrypted AES key from server
encrypted_aes_key = client_socket.recv(2048)

#decrypt AES key with client's private key
cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

#function to encrypt message
def encrypt_message(key, message):
  cipher = AES.new(key, AES.MODE_CBC)
  ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
  return cipher.iv + ciphertext

#function to decrypt message
def decrypt_message(key, encrypted_message):
  iv = encrypted_message[:AES.block_size]
  ciphertext = encrypted_message[AES.block_size:]
  cipher = AES.new(key, AES.MODE_CBC, iv)
  decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
  return decrypted_message.decode()

#function to receive message from server
def receive_message():
  while True:
    try:
      encrypted_message = client_socket.recv(1024)
      if not encrypted_message:  # Connection closed by server
        break
      decrypted_message = decrypt_message(aes_key, encrypted_message)
      print(f"Received message: {decrypted_message}")
    except:
      break
  print("Disconnected from server")

#start the receive thread
receive_thread = threading.Thread(target=receive_message)
receive_thread.daemon = True  # Thread will exit when main program exits
receive_thread.start()

#send message from client
try:
  while True:
    message = input("Enter message (type 'exit' to quit): ")
    encrypted_data = encrypt_message(aes_key, message)
    client_socket.send(encrypted_data)
    
    if message == "exit":
      break
finally:
  #close the client socket
  client_socket.close()
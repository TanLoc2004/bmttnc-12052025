from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket, threading, hashlib

#initialize server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

#generate RSA keys pair
server_key = RSA.generate(2048)

#list of connected clients
clients = []

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

#function to handle client connection
def handle_client(client_socket, client_address):
  print(f"Connected with {client_address}")

  #send server's public key to client
  client_socket.send(server_key.publickey().export_key(format='PEM'))

  #receive client's public key
  client_recived_key = RSA.import_key(client_socket.recv(2048))

  #generate AES key for message encryption
  aes_key = get_random_bytes(16)

  #encrypt AES key with client's public key
  cipher_rsa = PKCS1_OAEP.new(client_recived_key)
  encrypted_aes_key = cipher_rsa.encrypt(aes_key)
  client_socket.send(encrypted_aes_key)

  #add client to the list
  clients.append((client_socket, aes_key))

  while True:
    encrypted_data = client_socket.recv(1024)
    decrypted_message = decrypt_message(aes_key, encrypted_data)
    print(f"Received message from {client_address}: {decrypted_message}")

    #send message to all clients
    for client, key in clients:
      if client != client_socket:
        encrypted = encrypt_message(key, decrypted_message)
        client.send(encrypted)

    if decrypted_message == "exit":
      break

  clients.remove((client_socket, aes_key))
  client_socket.close()
  print(f"Connection with {client_address} closed")

#Accept client connections
while True:
  client_socket, client_address = server_socket.accept()
  client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
  client_thread.start()
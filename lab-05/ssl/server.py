import socket
import ssl
import threading

# Thong tin server
server_address = ('localhost', 12345)

#danh sach client da ket noi
clients = []

def handle_client(client_socket):
  #them client vao danh sach
  clients.append(client_socket)

  print("Da ket noi voi: ", client_socket.getpeername())

  try:
    #Nhan va gui du lieu
    while True:
      data = client_socket.recv(1024)
      if not data:
        break
      print("Nhan du lieu: ", data.decode('utf-8'))

      #gui du lieu toi tat ca client khac
      for client in clients:
        if client != client_socket:
          try:
            client.send(data)
          except:
            clients.remove(client)
  except:
    clients.remove(client_socket)
  finally:
    print("Da ngat ket noi voi: ", client_socket.getpeername())
    clients.remove(client_socket)
    client_socket.close()

#Tao socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(server_address)
server_socket.listen(5)

print("Server dang cho ket noi...")

#Lang nghe cac ket noi
while True:
  client_socket, client_address = server_socket.accept()

  #Tao ssl context
  context = ssl.SSLContext(ssl.PROTOCOL_TLS)
  context.load_cert_chain(certfile="./certificates/server-cert.crt", keyfile="./certificates/server-key.key")

  #Thiet lap ket noi SSL
  ssl_socket = context.wrap_socket(client_socket, server_side=True)

  #Bat dau mot luong xu ly cho moi client
  client_thread = threading.Thread(target=handle_client, args=(ssl_socket,))
  client_thread.start()


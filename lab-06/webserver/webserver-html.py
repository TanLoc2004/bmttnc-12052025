import socket

def handle_request(client_socket, request_data):
    if "GET /admin" in request_data:
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        try:
            with open("admin.html", "r", encoding="utf-8") as file:
                response += file.read()
        except FileNotFoundError:
            response += "<h1>Admin page not found.</h1>"
    else:
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        try:
            with open("index.html", "r", encoding="utf-8") as file:
                response += file.read()
        except FileNotFoundError:
            response += "<h1>Index page not found.</h1>"

    client_socket.sendall(response.encode('utf-8'))
    client_socket.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 8080))
    server_socket.listen(5)
    print("Server listening on port 8080...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        request_data = client_socket.recv(1024).decode('utf-8', errors='ignore')
        handle_request(client_socket, request_data)

if __name__ == "__main__":
    main()

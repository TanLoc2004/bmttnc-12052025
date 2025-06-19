import socket


def handle_request(client_socket, request_data: str) -> None:
    """Trả về nội dung HTML đơn giản dựa trên đường dẫn yêu cầu."""
    if request_data.startswith("GET /admin"):
        body = "Welcome to the admin page!"
    else:
        body = "Hello, this is a simple web server!"

    response_lines = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body.encode('utf-8'))}",
        "",                     # Dòng trống ngăn cách header và body
        body
    ]
    response = "\r\n".join(response_lines)
    client_socket.sendall(response.encode("utf-8"))
    client_socket.close()


def main() -> None:
    host = "127.0.0.1"
    port = 8080

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Cho phép chạy lại nhanh mà không bị lỗi “Address already in use”
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on http://{host}:{port}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address}")
            request_data = client_socket.recv(1024).decode("utf-8", errors="ignore")
            handle_request(client_socket, request_data)
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()

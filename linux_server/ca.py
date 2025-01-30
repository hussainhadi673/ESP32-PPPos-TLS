import socket
import ssl

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="CA/ca.crt", keyfile="CA/ca.key")
    context.load_verify_locations("CA/ca.crt")  # Trust CA certificate
    context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server_socket:
        server_socket.bind(("172.16.2.97", 8443))
        server_socket.listen(5)
        print("Server listening on port 8443...")

        with context.wrap_socket(server_socket, server_side=True) as tls_server:
            client_socket, client_addr = tls_server.accept()
            print(f"Connection received from {client_addr}")
            
            # Call getpeercert() on the accepted socket, not tls_server
            print(f"Client certificate: {client_socket.getpeercert()}")
            
            client_socket.send(b"Hello from server")
            client_socket.close()

start_server()

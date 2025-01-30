import socket
import ssl

def start_client():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile="Client/client.crt", keyfile="Client/client.key")  # Client certificate and key
    context.load_verify_locations("CA/ca.crt")  # Trust the server's CA certificate

    with socket.create_connection(("172.16.2.97", 8443)) as sock:
        with context.wrap_socket(sock, server_hostname="server.mydomain.com") as tls_conn:
            # print(f"Server certificate: {tls_conn.getpeercert()}")
            print("Connection established successfully.")
            print("Received:", tls_conn.recv(1024).decode())

start_client()

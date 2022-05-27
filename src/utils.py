from datetime import datetime

separator = "<sep>".encode()
id_separator = "<id_sep>"
dest_separator = "<dest_sep>".encode()
message_separator = "<message_sep>".encode()
hash_algo = "SHA-512"
number_of_clients = 3
nb_bytes_random = 16
nb_bytes_session_key = 64

# function to generate a certificate based on the entity's id and public key
def generate_certificate(id, public_key):
    return {
        "id": id,
        "timestamp": datetime.now(), # date and time the certificate was generated
        "public_key": public_key
    }

# function to check is socket still open and has not been closed by server
def is_socket_still_open(socket):
    try:
        # try sending message to server
        socket.send("test".encode())
        socket.send("test".encode())
        # if successful --> socket still open
        return True
    except Exception as e:
        # if something goes wrong --> socket closed
        return False


from ctypes import WinError
from time import sleep

separator = "<sep>".encode()
separator_id = "<id_sep>"
hash_algo = "SHA-512"
number_of_clients = 3
timeout_socket = 30

nb_bytes_random = 3

def generate_certificate(id, public_key):
    return {
        "id": id,
        "timestamp": None, # !!!!!!!!!!!!!!!
        "public_key": public_key
    }

def is_socket_still_open(socket):
    try:
        socket.send("test".encode())
        socket.send("test".encode())
        return True
    except Exception as e:
        return False
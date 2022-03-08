import socket, threading, logging 

class Server:

    def __init__(self, host="127.0.0.1", port="65432"):
        self.name = "S"
        # socket stuff
        self.host = host
        self.port = port
        # bind etc. in __init__ ??
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        self.clients = [] # list of clients with info
        # encryption stuff
        self.public_key = None # generated with RSA ?
        self.private_key = None # generated with RSA ?
        # certificates stuff
        self.certificate = {
            "id": self.name + "<>" + str(self.port), # IP address too ???
            "timestamp": None, #### DEAL WITH CE TRUC
            "public_k": self.public_key 
        }

    
    """ leave it here or put in __init__?? """
    def start(self): # in __init__ ??
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        self.accept_clients()

    """ accept connection BUT does not check if authentication OK """
    def accept_clients(self):
        while len(self.clients) < 3: # expect 3 clients every time
            client, address = self.socket.accept()
            print("Connected with {}".format(str(address))) 
            # add client to list of clients (for now)
            client_entry = {"socket": client}
            self.clients.append(client_entry)
            # client.send("Connected to server!".encode("utf8")) 
            thread = threading.Thread(target=self.check_client_identity, args=(self.clients.index(client_entry),))
            thread.start()
            

    """ if client identity OK then add certif to list + redirect vers """
    def check_client_identity(self,client_index):
        client_socket = self.clients[client_index]["socket"]
        authenticated_client = False
        while True: # wait for authentication message from client
            try:
                # message = client_socket.recv(1024)
                # parse pour recup certif + timestamps for freshness
                # decrypt enveloppe (?) with pk in certif
                authenticated_client = True #self.compare_hashes(timestamp_freshness, decrypted_enveloppe)
                # if authenticated_client:
                #   self.clients[client_index]["cert"] = certificate
                self.clients[client_index]["cert"] = {"test": "dummy_cert"}
                #   self.clients[client_index]["id"] = certificate["id"] # pour que ce soit + easy à chercher
                break
                # else:
                #   client_socket.close()
                #   self.clients.remove(self.clients[client_index])
                #   break
            except:
                client_socket.close()
                self.clients.remove(self.clients[client_index])
                break

        if authenticated_client:
            # send server certificate with timestamp for freshness
            all_users_auth = self.all_user_authenticated()
            if all_users_auth:
                # send certificates to every one
                pass
            # puis ok pour transfer messages maintenant
            self.transfer_messages(client_socket)
    
    def transfer_messages(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode('utf8')
                # parse pour recup recipient_list + message body
                # recipient_list = self.clients
                # for recipient in recipient_list:
                    # associate recipient to recipient_socket
                #    recipient["socket"].send(message) #_body)
                for client in self.clients:
                    if client["socket"] != client_socket:
                        client["socket"].send(message.encode('utf8'))
            except:
                print("Oups! Something went wrong")
                client_socket.close()
                for client in self.clients:
                    if client["socket"] == client_socket:
                        print("Someone left!")
                        self.clients.remove(client)
                break

    def all_user_authenticated(self):
        all_user_auth = False
        for client in self.clients:
            all_user_auth = all_user_auth and ("cert" in client)
        return all_user_auth

    """============================================================="""
    """ in tool file ???? because common to all entities OR part of libraries """
    def decrypt(self, key, cipher_text):
        # return decrypted_message
        pass

    def encrypt(self, key, plain_text):
        # return encrypted_message
        pass

    def sign_message(self, message):
        # hash = hash(message)
        # signed_message = self.encrypt(self.private_key, hash)
        # return signed_message
        pass

    def compare_hash(self, message, hash):
        # hashed_message = hash(plain_text)
        # return hashed_message == hash
        pass
    """ in tool file ???? because common to all entities """
    """============================================================="""
   
# piste: faire 1 seule fonction "start_server" dans laquelle j'appelle accept_client et tout


if __name__ == "__main__":
    server = Server('127.0.0.1', 1818)
    server.start()
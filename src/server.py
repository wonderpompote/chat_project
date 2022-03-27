from rsa import VerificationError
import utils
import rsa, threading, socket, pickle, random

class Server:

    def __init__(self, ip="127.0.0.1", port=1818, name="S"):
        self.ip = ip
        self.port = port
        self.name = name
        self.id = self.name + utils.separator_id + str(self.port)
        self.socket = None
        (self.pub_key, self.priv_key) = rsa.newkeys(1024)
        self.certificate = utils.generate_certificate(self.id, self.pub_key)
        self.potential_clients = []
        self.authenticated_clients = []
        self.authenticated_sockets = []

    def start(self):
        # initialise socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
        # wait for clients
        self.socket.listen()
        while len(self.authenticated_clients) < utils.number_of_clients-1: # we expect only 3 clients
            client, address = self.socket.accept()
            print("Connected with {}".format(str(address)))
            self.potential_clients.append(client)
            # thread to check identity of client
            thread = threading.Thread(target=self.check_identity, args=(client,))
            thread.start()

    def check_identity(self, client):
        # while client not authenticated wait for his authentication message
        while client in self.potential_clients: 
            try:
                message = client.recv(2048) # change value ??????
                if message:
                    message_split = message.split(utils.separator)
                    if len(message_split) == 3:
                        certificate = pickle.loads(message_split[0])
                        verif_signature = rsa.verify(message_split[1], message_split[2], certificate["public_key"])
                        # if verification of signature ok
                        if verif_signature:
                            # add client to list of authenticated users
                            self.authenticated_clients.append({
                                "certificate":certificate,
                                "socket":client})
                            self.authenticated_sockets.append(client)
                            # remove client from list of potential users
                            self.potential_clients.remove(client)
                            print("Client "+certificate["id"].split(utils.separator_id)[0]+" authenticated successfully!")
                            # server responds by sending its own certificate
                            server_random_number = random.randbytes(utils.nb_bytes_random)
                            server_message = pickle.dumps(self.certificate) + utils.separator + server_random_number + utils.separator + rsa.sign(server_random_number, self.priv_key,utils.hash_algo)
                            client.send(server_message)
            except:
                print("Error during authentication of client "+str(client.getpeername()))
                client.close()
                if client in self.potential_clients:
                    self.potential_clients.remove(client)
                if client in self.authenticated_clients:
                    self.authenticated_clients.remove(client)
                break
        
        if len(self.authenticated_clients) == utils.number_of_clients and len(self.potential_clients) == 0: # if all clients authenticated
            # send client certificates to other clients
            for auth_client in self.authenticated_clients:
                random_number = random.randbytes(utils.nb_bytes_random)
                message = b''
                for client_certificate in self.authenticated_clients:
                    if client_certificate != auth_client:
                        message += pickle.dumps(client_certificate["certificate"]) + utils.separator
                message += random_number + utils.separator + rsa.sign(random_number, self.priv_key, utils.hash_algo)
                auth_client["socket"].send(message)
            self.transfer_messages(client)

    def transfer_messages(self, client_socket):
        sender = None
        for client in self.authenticated_clients:
            if client["socket"] == client:
                sender = client["certificate"]["id"]
        while client_socket in self.authenticated_sockets:
            try:
                message = client_socket.recv(1024)
                if message:
                    message_split = message.split(utils.separator)
                    if len(message_split) >= 2:
                        recipient_list = pickle.loads(message_split[0])
                        for recipient in recipient_list:
                            print("Transfer message to "+recipient)
                            for client in self.authenticated_clients:
                                if recipient == client["certificate"]["id"]:
                                    message_to_transfer = sender.encode() + utils.separator + message_split[1]
                                    print("Message to transfer : "+str(message_to_transfer))
                                    client["socket"].send(message_to_transfer)
            except:
                print("Oups, error while transfering message")

if __name__ == "__main__":
    server = Server()
    server.start()

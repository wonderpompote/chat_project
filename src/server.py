import utils
import rsa, threading, socket, pickle, random, sys
from time import sleep


class Server:

    def __init__(self, ip="127.0.0.1", port=1818, name="S"):
        self.ip = ip
        self.port = port
        self.name = name
        self.id = self.name + utils.id_separator + str(self.port)
        self.socket = None
        (self.pub_key, self.priv_key) = rsa.newkeys(1024)
        self.certificate = utils.generate_certificate(self.id, self.pub_key) # condition 2
        self.potential_clients = []
        self.authenticated_clients = {} # contains clients certificates + sockets (condition 3)
        self.message_buffer = {} # will contain messages to be transfered

    def start(self):
        # initialise socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
        # wait for clients
        self.socket.listen()
        while len(self.authenticated_clients) < utils.number_of_clients: # we expect only a defined number of clients
            client, address = self.socket.accept()
            print("Connected with {}".format(str(address)))
            self.potential_clients.append(client)
            # thread to check identity of client
            thread = threading.Thread(target=self.check_identity, args=(client,))
            thread.start()

    # function to close client socket and remove it from potential clients list and authenticated clients dictionary
    def close_client_socket(self, client):
        client.close()
        if client in self.potential_clients:
            self.potential_clients.remove(client)
        for auth_client_id, auth_client_val in self.authenticated_clients.items():
            if auth_client_val["socket"] == client:
                del self.authenticated_clients[auth_client_id]
                break

    def check_identity(self, client):
        # while client not authenticated wait for his authentication message
        while client in self.potential_clients: 
            try:
                message = client.recv(2048)
                if message:
                    # if message received, check format OK + signature
                    message_split = message.split(utils.separator)
                    if len(message_split) == 3:
                        certificate = pickle.loads(message_split[0])
                        verif_signature = rsa.verify(message_split[1], message_split[2], certificate["public_key"])
                        # if verification of signature ok
                        if verif_signature:
                            # add client to list of authenticated users
                            self.authenticated_clients[certificate["id"]] = {
                                "certificate":certificate,
                                "socket":client
                            }
                            # remove client from list of potential users
                            self.potential_clients.remove(client)
                            print("Client "+certificate["id"].split(utils.id_separator)[0]+" authenticated successfully!")
                            # server responds by sending its own certificate (condition 3)
                            server_random_number = random.randbytes(utils.nb_bytes_random)
                            server_message = pickle.dumps(self.certificate) + utils.separator + server_random_number + utils.separator + rsa.sign(server_random_number, self.priv_key,utils.hash_algo)
                            client.send(server_message)
                            sleep(2)

            except Exception as e:
                print("Error during authentication of client "+str(client.getpeername())+": "+str(e))
                # close connection with client
                self.close_client_socket(client)
                break
        
        # wait while all clients not authenticated
        while len(self.authenticated_clients) < utils.number_of_clients: 
            sleep(0.1)

        if len(self.authenticated_clients) == utils.number_of_clients and len(self.potential_clients) == 0:  
            # if all clients authenticated, send other clients certificate to current client (condition 3)
            random_number = random.randbytes(utils.nb_bytes_random)
            message = b''
            # go through all authenticated clients
            for wanted_client_certificate in self.authenticated_clients.values():
                # if wanted_client_certificate not equal to current client (auth_client)
                if wanted_client_certificate["socket"] != client:
                    # we add its certificate to the message that will be sent to auth_client
                    message += pickle.dumps(wanted_client_certificate["certificate"]) + utils.separator
            # server adds randm number for freshness + signs message
            message += random_number + utils.separator + rsa.sign(random_number, self.priv_key, utils.hash_algo)
            client.send(message)
            self.key_establishment_clients(client)

    # method that returns client id corresponding to client's socket
    def get_client_id_from_socket(self, socket):
        for client_id, client_values in self.authenticated_clients.items():
            if client_values["socket"] == socket:
                return client_id

    def key_establishment_clients(self, client):
        while len(self.message_buffer) < utils.number_of_clients and len(self.authenticated_clients) == utils.number_of_clients:
            try:
                message = client.recv(4096)
                if message and "test".encode() not in message: # check if "test".encode() not in message (because used to check if connection still open)
                    message_split = message.split(utils.message_separator)
                    if len(message_split) == utils.number_of_clients-1: # check if message has correct format
                        # recover sender ID
                        sender_id = self.get_client_id_from_socket(client)
                        self.message_buffer[sender_id] = []
                        # appends random numbers to self.message_buffer[senderID]
                        for pending_message in message_split:
                            self.message_buffer[sender_id].append(pending_message)
                        break

            except Exception as e: # if something goes wrong --> close everything
                print("Error during the key agreement of the clients: "+str(e))
                self.close_client_socket(client)
                sys.exit()
        
        # wait to receive all the messages necessary for key agreement
        while len(self.message_buffer) != utils.number_of_clients:
            sleep(0.1)

        # if we received all the messages necessary for the clients key agreement
        if len(self.message_buffer) == utils.number_of_clients and len(self.authenticated_clients) == utils.number_of_clients:
            sender_id = self.get_client_id_from_socket(client)
            for message in self.message_buffer[sender_id]:
                # each message of format: destination<dest_separator>{RanNumber}PubK_destination<separator>signature
                message_split = message.split(utils.dest_separator) # split message to remove recipient id and replace it by sender id
                destination_id = pickle.loads(message_split[0])[0] # recover destination id
                message_to_be_sent = pickle.dumps(sender_id) + utils.separator + message_split[1]
                self.authenticated_clients[destination_id]["socket"].send(message_to_be_sent) # send message to destination
                sleep(2)

            self.transfer_messages(client)
        
        else:
            self.close_client_socket(client)
            sys.exit()

    def transfer_messages(self, client):
        client_id = self.get_client_id_from_socket(client) # recover current client ID from socket
        while client_id in self.authenticated_clients and len(self.authenticated_clients) == utils.number_of_clients: # while all clients connected
            try:
                message = client.recv(1024)
                if message and "test".encode() not in message and len(self.authenticated_clients) == utils.number_of_clients:
                    # broadcast message to all entities (except the one who sent message)
                    for auth_client_id, auth_client_val in self.authenticated_clients.items():
                        if auth_client_id != client_id:
                            auth_client_val["socket"].send(message)
                            
            except Exception as e: # if something goes wrong --> close everything
                print("Error while transfering message: "+str(e))
                self.close_client_socket(client)
                break
        
        self.close_client_socket(client)
        sys.exit()

if __name__ == "__main__":
    server = Server()
    server.start()

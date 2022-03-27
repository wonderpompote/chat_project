import socket, rsa, threading, random, pickle
from time import sleep
from rsa import VerificationError
import utils

class Client:

    def __init__(self,name, server_ip="127.0.0.1", server_port=1818):
        self.name = name
        self.id = None # to be generated when connected to server
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        (self.pub_key, self.priv_key) = rsa.newkeys(1024)
        self.rand_nb_key_agreement = []
        self.session_key = None # to be generated
        self.certificate = None # to be generated when connected to server
        self.server_certificate = None # will be received after authentication to server
        self.other_certificates = []

    def start(self):
        self.socket.connect((self.server_ip, self.server_port))
        ###### REMOVE THIS AFTER TESTS ####################
        print("Connected to server "+str(self.socket.getpeername()))
        ###################################################
        self.id = self.name + utils.separator_id + str(self.socket.getsockname()[1])
        self.certificate = utils.generate_certificate(self.id, self.pub_key)
        authentication_thread = threading.Thread(target=self.auth_to_server) 
        authentication_thread.start()

    def auth_to_server(self):
        random_number = random.randbytes(utils.nb_bytes_random)
        message_server = pickle.dumps(self.certificate) + utils.separator + random_number + utils.separator + rsa.sign(random_number,self.priv_key,utils.hash_algo)
        self.socket.send(message_server)
        sleep(2) # wait for server to check our authentication
        if utils.is_socket_still_open(self.socket): # if connection still open ( = authentication successful)
            while self.server_certificate is None: # wait for server to send its own certificate
                try:
                    message_server = self.socket.recv(1024)
                    if message_server and self.server_certificate is None: # first certificate to receive is the server's
                        message_split = message_server.split(utils.separator)
                        if len(message_split) == 3:
                            certificate = pickle.loads(message_split[0])
                            verif_signature = rsa.verify(message_split[1], message_split[2], certificate["public_key"])
                            if verif_signature:
                                self.server_certificate = certificate
                                ###### REMOVE THIS AFTER TESTS ####################
                                print("Server certificate : "+str(self.server_certificate))
                                ################################################### 
                                break   
                except VerificationError:
                    print("Error while verifying random number signature")
                    self.socket.close()
                    break
                except TimeoutError:
                    print("Timeout les gros")
                    self.socket.close()
                    break
                except Exception as e:
                    print("Error during authentication to server : "+str(e))
                    self.socket.close()
                    break
            if self.server_certificate is not None:
                self.receive_other_certificates()
        else:
            print("Socket closed by server")
            self.socket.close() 
    
    def receive_other_certificates(self):
        while len(self.other_certificates) < (utils.number_of_clients - 1):
            try:
                message = self.socket.recv(1024)
                if message and len(self.other_certificates) != (utils.number_of_clients - 1):
                    ###### REMOVE THIS AFTER TESTS ####################
                    print("Waiting for other certificates")
                    ###################################################
                    message_split = message.split(utils.separator)
                    if len(message_split) == 4:
                        # check signed random number with server public key
                        verif_signature = rsa.verify(message_split[2], message_split[3], self.server_certificate["public_key"])
                        if verif_signature:
                            # add other certificates to our list
                            for i in range(utils.number_of_clients - 1):
                                message_to_load = message_split[i]
                                certificate = pickle.loads(message_to_load)
                                self.other_certificates.append(certificate)
                            ###### REMOVE THIS AFTER TESTS ####################
                            print("All certificates received : "+str(self.other_certificates))
                            ###################################################
                            break

            except Exception as e:
                print("Error while waiting for other certificates : "+str(e))
                self.socket.close()
                break
        if len(self.other_certificates) == (utils.number_of_clients - 1):
            self.key_agreement()
                   

    def key_agreement(self):
        print("Coucou key agreement")
        """
        random_number = random.randbytes(utils.nb_bytes_random)
        self.rand_nb_key_agreement.append(random_number)
        for other_client in self.other_certificates:
            encrypted_number = rsa.encrypt(random_number, other_client["public_key"])
            encrypted_signed_number = {
                "encrypted_number": encrypted_number,
                "signed_message": rsa.sign(encrypted_number, self.priv_key, utils.hash_algo)
            }
            message = pickle.dumps([other_client["id"]]) + utils.separator + pickle.dumps(encrypted_signed_number)
            self.socket.send(message)

        #receive_thread = threading.Thread(target=self.receive_messages)
        #receive_thread.start()
        #self.send_messages()
        """
        
    def receive_messages(self):
        while True:
            try:
                message = self.socket.recv(4096)
                
            except:
                print('Oups! Something went wrong!')
                self.socket.close()
                break

    def send_messages(self):
        while True:
            message = input("> ")
            if "exit" in message:
                self.socket.close()
                break
            self.socket.send(message.encode('utf8', 'ignore'))


if __name__ == "__main__":
    client_name = input("name> ")
    client = Client(name=client_name)
    client.start()

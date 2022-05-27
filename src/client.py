import socket, rsa, threading, random, pickle, sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes
from time import sleep
import utils

class Client:

    def __init__(self,name, server_ip="127.0.0.1", server_port=1818):
        self.name = name
        self.id = None # to be generated when connected to server
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        (self.pub_key, self.priv_key) = rsa.newkeys(1024)
        self.rand_nb_key_agreement = [] # will contain random numbers for key agreement
        self.session_key = None # to be generated with random numbers from other entities
        self.aes_block_size = 16
        self.certificate = None # to be generated (condition 2)
        self.server_certificate = None # will be received after authentication to server
        self.other_certificates = [] # will contain other clients certificates
        self.send_thread_running = False
        self.receive_thread_running = False

    def start(self):
        # socket to connec to server (condition 1)
        self.socket.connect((self.server_ip, self.server_port))
        print("Connected to server "+str(self.socket.getpeername()))
        # generate own id from name and socket port
        self.id = self.name + utils.id_separator + str(self.socket.getsockname()[1])
        # generate certificate with own id and public key (condition 2)
        self.certificate = utils.generate_certificate(self.id, self.pub_key)
        # launch thread to authenticate to the server (and eventually send messages if everything goes well)
        authentication_thread = threading.Thread(target=self.auth_to_server)
        self.send_thread_running = True 
        authentication_thread.start()

    def auth_to_server(self): # condition 5
        # generate random byte number for freshness
        random_number = random.randbytes(utils.nb_bytes_random)
        # message to server --> Cert<sep>random_number<sep>Signature(random_number)
        message_server = pickle.dumps(self.certificate) + utils.separator + random_number + utils.separator + rsa.sign(random_number,self.priv_key,utils.hash_algo)
        self.socket.send(message_server)
        sleep(2) # wait for server to check our authentication
        if utils.is_socket_still_open(self.socket): # if connection still open ( = authentication successful)
            while self.server_certificate is None: # wait for server to send its own certificate
                try:
                    message_server = self.socket.recv(1024)
                    if message_server and self.server_certificate is None: # first certificate we receive is the server's
                        message_split = message_server.split(utils.separator) # split message to have [cert, random number, signature]
                        if len(message_split) == 3:
                            certificate = pickle.loads(message_split[0])
                            verif_signature = rsa.verify(message_split[1], message_split[2], certificate["public_key"])
                            if verif_signature: # if signature, store certificate in self.server_certificate
                                self.server_certificate = certificate
                                break   
                # if something goes wrong --> close socket and program
                except rsa.VerificationError:
                    print("Error while verifying random number signature")
                    self.socket.close()
                    sys.exit()
                except Exception as e:
                    print("Error during authentication to server : "+str(e))
                    self.socket.close()
                    sys.exit()

            # if received server certificate correctly --> go wait for other entities' certificates
            if self.server_certificate is not None:
                self.receive_other_certificates()
        
        else: # if socket closed by server --> close socket and program
            print("Socket closed by server")
            self.socket.close() 
            sys.exit()
    
    def receive_other_certificates(self):
        while len(self.other_certificates) != (utils.number_of_clients - 1):
            try:
                message = self.socket.recv(2048)
                if message:
                    # message should be Cert1<sep>Cert2<sep>random_number<signature(random_number)
                    message_split = message.split(utils.separator)
                    if len(message_split) == utils.number_of_clients+1: 
                        # check signed random number with server public key
                        verif_signature = rsa.verify(message_split[utils.number_of_clients-1], message_split[utils.number_of_clients], self.server_certificate["public_key"])
                        if verif_signature:
                            # add other certificates to our list
                            for i in range(utils.number_of_clients - 1):
                                message_to_load = message_split[i]
                                certificate = pickle.loads(message_to_load)
                                self.other_certificates.append(certificate)
                            break

            except Exception as e: # if something goes wrong --> close socket and program
                print("Error while receiving other certificates : "+str(e))
                self.socket.close()
                sys.exit()


        if len(self.other_certificates) == (utils.number_of_clients - 1):
            # if we have all the necessary certificates --> go to key agreement function
            self.key_agreement()

    # function that returns public key of client based on its id
    def find_pub_key_from_id(self, id):
        for client in self.other_certificates:
            if client["id"] == id:
                return client["public_key"]

    def send_random_number(self):
        # generate random number for key agreement
        random_number = get_random_bytes(utils.nb_bytes_session_key)
        self.rand_nb_key_agreement.append(random_number) # first number of self.rand_nb_key_agreement is generated by client itself
        message = b''
        # encrypt number for each client doing the key agreement
        for other_client in self.other_certificates:
            # if message is not empty, add separator to separate messages
            if len(message) != 0:
                message += utils.message_separator
            # encrypt random number with recipient's public key
            encrypted_number = rsa.encrypt(random_number, other_client["public_key"])
            # sign the message for authentication and integrity (condition 4)
            signature = rsa.sign(encrypted_number, self.priv_key, utils.hash_algo)
            # append recipientID, encrypted number and signature to message (separated by utils.separator)
            message += pickle.dumps([other_client["id"]]) + utils.dest_separator + pickle.dumps(encrypted_number) + utils.separator + pickle.dumps(signature)
        # send whole message to server
        self.socket.send(message) # format: ID1<sep>{rand_num}Pub_k1<sep>Signature({rand_num}Pub_k1)<sep_message>ID2<sep>{rand_num}Pub_k2<sep>Signature({rand_num}Pub_k2)

    def receive_random_numbers(self):
        # once message is sent --> wait for other entities' random numbers
        if utils.is_socket_still_open(self.socket): # if socket not closed by server
            while len(self.rand_nb_key_agreement) != utils.number_of_clients:
                try:
                    message = self.socket.recv(1024)
                    if message:
                        message_split = message.split(utils.separator)
                        if len(message_split) == 3:
                            # recover sender from message and its public_key to verify signature
                            sender = pickle.loads(message_split[0])
                            sender_pub_key = self.find_pub_key_from_id(sender)
                            # verify signature (condition 4)
                            verif_signature = rsa.verify(pickle.loads(message_split[1]), pickle.loads(message_split[2]),sender_pub_key)
                            if verif_signature:
                                # if signature ok --> decrypt number with our own private key and add it to list
                                random_number = rsa.decrypt(pickle.loads(message_split[1]),self.priv_key)
                                self.rand_nb_key_agreement.append(random_number)
                except Exception as e:
                    print("Error during the establishment of the session key: "+str(e))
                    self.socket.close()
                    sys.exit()
    
    def generate_session_key(self):
        # generate 256-bit hash of the random numbers --> our session key
        hash = SHA3_256.new()
        concatenated_rand_nb = b''.join(self.rand_nb_key_agreement)
        hash.update(concatenated_rand_nb)
        self.session_key = hash.digest()

    def key_agreement(self):
        self.send_random_number() # send our random number to the other entities (via server)
        self.receive_random_numbers() # receive all the random numbers
        self.rand_nb_key_agreement.sort() # sort the random numbers so that every entity has them in the same order
        self.generate_session_key() # generate session key
        # launch thread to receive messages and go to send_messages function
        receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread_running = True
        receive_thread.start()
        self.send_messages()
    
    # function to pad the messages so they respect the self.aes_block_size
    def pad_message(self, message):
        nb_bytes_to_add = self.aes_block_size - len(message) % self.aes_block_size
        pad_character = chr(nb_bytes_to_add).encode() # generate padding byte character (character = nb of bytes to add)
        padding = nb_bytes_to_add * pad_character # generate padding
        return message + padding # return message concatenated with padding

    # function to remove padding of message
    def unpad_message(self, padded_message):
        last_character = padded_message[len(padded_message) - 1:] # get last character of message (supposed to be padding character)
        pad_char_to_remove = ord(last_character) # get nb corresponding to padding character
        return padded_message[:-pad_char_to_remove] # return message without padding

    def send_messages(self):
        print("Chat correctly set up!")
        while self.receive_thread_running:
            message = input()
            if "exit" in message: # if type only "exit" --> end the program
                self.socket.close()
                self.send_thread_running = False
                self.receive_thread_running = False
                sys.exit()
            padded_message = self.pad_message(pickle.dumps(message))
            try:
                # create new aes cipher to encrypt message
                aes_cipher = AES.new(self.session_key, AES.MODE_CBC)
                encrypted_message = aes_cipher.encrypt(padded_message)
                # add sender id to message and aes iv (so the others will be able to decrypt)
                message_to_send = self.id.encode() + utils.separator + aes_cipher.iv + utils.separator + encrypted_message
                self.socket.send(message_to_send)

            except Exception as e:
                if self.receive_thread_running:
                    print("Error while sending message: "+str(e))
                self.socket.close()
                self.send_thread_running = False
                self.receive_thread_running = False
                sys.exit()

    def receive_messages(self):
        while self.send_thread_running:
            try:
                message = self.socket.recv(1024)
                if message and self.send_thread_running:
                    message_split = message.split(utils.separator) # split message to have [sender_id, encrypted_message, aes_iv]
                    if len(message_split) == 3: # if valid message format
                        # recover sender ID and name
                        sender = message_split[0].decode()
                        sender_name = sender.split(utils.id_separator)[0]
                        # recover aes iv and create cipher object to decrypt message
                        aes_iv = message_split[1]
                        aes_cipher = AES.new(self.session_key, AES.MODE_CBC, iv=aes_iv)
                        # decrypt message using session key
                        decrypted_message =  aes_cipher.decrypt(message_split[2])
                        # decode message and remove padding
                        unpad_decoded_message = self.unpad_message(decrypted_message)
                        message_decoded = pickle.loads(unpad_decoded_message)
                        # print message
                        print(sender_name+"> "+str(message_decoded))
                
            except Exception as e:
                if self.send_thread_running:
                    print('Error occured while receiving a message: '+str(e))
                self.socket.close() # close socket
                self.send_thread_running = False
                self.receive_thread_running = False
                sys.exit()

if __name__ == "__main__":
    client_name = input("name> ")
    client = Client(name=client_name)
    client.start()

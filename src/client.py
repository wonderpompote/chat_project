import socket, threading

class Client:

    def __init__(self, name="", server_host='127.0.0.1', server_port=1818):
        self.name = name
        # socket stuff
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        # encryption stuff
        self.public_key = None # generated with RSA ?
        self.private_key = None # generated with RSA ?
        self.session_key = None # to be agreed upon w/ other clients
        # certificates stuff
        self.certificate = {"id": self.name, "pub_key": self.public_key} # timestamp + pk + name + (host + port)
        self.entities_certificates = {} # other entities certificates (ie. S,B,C)
        # ??? stuff
        self.random_number = None # ??? att or just function??

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_host, self.server_port))
        # start threads
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()
        write_thread = threading.Thread(target=self.send_messages) 
        write_thread.start()

    def send_certificate(self):
        pass

    def verif_message(self, source, message):
        pass

    def receive_messages(self):
        while True:
            try:
                message = self.socket.recv(1024).decode('utf8')
                print(message)
            except:
                print('Oups! Something went wrong!')
                self.socket.close()
                break

    def send_messages(self):
        while True:
            message = input('me > ')
            if "exit" in message:
                self.socket.close()
                break
            self.socket.send(message.encode('utf8', 'ignore'))


if __name__ == "__main__":
    client = Client()
    client.name = input("name > ")
    client.start()
    
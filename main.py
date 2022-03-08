import threading

clients = [ {"id": "numb1", "socket": "coucou socket1"},
            {"id": "numb2", "socket": "coucou socket2"}]

"""
for client in enumerate(clients):
    print("client socket: "+client["socket"])
    client["cert"] = "cert"+str(index)
    print("client cert: "+client["cert"])
    
    
cert_A = {"id":"A","pk":"pkA","timestamp":"tsA"}
cert_B = {"id":"B","pk":"pkB","timestamp":"tsB"}
str_A =str(cert_A)
str_B = str(cert_B)
print(str(hash(str_A+str_B)))
print(str(hash(str_B+str_A)))

client_entry = {"test": "coucou test"}
clients.append(client_entry)
print(str(clients)+"\nClient_entry index: "+str(clients.index(client_entry)))

i=False
def thread_function_2():
    print(">>> coucou thread function 2")

def thread_function_1():
    if i:
        print(">>> coucou thread function 1")
        thread_function_2()
    else:
        pass

thread = threading.Thread(target=thread_function_1)
thread.start()


test = True
test = test and True
print(test)
print(test and False)
"""
message = input("> ")
if "exit" in message:
    print("exit babyyyy")
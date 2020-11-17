import socket#used to create sockets that can communicate with one another
import pickle#used to encode and decode data structres to be sent through UDP connection
import random#used to generate nonce
from cryptography.fernet import Fernet#used to generate key, encryption and decryption

def pwd(action_message,client):#function to do remote call to file server for pwd
    action_message.append(session_key.encrypt(action.encode()))
    action_message = pickle.dumps(action_message)
    client.sendto(action_message, file_location)#remote call to file server
    output = client.recvfrom(4096)
    output = session_key.decrypt(output[0])
    output = output.decode()
    return(output)#response of file server

def ls(action_message,client):#function to do remote call to file server for ls
    action_message.append(session_key.encrypt(action.encode()))
    action_message = pickle.dumps(action_message)
    client.sendto(action_message, file_location)#remote call to file server
    output = client.recvfrom(4096)
    output = session_key.decrypt(output[0])
    output = output.decode()
    return(output)#response of file server

def cat(action_message,client):#function to do remote call to file server for cat
    action_message.append(session_key.encrypt(action.encode()))
    print("Name the file you want to read ")
    file_to_read = str(input())#name of file to read
    action_message.append(session_key.encrypt(file_to_read.encode()))
    action_message = pickle.dumps(action_message)
    client.sendto(action_message, file_location)#remote call to file server
    output = client.recvfrom(4096)
    output = session_key.decrypt(output[0])
    output = output.decode()
    return (output)#response of file server

def cp(action_message,client):#function to do remote call to file server for cp
    action_message.append(session_key.encrypt(action.encode()))
    print("Name the file you want to copy from other server  ")
    file_to_copy = str(input())#name of file to copy
    action_message.append(session_key.encrypt(file_to_copy.encode()))
    action_message = pickle.dumps(action_message)
    client.sendto(action_message, file_location)#remote call to file server
    output = client.recvfrom(4096)
    output = session_key.decrypt(output[0])
    output = output.decode()
    return (output)#response of file server

def add(action_message,client):#function to do remote call to file server for add
    action_message.append(session_key.encrypt(action.encode()))
    print("Name the file you want to add to server  ")
    file_to_add = str(input())#name of file to add
    print("Please write Content of this file")
    content_of_file = str(input())#content of file
    action_message.append(session_key.encrypt(file_to_add.encode()))
    action_message.append(session_key.encrypt(content_of_file.encode()))
    action_message = pickle.dumps(action_message)
    client.sendto(action_message, file_location)#remote call to file server
    output = client.recvfrom(4096)
    output = session_key.decrypt(output[0])
    output = output.decode()
    return (output)#response of file server

ip='127.0.0.1'#local address
print("What is port number of this Client server? : ")
my_port=int(input())#port number of client entered by user
print("What is port number of Key Distribution Server? : ")
kdsp=int(input())#port number of kds entered by user
kds=('127.0.0.1',kdsp)#location of kds
my_addr=('127.0.0.1',my_port)#location of current client
client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)#create UDP connection
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#terminate any previously created socket which may be running
client.bind(my_addr)#bind socket
keys={}#info about keys is stored in dict
my_info=pickle.dumps(my_port)
client.sendto(my_info,kds)#register with kds
message=client.recvfrom(4096)
keys['kds']=Fernet(message[0])#activate key
client_numb=client.recvfrom(4096)
client_numb=int(keys['kds'].decrypt(client_numb[0]).decode())#client number given by kds

if (client_numb==1):
    client_name='cs1'
    print("Waiting for 2 clients to register")#wait for other clients
elif(client_numb==2):
    client_name='cs2'
    print("Waiting for 1 client to register")#wait for one more client
elif(client_numb==3):
    client_name='cs3'

#after 3 clients we can access file server
ready_to_access=client.recvfrom(4096)
ready_to_access=int(keys['kds'].decrypt(ready_to_access[0]).decode())
if (ready_to_access==3):
    print("All clients have registered, you can now access file servers\n")
    file_server_info = client.recvfrom(4096)
    file_server_info = str(keys['kds'].decrypt(file_server_info[0]).decode())#file info given to clients
    print(file_server_info)
    def gen_nonce():#nonce
        return(random.randint(1,10000))

    nonce=gen_nonce()
    print("What file server do you want to access? (options are fs1 and fs2) : ")
    file_name=input()#name of file server to access
    while (file_name not in ['fs1','fs2']):#file server not available
        print("No such file server , Enter file server name again : ")
        file_name = input()
    access=[client_name,file_name,str(nonce)]#client 1 wants to access file server 1 along with nonce
    send_det=pickle.dumps(access)
    client.sendto(send_det,kds)#send info to kds based on needham schroder
    enc_response=client.recvfrom(4096)
    enc_response=pickle.loads(enc_response[0])
    key_kds=keys['kds']

    response=[]
    for i in range(6):
        response.append(key_kds.decrypt(enc_response[i]))#decrypt response
        if (i<3):
            response[i]=response[i].decode()#decode first 3, next 3 is ticket to file server
    if nonce==int(response[0]):#if nonce is correct
        session_key=Fernet(response[1])#activate key
        keys[file_name]=session_key#store session key
        file_location=(ip,int(response[2]))#location of file server
        message_to_file=pickle.dumps([response[3],response[4],response[5]])

        client.sendto(message_to_file,file_location)#send message to file server
        file_reply=client.recvfrom(4096)

        file_reply=file_reply[0]#response based on needham schroder
        dec_nonce=session_key.decrypt(file_reply)
        dec_nonce=dec_nonce.decode()
        dec_nonce=int(dec_nonce)-1#reduce value of nonce
        enc_nonce=session_key.encrypt(str(dec_nonce).encode())
        client.sendto(enc_nonce,file_location)#send message
        verified=client.recvfrom(4096)
        verified=verified[0].decode()#if verified
        want_continue='y'#variable to store if client wants to continue
        actions=["pwd","ls","cp","cat","add"]#list of available actions
        if (verified=='1'):#once client is verified
            print(file_name+" has verified you\n")
            print("You can perform these actions :")
            print("\tpwd - List present working directory of a file")
            print("\tls - list the contents of a file server")
            print("\tcp - copy one file from one server to the other ")
            print("\tcat - display contents of a file (read file)")
            print("\tadd - add a file to this server ")

            while(want_continue=='y'):
                print("What action do you want to do? ")
                action=input()
                yes='y'#indicates file server should keep serving this client
                yes=session_key.encrypt(yes.encode())
                action_message=[yes]#build message to send file server
                if (action not in actions):#action not supported
                    print("This action is not supported :")
                    print("Do you want to continue?(y/n):")
                    want_continue=input()
                else:#if action is valid
                    if (action=='pwd'):
                        output=pwd(action_message,client)# call function for pwd
                        print(output)

                    elif (action=='ls'):
                        output=ls(action_message,client)# call function for ls
                        print(output)
                    elif(action=="cat"):
                        output=cat(action_message,client)# call function for cat
                        print(output)
                    elif(action=="cp"):
                        output=cp(action_message, client)# call function for cp
                        print(output)
                    elif(action=="add"):
                        output=add(action_message, client)# call function for add
                        print(output)
                    print("Do you want to continue?(y/n):")
                    want_continue = input()
                    while (want_continue not in ['y','n']):
                        print("Please enter valid response if you want to continue\n (y-->yes,n-->no)")
                        print("Do you want to continue?(y/n):")
                        want_continue = input()

            no='n'#client done accessing server
            no = session_key.encrypt(no.encode())
            action_message = [no]#indicate we are done so file server can access other clients
            action_message = pickle.dumps(action_message)
            client.sendto(action_message, file_location)

        else:#file server has not verified client
            print("Not verified, you are not allowed to perform actions on file server ")
    else:#kds has not sent correct nonce
        print("Key Distribution Server not verified as nonce not equal ")
else:#kds not able to register 3 clients unexpected error
    print("There has been a problem registering 3 clients ")




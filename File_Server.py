import socket#used to create sockets that can communicate with one another
import pickle#used to encode and decode data structres to be sent through UDP connection

import random#used to generate nonce
from cryptography.fernet import Fernet#used to generate key, encryption and decryption

def pwd(file_name):#function to indicate working directory
    if (file_name=="fs1"):
        full="File Server-1"#full name of file server

    elif(file_name=="fs2"):
        full="File Server-2"#full name of file server
    return("Your Present working directory is "+full+"\n")#indicate working directory

def ls(file_name,my_files):#to indicate contents of file server
    if (file_name=="fs1"):
        full="File Server-1"#full name of file server

    elif(file_name=="fs2"):
        full="File Server-2"#full name of file server
    files=""
    for i in my_files:
        files=files+"\n\t"+str(i)#message is built
    return(full + " contains : " +files+"\n")#contains info about files in file server

def cat(file_to_read,my_files):#read a file
    if (file_to_read not in my_files):#if file is not present in current directory
        return ("This file is not present in this file server "+"\n")
    else:
        f=open(file_to_read,"r")
        response="Contents of " +file_to_read +" are :\n"+f.read()+"\n"#display contents of file
        f.close()
        return(response)#return response

def cp(file_to_copy,my_files,file_name):#to copy a file from other file server
    my_files.append(file_to_copy)#update info about files stored in this server
    response=file_to_copy+" copied to " +file_name+"\n"
    return(response)#return response

def add(file_to_add,content_of_file,my_files,file_name):#to add a file
    fa = open(file_to_add, "w+")#open a file with particular title
    fa.write(content_of_file)#write the contents
    fa.close()
    my_files.append(file_to_add)#update info about files stored in this server
    response=file_to_add+" has been added to "+file_name+"\n"
    return([response,my_files])#return response and updates info

ip='127.0.0.1' #local address
print("What is port number of this file server? : ")
my_port=int(input())#port number of file server entered by user
print("What is port number of Key Distribution Server? : ")
kdsp=int(input())#port number of kds entered by user
kds=('127.0.0.1',kdsp)#location of kds

my_addr=('127.0.0.1',my_port)#location of current file server
file=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)#create UDP connection
file.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#terminate any previously created socket which may be running
file.bind(my_addr)#bind socket
keys={}#info about keys is stored in dict
my_info=pickle.dumps(my_port)
file.sendto(my_info,kds)#register with kds
message=file.recvfrom(4096)
my_files=[]#list of files in this file server
keys['kds']=Fernet(message[0])#activate key
file_numb=file.recvfrom(4096)#file server number of this file server
file_numb=int(file_numb[0].decode())
if (file_numb==1):#some initial files for this file server
    file_name='fs1'
    fa=open("file 1.txt","w+")
    fa.write("This is file 1.txt")
    fb=open("file 2.txt","w+")
    fb.write("This is file 2.txt")
    fa.close()
    fb.close()
    my_files=["file 1.txt","file 2.txt"]
elif(file_numb==2):#some initial files for this file server
    file_name='fs2'
    fa=open("file 3.txt","w+")
    fa.write("This is file 3.txt")
    fb=open("file 4.txt","w+")
    fb.write("This is file 4.txt")
    fa.close()
    fb.close()
    my_files=["file 3.txt","file 4.txt"]
my_files_info=pickle.dumps(my_files)
file.sendto(my_files_info,kds)#send info about files in this server
while (True):
    enc_message=file.recvfrom(4096)#message recieved from client
    enc_message=pickle.loads(enc_message[0])
    key_kds=keys['kds']
    message=[]
    for i in range (3):
        message.append(key_kds.decrypt(enc_message[i]))#decrypt each part of message
        message[i]=message[i].decode()#decode each part of message
    session_key=Fernet(message[0])#activate the key
    client_location=(ip,int(message[1]))#save location of client
    client_name=message[2]
    keys[client_name]=session_key#save the session key of this client


    def gen_nonce():#function to generate nonce
        return (random.randint(1, 10000))
    nonce=gen_nonce()#nonce
    enc_nonce=session_key.encrypt(str(nonce).encode())
    file.sendto(enc_nonce,client_location)#based on needham schroeder algo
    nonce_from_client=file.recvfrom(4096)
    dec_nonce=session_key.decrypt(nonce_from_client[0])
    recv_nonce=dec_nonce.decode()
    if (int(recv_nonce)==nonce-1):#if nonces are correct client is verified
        print(client_name +" is verified ")
        file.sendto(str(1).encode(),client_location)#indicate to client that client is verified
        while (True):
            action_message=file.recvfrom(4096)#message containing the command that client wants to perform
            action_message=pickle.loads(action_message[0])
            if((session_key.decrypt(action_message[0])).decode()=='y'):#'y' indicates that client still wants to perform commands
                action=(session_key.decrypt(action_message[1])).decode()
                if (action=='pwd'):#client wants to know working directory
                    response=pwd(file_name)#function for pwd
                    response=session_key.encrypt(response.encode())
                    file.sendto(response,client_location)#send response to client
                if (action=='ls'):#client wants to know files stored in this file server
                    response=ls(file_name,my_files)#function for ls
                    response = session_key.encrypt(response.encode())
                    file.sendto(response, client_location)#send response to client
                if(action=='cat'):#client wants to read a file
                    file_to_read=(session_key.decrypt(action_message[2])).decode()
                    response = cat(file_to_read, my_files)#function for cat
                    response = session_key.encrypt(response.encode())
                    file.sendto(response, client_location)#send response to client
                if(action=='cp'):#client wants to copy a file
                    file_to_copy=(session_key.decrypt(action_message[2])).decode()
                    if file_to_copy not in my_files:#make sure file is not already present in file server
                        message=[file_name,action]
                        message=pickle.dumps(message)
                        file.sendto(message,kds)#ask kds info about other file server
                        other_server_info=file.recvfrom(4096)
                        other_server_info=pickle.loads(other_server_info[0])
                        dec_other_server_info=[]
                        for i in other_server_info:
                            dec_other_server_info.append((key_kds.decrypt(i)).decode())

                        if file_to_copy not in dec_other_server_info:#if file not present in other file server
                            response="This file is not in the other file server \n (Use add function to add this file)"+"\n"
                            message2=["Client has entered a file name not present in other file server, hence no file copied",my_files]
                            message2 = pickle.dumps(message2)
                            file.sendto(message2, kds)#indicate to kds that no file is copied
                            response = session_key.encrypt(response.encode())
                            file.sendto(response, client_location)#send response to client
                        else:#if file is present in other file server
                            response=cp(file_to_copy,my_files,file_name)#function for cp
                            message2=[response,my_files]
                            message2 = pickle.dumps(message2)
                            file.sendto(message2, kds)#indicate to kds that file is copied
                            response = session_key.encrypt(response.encode())
                            file.sendto(response, client_location)#send response to client
                    else:#file already present in file server
                        response="File with this name is already in this server "+"\n"
                        response = session_key.encrypt(response.encode())
                        file.sendto(response, client_location)#send response to client
                if (action=="add"):#client wants to add a file
                    file_to_add = (session_key.decrypt(action_message[2])).decode()#name of file to add
                    content_of_file = (session_key.decrypt(action_message[3])).decode()#content of file to add
                    if(file_to_add in my_files):#if file already present in file server
                        response="File with this name is already present inside the server, choose a different name "+"\n"
                        response = session_key.encrypt(response.encode())
                        file.sendto(response, client_location)#send response to file
                    else:#if file not present in file server
                        result=add(file_to_add,content_of_file,my_files,file_name)#function to add file
                        message = [file_name, action,result[0],result[1]]
                        message = pickle.dumps(message)
                        file.sendto(message, kds)#indicate to kds that file has been added to file server
                        response=result[0]
                        my_files=result[1]
                        response = session_key.encrypt(response.encode())
                        file.sendto(response, client_location)#send response to client
            elif((session_key.decrypt(action_message[0])).decode()=='n'):#n means that client is done accessing files from this file server and file server can service requests from ohter clients
                break

    else:#nonce not correct
        print("Client not verified as nonce not correct")
        file.sendto(str(0).encode(), client_location)#tell client that he is not verified



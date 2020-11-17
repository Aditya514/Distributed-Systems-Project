import socket #used to create sockets that can communicate with one another
import pickle #used to encode and decode data structres to be sent through UDP connection
import random #used to generate nonce
from cryptography.fernet import Fernet #used to generate key, encryption and decryption

ip='127.0.0.1' #local address
print("What is port number of this Key Distribution Server? : ")
my_port=int(input()) #port number entered by user

s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #create UDP connection
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #terminate any previously created socket which may be running
s.bind(('127.0.0.1',my_port)) #bind socket


fileserver_info={} #info about file servers
fileserver_count=0 #number of file servers
clientserver_info={} #info about clients
clientserver_count=0 #number of clients


#first file servers must register
#fs1
fileserver1_data=s.recvfrom(4096)
fileserver_info['fs1']=[(pickle.loads(fileserver1_data[0])),'tempkey',[]] #save port number of file server and set temporary values for key and files stored
kds_fs1=Fernet.generate_key() #generate a symmetric key for file server
fileserver_info['fs1'][1]=Fernet(kds_fs1) #activate key
print("File Server 1 is registered at  port number "+str(fileserver_info['fs1'][0]))
fileserver_count=fileserver_count+1 #increase count
s.sendto(kds_fs1,(ip,fileserver_info['fs1'][0]))#send key back
s.sendto(str(fileserver_count).encode(),(ip,fileserver_info['fs1'][0])) #send count to tell file server its number
info_files_stored_1=s.recvfrom(4096) #file server must register the files stored to kds
fileserver_info['fs1'][2]=pickle.loads(info_files_stored_1[0]) #kds saves info about files stored in each file server

#fs2
fileserver2_data=s.recvfrom(4096)
fileserver_info['fs2']=[(pickle.loads(fileserver2_data[0])),'tempkey',[]] #save port number of file server and set temporary values for key and files stored
kds_fs2=Fernet.generate_key() #generate a symmetric key for file server
fileserver_info['fs2'][1]=Fernet(kds_fs2) #activate key
print("File Server 2 is registered at  port number "+str(fileserver_info['fs2'][0]))
fileserver_count=fileserver_count+1 #increase count
s.sendto(kds_fs2,(ip,fileserver_info['fs2'][0]))#send key back
s.sendto(str(fileserver_count).encode(),(ip,fileserver_info['fs2'][0])) #send count to tell file server its number
info_files_stored_2=s.recvfrom(4096) #file server must register the files stored to kds
fileserver_info['fs2'][2]=pickle.loads(info_files_stored_2[0]) #kds saves info about files stored in each file server


#fileserver_info['fs2']=[4005,'garbage_key',["file 3.txt","file 4.txt"]]#garbage code inplace of second file server

print("\n")

#next clients must register
#cs1
client1_data=s.recvfrom(4096)
clientserver_info['cs1']=[(pickle.loads(client1_data[0])),'tempkey']#save client port number and temp value of key
kds_cs1=Fernet.generate_key()#generate symmetric key
clientserver_info['cs1'][1]=Fernet(kds_cs1)#store symmetric key for client
clientserver_count=clientserver_count+1#increase count
print("Client 1 is registered at port number "+str(clientserver_info['cs1'][0]))
s.sendto(kds_cs1,(ip,clientserver_info['cs1'][0]))#send key back
s.sendto(clientserver_info['cs1'][1].encrypt(str(clientserver_count).encode()),(ip,clientserver_info['cs1'][0])) #send client info to indicate which client number it is

#client 2
client2_data=s.recvfrom(4096)
clientserver_info['cs2']=[(pickle.loads(client2_data[0])),'tempkey']#save client port number and temp value of key
kds_cs2=Fernet.generate_key()#generate symmetric key
clientserver_info['cs2'][1]=Fernet(kds_cs2)#store symmetric key for client
clientserver_count=clientserver_count+1#increase count
print("Client 2 is registered at port number "+str(clientserver_info['cs2'][0]))
s.sendto(kds_cs2,(ip,clientserver_info['cs2'][0]))#send key back
s.sendto(clientserver_info['cs2'][1].encrypt(str(clientserver_count).encode()),(ip,clientserver_info['cs2'][0])) #send client info to indicate which client number it is

#client 3
client3_data=s.recvfrom(4096)
clientserver_info['cs3']=[(pickle.loads(client3_data[0])),'tempkey']#save client port number and temp value of key
kds_cs3=Fernet.generate_key()#generate symmetric key
clientserver_info['cs3'][1]=Fernet(kds_cs3)#store symmetric key for client
clientserver_count=clientserver_count+1#increase count
print("Client 3 is registered at port number "+str(clientserver_info['cs3'][0]))
s.sendto(kds_cs3,(ip,clientserver_info['cs3'][0]))#send key back
s.sendto(clientserver_info['cs3'][1].encrypt(str(clientserver_count).encode()),(ip,clientserver_info['cs3'][0])) #send client info to indicate which client number it is


file_info_to_client="" #intial message to client about files stored in each server
for i in fileserver_info:
    file_info_to_client=file_info_to_client+i+" contains : "
    for j in fileserver_info[i][2]:
        file_info_to_client=file_info_to_client+"\n\t" + j
    file_info_to_client = file_info_to_client+"\n"

print("\n")
#clientserver_count=clientserver_count+1#garbage test code
#clientserver_count=clientserver_count+1#garbage test code
for i in clientserver_info:
    s.sendto(clientserver_info[i][1].encrypt(str(clientserver_count).encode()),(ip,clientserver_info[i][0])) #once all three clients are registered we allow clients to access file servers
    s.sendto(clientserver_info[i][1].encrypt(str(file_info_to_client).encode()), (ip, clientserver_info[i][0]))#info about files are sent


while (True):
    message_info=s.recvfrom(1024)#message may be recieved from file server or client
    message=pickle.loads(message_info[0])
    if message[0] in clientserver_info:#when client wants to access file server
        print((message[0]) + " wants to access "  + (message[1])+"\n")
        session_key=Fernet.generate_key() #generate a seesion key between client and desired file server

        cs=message[0]#client name
        fs=message[1]#file name
        nonce=message[2]#nonce

        cp=clientserver_info[cs][0]#client port
        fp=fileserver_info[fs][0]#file port

        ck=clientserver_info[cs][1]#client key
        fk=fileserver_info[fs][1]#file key

        response=[] #response is built based on needham schroeder algo
        response.append(ck.encrypt(str(nonce).encode()))
        response.append(ck.encrypt(session_key))
        response.append(ck.encrypt(str(fp).encode()))
        response.append(ck.encrypt(fk.encrypt(session_key)))
        response.append(ck.encrypt(fk.encrypt(str(cp).encode())))
        response.append(ck.encrypt(fk.encrypt(cs.encode())))

        response=pickle.dumps(response)
        s.sendto(response,(ip,cp)) #send response
    elif message[0] in fileserver_info: #if file server is contacting kds
        fs_name=message[0] #file server name
        fs_loc=fileserver_info[fs_name][0]#file server location
        fs_key=fileserver_info[fs_name][1]#file server key
        if message[1]=='cp':#if message type is of cp command

            other_server_files=[] #file server wants info about files stored in other file server
            enc_other_server_files=[]
            for i in fileserver_info:
                if (i!=fs_name):
                    other_server_files=fileserver_info[i][2] #info about other file server
                else:
                    continue
            for k in other_server_files:
                enc_other_server_files.append(fs_key.encrypt(k.encode()))#encrypt this message
            enc_other_server_files=pickle.dumps(enc_other_server_files)
            s.sendto(enc_other_server_files,(ip,fs_loc)) #encrypted message sent
            message2=s.recvfrom(4096)
            message2= pickle.loads(message2[0])#response of file server
            if (message2[1]==fileserver_info[fs_name][2]):#no file is copied
                print(message2[0])
            else:#a file has been copied
                print(message2[0])
                fileserver_info[fs_name][2]=message2[1]#update file server info

        elif message[1]=='add':#if command type is add
            print(message[2])#print that file has been added
            fileserver_info[fs_name][2]=message[3]#update file server info
















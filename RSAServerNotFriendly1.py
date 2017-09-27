from Crypto.Cipher import *                   		   #Importing the Crypto library to do the encrytion
from Crypto.PublicKey import RSA
from Crypto.Hash import *
from Crypto.Signature import *
from socket import *                                #Importing socket in order to use the functions for socket programming 
from threading import Thread
import pickle

key = RSA.generate(1024) 
PubKey = key.publickey()
PubKeyFinal = pickle.dumps(PubKey)

sock = socket(AF_INET, SOCK_STREAM) #AF_INET is an address family that is used to designate the type of addresses that the socket can
                                    #communicate with.
				    #SOCK_STREAM provides sequenced, reliable, two-way, connection-based byte streams. An out-of-band
                                    #data transmission mechanism may be supported.

host = ''
port = 20900
sock.bind((host, port))                               #The server binds to the Host (i.e.the domain or the IPv4 address) and the port
sock.listen(2)                                       #Number of connection the server can receive

print "Server is running"
 	
def Encrypt(UnEncData,PubKeyOfClient):
	EncData = PubKeyOfClient.encrypt(UnEncData,32)
	EncDataFinal = pickle.dumps(EncData)
	return EncDataFinal

def Decrypt(EncData):
	EncDataTemp = pickle.loads(EncData)
	UnEncData = key.decrypt(EncDataTemp)
	return UnEncData

def Signature(UnsignData):
	HashMsg = SHA256.new(UnsignData)
	signer = PKCS1_v1_5.new(key)
	SignatureTemp = signer.sign(HashMsg)
	signature  = pickle.dumps(SignatureTemp)
	return signature

def SignatureVerify(DataReceived,SignatureTemp,PubKeyOfClient):
	HashMsg = SHA256.new(DataReceived)
	Signature = pickle.loads(SignatureTemp)
	verifier = PKCS1_v1_5.new(PubKeyOfClient)	
	FinalVerification = verifier.verify(HashMsg,Signature)
	return FinalVerification

def Server():
	conn, addr = sock.accept()                           #Sock.accept() is used to accept connection that is coming from the port
	print ("You are now connected with", addr)           #Displays the address of the client that the server is connected with 
	
	
	CommDec = raw_input("Do you want to send public key and proceed with this client(Y/N): ")
	if CommDec == "Y":
		conn.sendall(PubKeyFinal)
		PubKeyClientTemp = conn.recv(1024)		
		PubKeyClient = pickle.loads(PubKeyClientTemp)	
		print "Public Key of client received."
	else:
		return

	while True:                                          #Loop will run till the condition is true	
		RecvData = conn.recv(1024)                   #Data that is received from client 
		RecvSign = conn.recv(1024)
		RecvDataFinal = Decrypt(RecvData)
		VerifySignature = SignatureVerify(RecvDataFinal,RecvSign,PubKeyClient)
		if VerifySignature == True:
			print "Signature of author verified. :-)"		
			print "Message from: " + str(addr) + " >>> " + str(RecvDataFinal)         #Print the data received from the client
		else:
			print "Signature not verified. We might be hacked, closing connection...."
			break
		if RecvDataFinal == "B":
			conn1 = addr[1]+1
			addr1 = [addr[0],conn1]
			conn.shutdown(int(addr1))
		Dec = raw_input("Do you want to reply(T/F): ")       #Decision to be made by server if it wants to talk or not
		if Dec == "T":
			SendData = raw_input("Reply: ")             #Getting input from server to send the client
			SendData1 = "If you want to block other client reply with B\n" + SendData			
			SendDataFinal = Encrypt(SendData1,PubKeyClient)			
			conn.send(SendDataFinal)                       #Sends data to all the nodes the server is connected to
			MsgSignature = Signature(SendData1)			
			conn.send(MsgSignature)			
			print "Waiting for reply..."
		else: 
			Block = "You are blocked by server, the connection will be closed now. :)"			
			BlockFinal = Encrypt(Block,PubKeyClient)			
			conn.send(BlockFinal)
			BlockSignature = Signature(Block)
			conn.send(BlockSignature)			
			break
	
for i in range(2):
	Thread(target=Server).start()

sock.close()                                                  #Close connection
from Crypto.Cipher import *                   		   #Importing the Crypto library to do the encrytion
from Crypto.PublicKey import *
from Crypto.Hash import *
from Crypto.Signature import *
from socket import *                               #Importing socket in order to use the functions for socket programming  
import pickle

key = RSA.generate(1024) 
PubKey = key.publickey()
PubKeyFinal = pickle.dumps(PubKey)

host = ''
port = 20900
sock = socket(AF_INET, SOCK_STREAM) #AF_INET is an address family that is used to designate the type of addresses that the socket can
sock.connect((host, port))          #communicate with. SOCK_STREAM provides sequenced, reliable, two-way, connection-based byte streams. An out-of-band

PubKeyServerTemp = sock.recv(1024)
PubKeyServer = pickle.loads(PubKeyServerTemp)

def Encrypt(UnEncData):
	EncData = PubKeyServer.encrypt(UnEncData,32)
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

def SignatureVerify(DataReceived,SignatureTemp):	
	HashMsg = SHA256.new(DataReceived)
	Signature = pickle.loads(SignatureTemp)
	verifier = PKCS1_v1_5.new(PubKeyServer)	
	FinalVerification = verifier.verify(HashMsg,Signature)
	return FinalVerification

print "Public Key of server received. Sending your public key...."
sock.send(PubKeyFinal)

while True:                                        #Loop will run till the condition is true
	SendData = raw_input("Your Message: ")     #Message to be sent to the server
	SendDataFinal = Encrypt(SendData)
	sock.send(SendDataFinal)            #Sending the encrypted data to server
	print "Signing and sending your message"
	MsgSignature = Signature(SendData)
	sock.send(MsgSignature)	
	print "Waiting for reply..."               #Printing a message 
	RecvData = sock.recv(1024)                #Receiving message from the server	
	RecvSign = sock.recv(1024)
	if not RecvData and RecvSign:
		print "No message received from server, exiting...."
		break
	RecvDataFinal = Decrypt(RecvData)	
	VerifySignature = SignatureVerify(RecvDataFinal,RecvSign)
	if VerifySignature == True:
		print "Signature of author verfied. :-)"	
		print "Message Received from Server or other client: ", RecvDataFinal        #Printing the received message
	else:
		print "Signature not verified. :-(\nServer has been compromised. We are all hacked, exiting...."
		break
sock.close()                                       #Closing the session

import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

def pad(s):
    #return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    return s + (16 - len(s) % 16) * bytes([(16 - len(s) % 16)])
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# Represents integers from 0-255 in one byte
def toByte(s):
    #return chr(s).encode('utf-8')
    return bytes([s]) 
    #return bytes("\x{:02x}".format(s).encode('utf-8'))


# Returns 0-255 byte to integer
def fromByte(s):
    return ord(s)

def unreliableSend(packet, sock, user, errRate):
    if errRate < rd.randint(0,100):
        sock.sendto(packet, user)
        

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
server = (HOST, PORT)
status = "Start"

errRate = 10 # Average Error rate of the unreliable channel
TIMEOUT = 0.0001 # Timeout value
N = 1 # Go-back-N N

filename = b'crime-and-punishment.txt'
sessionKey = Random.get_random_bytes(32)                        # AES256 must be 32 bytes
secretWord = b"This word is secret"                         # The word that will be encrypted.  
AEScipher = AES.new(sessionKey, AES.MODE_ECB)                   # Create AES cipher with given key. 
phrase= AEScipher.encrypt(pad(secretWord))                  # The words that will be encrypted
                                                            # Must have length multiple of 16.

rsaKey = RSA.generate(1024)                                 # Generate RSA public and Private keys
private_key = rsaKey.export_key()                           # Export private key.
public_key = rsaKey.publickey().export_key('OpenSSH')       # Export public key. 
                                                            # Public key will be shared.
publicKey = RSA.import_key(public_key)                      # Convert RSA keys to be usable by 
privateKey = RSA.import_key(private_key)                    # Encryptors

rsaEncryptor = PKCS1_OAEP.new(publicKey)                    # RSA has separate decoder and encoders
rsaDecryptor = PKCS1_OAEP.new(privateKey)                   # Which have different keys

enc = rsaEncryptor.encrypt(secretWord)#.encode('utf-8'))
dec = rsaDecryptor.decrypt(enc)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     # Create UDP socket
sock.bind(server)
print("Server is running...")

while True:
        data, user = sock.recvfrom(1024)
        print('Received:', data)

        if data[0] == 0:                                        # Handshake
            packetLength = data[1]
            recievedFileName = data[2:2+len(filename)]
            if(recievedFileName != filename):
                sock.settimeout()
            recievedPublicKey = data[2+len(filename):2+packetLength]
            recievedPublicKey = RSA.import_key(recievedPublicKey)
            rsaEncryptor = PKCS1_OAEP.new(recievedPublicKey)
            pType = toByte(0)                                   # Packet type
            length = toByte(len(sessionKey))                    # Payload length
            packet = rsaEncryptor.encrypt(pType + length + sessionKey)
            # Packet to send
            unreliableSend(packet, sock, user, errRate)         # Send response to client

        elif data[0] == 1:                                      # ACK
            pass

        elif data[0] == 2:                                      # DATA
            pass

        elif data[0] == 3:                                      # FIN
            pass

        else:
            print("CLIENT SENT WRONG PACKET")

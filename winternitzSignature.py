'''Example implementation of Winternitz one-time signature scheme'''

import hashlib
import secrets

def fromBytesToBinary(bytes: bytes) -> list[str]:
    '''Converts bytes to list of 8bit binary strings.'''
    binaryList = []
    for byte in bytes:
        binaryList.append(bin(byte)[2:].zfill(8))
    return binaryList


def generateKeyPair() -> tuple[list[bytes], list[bytes]]:
    '''Generates (secretKey, publicKey) pair, where secretKey is secret and publicKey is public key.'''
    secretKey = []
    publicKey = []
    for i in range(32): # generates 32 random values for secret key and hashes every one of them 256 times to create public key
        secretKey.append(secrets.token_bytes(32))
        publicKeyElement = hashlib.sha256(secretKey[i]).digest()
        for j in range(1, 256):
            publicKeyElement = hashlib.sha256(publicKeyElement).digest()
        publicKey.append(publicKeyElement)
    return (secretKey, publicKey)

def sign(message: str, secretKey: list[bytes]) -> list[bytes]:
    '''Generates signature for the message.'''
    signature = []
    messageHash = fromBytesToBinary(hashlib.sha256(message.encode('utf-8')).digest()) # hashes the message and converts it to 8-bit binary strings
    for i in range(len(messageHash)): 
        N = int(messageHash[i], 2) # converts value N (8-bit string from message hash) from binary to decimal
        signatureElement = hashlib.sha256(secretKey[i]).digest() 
        for j in range(1, 256 - N): # creates the signature by hashing every element of secret key 256-N times
            signatureElement = hashlib.sha256(signatureElement).digest()
        signature.append(signatureElement)
    return signature

def verifySignature(signature: list[bytes], message: str, publicKey: list[bytes]) -> bool: 
    '''Returns True if signature is compatible with public key, False otherwise.'''
    messageHash = fromBytesToBinary(hashlib.sha256(message.encode('utf-8')).digest())
    for i in range(len(signature)):
        N = int(messageHash[i], 2)
        signatureElement = hashlib.sha256(signature[i]).digest()
        for j in range(1, N): # hashes every element in signature another N times and compares it with corresponding value in public key
            signatureElement = hashlib.sha256(signatureElement).digest()
        if signatureElement != publicKey[i]:
            return False
    return True

keypair = generateKeyPair()
message = "This is message"
signature = sign(message, keypair[0])
print(f"Signature verification: {verifySignature(signature, message, keypair[1])}")
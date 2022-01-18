'''Example implementation of Lamport one-time signature scheme.'''

import hashlib
import secrets

def fromStrToBinary(bytes: bytes) -> str:
    '''Converts bytes to binary bits string.'''
    binaryList = []
    for byte in bytes:
        binaryList.append(bin(byte)[2:].zfill(8))
    return ''.join(binaryList)

def generateKeyPair() -> tuple[list[bytes], list[bytes]]:
    '''Generates (secretKey, publicKey) pair, where secretKey is secret and publicKey is public key.'''
    secretKey = []
    publicKey = []
    for i in range(256):
        secretKey.append([secrets.token_bytes(32), secrets.token_bytes(32)])
        publicKey.append([hashlib.sha256(secretKey[i][0]).digest(), hashlib.sha256(secretKey[i][1]).digest()])
    return (secretKey, publicKey)

def sign(message: str, secretKey: str) -> list[bytes]:
    '''Generates signature for the message.'''
    signature = []
    messageHash = fromStrToBinary(hashlib.sha256(message.encode('utf-8')).digest())
    for i in range(256):
        signature.append(secretKey[i][int(messageHash[i])])
    return signature

def verifySignature(signature: list[bytes], message: str, publicKey: list[bytes]) -> bool: 
    '''Returns True if signature is compatible with public key, False otherwise.'''
    messageHash = fromStrToBinary(hashlib.sha256(message.encode('utf-8')).digest())
    for i in range(len(signature)):
        elementHash = hashlib.sha256(signature[i]).digest()
        if elementHash != publicKey[i][int(messageHash[i])]:
            return False
    return True


keypair = generateKeyPair()
message = "This is message"
signature = sign(message, keypair[0])
print(f"Signature verification: {verifySignature(signature, message, keypair[1])}")


'''Example implementation of Lamport one-time signature scheme.'''

import hashlib
import secrets

def fromBytesToBinary(bytesToConvert: bytes) -> str:
    '''Converts bytes to binary bits string.'''
    binaryList: list[bytes] = []
    for byte in bytesToConvert:
        binaryList.append(bin(byte)[2:].zfill(8))
    return ''.join(binaryList)

def generateKeyPair() -> tuple[list[list[bytes]], list[list[bytes]]]:
    '''Generates (secretKey, publicKey) pair, where secretKey is secret and publicKey is public key.'''
    secretKey: list[list[bytes]] = []
    publicKey: list[list[bytes]] = []
    for i in range(256): # generates 256 pairs of random bytes for secret key and hashes each of them to create public key
        secretKey.append([secrets.token_bytes(32), secrets.token_bytes(32)])
        publicKey.append([hashlib.sha256(secretKey[i][0]).digest(), hashlib.sha256(secretKey[i][1]).digest()])
    return (secretKey, publicKey)

def sign(message: str, secretKey: list[list[bytes]]) -> list[bytes]:
    '''Generates signature for the message.'''
    signature: list[bytes] = []
    messageHash = fromBytesToBinary(hashlib.sha256(message.encode('utf-8')).digest()) # hashes the message and converts the hash from bytes to binary bits
    for i in range(256): # creates signature by choosing first or second value from secret key, depending on the value of corresponding bit in message hash (for every pair)
        signature.append(secretKey[i][int(messageHash[i])])
    return signature

def verifySignature(signature: list[bytes], message: str, publicKey: list[list[bytes]]) -> bool: 
    '''Returns True if signature is compatible with public key, False otherwise.'''
    messageHash = fromBytesToBinary(hashlib.sha256(message.encode('utf-8')).digest()) # again hashes the message and converts the hash from bytes to binary bits
    for i in range(len(signature)): # hashes every element in signature and compares it with corresponding value in public key 
        elementHash = hashlib.sha256(signature[i]).digest()
        if elementHash != publicKey[i][int(messageHash[i])]:
            return False
    return True

if __name__ == "__main__":
    keypair = generateKeyPair()
    message = "This is message"
    signature = sign(message, keypair[0])
    print(f"Signature verification: {verifySignature(signature, message, keypair[1])}")


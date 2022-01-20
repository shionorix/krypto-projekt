from ntpath import join
import lamportSignature
import hashlib


class MerkleTree:
    messageCount: int = 0
    merklePrivateKey: list[list[bytes]] = []
    merklePublicKey: bytes = []
    lamportKeypairs: list[tuple[list[bytes], list[bytes]]] = []
    nodes: list[bytes] = []
    height: int
    def __init__(self, treeHeight: int = 3) -> None:
        """Generate Merkle Tree with OTS Lamport keys"""
        self.height = treeHeight
        for el in range(2**(treeHeight+1)-1): #create empty nodes
            self.nodes.append(b'')
        
        for keypairOffset in range(2**treeHeight): #generate hashes of public keys in leaves
            keypair = lamportSignature.generateKeyPair()
            self.lamportKeypairs.append(keypair)
            joined = [b''.join(el) for el in keypair[1]]
            joined = b''.join(joined)
            self.nodes[2**treeHeight + keypairOffset - 1] = hashlib.sha256(joined).digest()
            self.merklePrivateKey.append(keypair[0])


        for node in reversed(range(2**treeHeight - 1)):
            self.nodes[node] = hashlib.sha256(self.nodes[2*(node+1)-1] + self.nodes[2*(node+1)]).digest()


        self.merklePublicKey = self.nodes[0]
        return
        
    def getMerkleKeys(self):
        return (self.merklePrivateKey, self.merklePublicKey)

    def signMessage(self, message):
        if self.messageCount == 2**self.height:
            print(f'Error, keys exhausted. Instantiate a new tree!')
            return
        signature = lamportSignature.sign(message, self.merklePrivateKey[self.messageCount])
        

        path = []
        curr_node = 2**self.height-1 + self.messageCount
        for h in range(self.height):
            if curr_node % 2 == 0:
                path.append(self.nodes[curr_node-1])
            else:
                path.append(self.nodes[curr_node+1])
            curr_node = curr_node//2

        self.messageCount += 1
        return (self.messageCount-1, signature, self.lamportKeypairs[self.messageCount-1][1], path)


def verifyMerkle(numberOfMessage, lamportSign, lamportPublicKey, verificationPath, message, merklePublicKey):
    #step 1 - verify signature with Lamport scheme
    if lamportSignature.verifySignature(lamportSign,message,lamportPublicKey) != True:
        print(f'Lamport verify failed!')
        return False
    
    #step 2 - verify Lamport public key 
    joined = [b''.join(el) for el in lamportPublicKey]
    joined = b''.join(joined)
    keyDigest = hashlib.sha256(joined).digest()
    idx = numberOfMessage
    for node in verificationPath:
        if idx % 2 == 1:
            keyDigest = hashlib.sha256(node+keyDigest).digest()
        else:
            keyDigest = hashlib.sha256(keyDigest+node).digest()
        idx = idx //2  
    
    if keyDigest == merklePublicKey:
        return True
    return False

if __name__ == "__main__":
    tree = MerkleTree(3)
    merklePublic = tree.getMerkleKeys()[1]

    print(f'Merkle public key: {merklePublic.hex()}')

    message = "kokodzambo"
    signed = tree.signMessage(message)
    print(f'Message no. {signed[0]}')
    print(f'First pair of Lamport signature {signed[1][0].hex()}')
    print(f'Message verification path {[el.hex() for el in signed[3]]}')
    print(f'Message signature verification status: {verifyMerkle(signed[0],signed[1],signed[2],signed[3],message,merklePublic)}')
    print('-'*40)

    signed = tree.signMessage(message)
    print(f'Message no. {signed[0]}')
    print(f'First pair of Lamport signature {signed[1][0].hex()}')
    print(f'Message verification path {[el.hex() for el in signed[3]]}')
    print(f'Message signature verification status: {verifyMerkle(signed[0],signed[1],signed[2],signed[3],message,merklePublic)}')
    
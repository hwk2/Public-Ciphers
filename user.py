import random
from Crypto.Cipher import AES
from encryption import padding, unpadding

class User:
    def __init__(self, name):
        self.name = name
        self.priv_key = None
        self.pub_key = None
        #could be made a list for many pub keys later??
        self.other_user_pub_key = None
        self.secret = None

    def generate_priv_key(self, q):
        self.priv_key =random.randint(1, q-1)

    def generate_pub_key(self, alpha, q):
        if(self.priv_key is None):
            raise ValueError("Private key not generated yet.")
        else:
            val = pow(alpha, self.priv_key, q)
            self.pub_key = val
    
    def receive_pub_key(self, other_user_pub_key):
        self.other_user_pub_key = other_user_pub_key

    def secret_key(self, q):
        if(self.priv_key is None):
            raise ValueError("Private key not generated yet.")
        if(self.other_user_pub_key is None):
            raise ValueError("Other user's public key not received yet.")

        else:
            self.secret = pow(self.other_user_pub_key, self.priv_key, q).to_bytes(length=len(str(q)), byteorder='big')

    #key is sha_256 hash of secret key truncated to 16 bytes
    def encode(self, message, key, iv):
        # returns encoded message with hash generated from most recent secret key
        if(self.secret is None):
            raise ValueError("Secret key not generated yet.")
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        print(f"Encoding message: {message} with key: {key.hex()} and iv: {iv.hex()}")
        encrypted_message = cipher.encrypt(padding(message.encode()))
        return encrypted_message
    
    def decode(self, encrypted_message, key, iv):
        if(self.secret is None):
            raise ValueError("Secret key not generated yet.")
        print(f"Decoding message with secret key: {key.hex()} and iv: {iv.hex()}")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        paddedPlaintext = cipher.decrypt(encrypted_message)
        print(f"Padded Plaintext after decryption: {paddedPlaintext}")
        plaintext = unpadding(paddedPlaintext)
        return plaintext
            

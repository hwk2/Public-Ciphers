import random

class User:
    def __init__(self, name):
        self.name = name
        self.priv_key = None
        self.pub_key = None
        #could be made a list for many pub keys later??
        self.other_user_pub_key = None

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
            return pow(self.other_user_pub_key, self.priv_key, q)

# assume both A and B get same IV

q = 37
alpha = 5
# q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
# alpha = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

bob = User('Bob')
alice = User('Alice')

bob.generate_priv_key(q)
bob.generate_pub_key(alpha, q)

alice.generate_priv_key(q)
alice.generate_pub_key(alpha, q)

bob.receive_pub_key(alice.pub_key)
alice.receive_pub_key(bob.pub_key)

print(f"Bob's Private Key: {hex(bob.priv_key)}")
print(f"Bob's Public Key: {hex(bob.pub_key)}")

print(f"Alice's Private Key: {hex(alice.priv_key)}")
print(f"Alice's Public Key: {hex(alice.pub_key)}")

print(f"Bob received Alice's Public Key: {hex(bob.other_user_pub_key)}")
print(f"Alice received Bob's Public Key: {hex(alice.other_user_pub_key)}")

bob_secret = bob.secret_key(q)
alice_secret = alice.secret_key(q)

print(f"Bob's Secret Key: {hex(bob_secret)}")
print(f"Alice's Secret Key: {hex(alice_secret)}")
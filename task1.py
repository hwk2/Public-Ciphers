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
            power = pow(alpha, self.priv_key)
            self.pub_key = power % q
    
    def receive_pub_key(self, other_user_pub_key):
        self.other_user_pub_key = other_user_pub_key

    def secret_key(self, q):
        if(self.priv_key is None):
            raise ValueError("Private key not generated yet.")
        if(self.other_user_pub_key is None):
            raise ValueError("Other user's public key not received yet.")

        else:
            power = pow(self.other_user_pub_key, self.priv_key)
            return power % q

# assume both A and B get same IV

q = 37
alpha = 5

bob = User('Bob')
alice = User('Alice')

bob.generate_priv_key(q)
bob.generate_pub_key(alpha, q)

alice.generate_priv_key(q)
alice.generate_pub_key(alpha, q)

bob.receive_pub_key(alice.pub_key)
alice.receive_pub_key(bob.pub_key)

print(f"Bob's Private Key: {bob.priv_key}")
print(f"Bob's Public Key: {bob.pub_key}")

print(f"Alice's Private Key: {alice.priv_key}")
print(f"Alice's Public Key: {alice.pub_key}")

print(f"Bob received Alice's Public Key: {bob.other_user_pub_key}")
print(f"Alice received Bob's Public Key: {alice.other_user_pub_key}")

bob_secret = bob.secret_key(q)
alice_secret = alice.secret_key(q)

print(f"Bob's Secret Key: {bob_secret}")
print(f"Alice's Secret Key: {alice_secret}")
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

    def generate_pub_key(self, alpha, priv_key, q):
        power = pow(alpha, priv_key)
        self.pub_key = power % q
    
    def receive_pub_key(self, other_user_pub_key):
        self.other_user_pub_key = other_user_pub_key

# assume both A and B get same IV

q = 37
alpha = 5

bob = User('Bob')
alice = User('Alice')

bob.generate_priv_key(q)
bob.generate_pub_key(alpha, bob.priv_key, q)

alice.generate_priv_key(q)
alice.generate_pub_key(alpha, alice.priv_key, q)

bob.receive_pub_key(alice.pub_key)
alice.receive_pub_key(bob.pub_key)

print(f"Bob's Private Key: {bob.priv_key}")
print(f"Bob's Public Key: {bob.pub_key}")

print(f"Alice's Private Key: {alice.priv_key}")
print(f"Alice's Public Key: {alice.pub_key}")

print(f"Bob received Alice's Public Key: {bob.other_user_pub_key}")
print(f"Alice received Bob's Public Key: {alice.other_user_pub_key}")
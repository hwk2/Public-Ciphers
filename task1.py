import random

class User:
    def __init__(self, name):
        self.name = name
        self.priv_key = "default_private_key"
        self.pub_key = "default_public_key"

def generate_priv_key(q):
    return random.randint(1, q-1)

def generate_pub_key(alpha, priv_key, q):
    power = pow(alpha, priv_key)
    return power % q

# assume both A and B get same IV

q = 37
alpha = 5

bob = User('Bob')
alice = User('Alice')

bob.priv_key = generate_priv_key(q)
bob.pub_key = generate_pub_key(alpha, bob.priv_key, q)

alice.priv_key = generate_priv_key(q)
alice.pub_key = generate_pub_key(alpha, alice.priv_key, q)

print(f"Bob's Private Key: {bob.priv_key}")
print(f"Bob's Public Key: {bob.pub_key}")

print(f"Alice's Private Key: {alice.priv_key}")
print(f"Alice's Public Key: {alice.pub_key}")
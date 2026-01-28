from user import User
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# q = 37
# alpha = 5
q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
alpha = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

bob = User('Bob')
alice = User('Alice')
mallory = User('Mallory')

# Bob Key Generation 
bob.generate_priv_key(q)
bob.generate_pub_key(alpha, q)

print("Bob's Public Key:", hex(bob.pub_key))

# Alice Key Generation
alice.generate_priv_key(q)
alice.generate_pub_key(alpha, q)

print("Alice's Public Key:", hex(alice.pub_key))

# Mallory Key Generation
mallory.generate_priv_key(q)
mallory.generate_pub_key(alpha, q)

print("Mallory's Public Key:", hex(mallory.pub_key))
print("------------------------------")

# Mallory swaps out public keys for global value q instead
bob.receive_pub_key(q)
alice.receive_pub_key(q)

# Mallory knows that public keys have been swapped and does the same for themself
mallory.receive_pub_key(q)

print(f"Bob received Mallory's Public Key (q): {hex(bob.other_user_pub_key)}")
print(f"Alice received Mallory's Public Key (q): {hex(alice.other_user_pub_key)}")
print(f"Mallory self-set public key (q): {hex(mallory.other_user_pub_key)}")
print("------------------------------")

# All three calculate secret keys, since they all have q as the received public key, they will all generate the same secret key
# and it WILL ALWAYS be 0
bob.secret_key(q)
alice.secret_key(q)
mallory.secret_key(q)

print(f"Bob's Secret Key: {(bob.secret)}")
print(f"Alice's Secret Key: {(alice.secret)}")
print(f"Mallory's Secret Key: {(mallory.secret)}")
print("------------------------------")

# Bob Encodes Key
bob_sha256_hash = SHA256.new()
bob_sha256_hash.update(bob.secret)
bob_symm_key = bob_sha256_hash.digest()[:16]
print("Bob's Encoded Key:", bob_symm_key.hex())

# Alice Encodes Key
alice_sha256_hash = SHA256.new()
alice_sha256_hash.update(alice.secret)
alice_symm_key = alice_sha256_hash.digest()[:16]
print("Alice's Encoded Key:", alice_symm_key.hex())

# Mallory Encodes Key
mallory_sha256_hash_a = SHA256.new()
mallory_sha256_hash_a.update(mallory.secret)
mallory_symm_key = mallory_sha256_hash_a.digest()[:16]
print("Mallory's Encoded Key:", mallory_symm_key.hex())

#All three will get the same symmetric encoded key because their secret keys are the same
print("All three encoded keys are the same:", bob_symm_key.hex() == alice_symm_key.hex() == mallory_symm_key.hex())
print("------------------------------")

#All three will get the same symmetric encoded key because their secret keys are the same

bob_message = "Hello Alice!"
alice_message = "Hello Bob!"

# we assume they get the same IV, we will generate one randomly here
iv = get_random_bytes(16)
print("IV:", iv.hex())

# Bob and alice encode their messages with the predictable shared key
bob_encoded_message = bob.encode(bob_message, bob_symm_key, iv)
alice_encoded_message = alice.encode(alice_message, alice_symm_key, iv)

print(f"Bob's Encoded Message: {bob_encoded_message}")
print(f"Alice's Encoded Message: {alice_encoded_message}")
print("------------------------------")


# Mallory can decode both messages with their own key (this is goofy!!!!)
mallory_decoded_message_a = mallory.decode(alice_encoded_message, mallory_symm_key, iv)
mallory_decoded_message_b = mallory.decode(bob_encoded_message, mallory_symm_key, iv)

print(f"Bob's Decoded Message (by mallory): {mallory_decoded_message_b}")
print(f"Alice's Decoded Message (by mallory): {mallory_decoded_message_a}")
print("------------------------------")


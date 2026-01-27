from user import User
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
# assume both A and B get same IV

# q = 37
# alpha = 5
q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
alpha = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

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

bob.secret_key(q)
alice.secret_key(q)

print(f"Bob's Secret Key: {(bob.secret)}")
print(f"Alice's Secret Key: {(alice.secret)}")

bob_sha256_hash = SHA256.new()
bob_sha256_hash.update(bob.secret)
bob_symm_key = bob_sha256_hash.digest()[:16]
print("Bob's Encoded Key:", bob_symm_key.hex())

alice_sha256_hash = SHA256.new()
alice_sha256_hash.update(alice.secret)
alice_symm_key = alice_sha256_hash.digest()[:16]
print("Alice's Encoded Key:", alice_symm_key.hex())

bob_message = "Hello Alice!"
alice_message = "Hello Bob!"

# we assume they get the same IV, we will generate one randomly here
iv = get_random_bytes(16)
print("IV:", iv.hex())

bob_encoded_message = bob.encode(bob_message, bob_symm_key, iv)
alice_encoded_message = alice.encode(alice_message, alice_symm_key, iv)

print(f"Bob's Encoded Message: {bob_encoded_message}")
print(f"Alice's Encoded Message: {alice_encoded_message}")

bob_decoded_message = bob.decode(alice_encoded_message, bob_symm_key, iv)
alice_decoded_message = alice.decode(bob_encoded_message, alice_symm_key, iv)

print(f"Bob's Decoded Message: {bob_decoded_message}")
print(f"Alice's Decoded Message: {alice_decoded_message}")
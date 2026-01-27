from Crypto.Cipher import AES

# From Module 2 Task 1
def padding(data):
    l = AES.block_size - (len(data) % AES.block_size)
    padded_data = bytes([l]) * l
    return data + padded_data

# From Module 2 Task 2
def unpadding(data):
    data_size = len(data)
    padding_count = data[-1]
    return data[:-padding_count]

# From Module 2 Task 1
def encCBC(plaintext, cipher, iv):
    padded_plaintext = padding(plaintext.encode())
    print(f"Padded Plaintext: {padded_plaintext}")
    ciphertext = b""
    previous_block = iv
    for i in range(0, len(padded_plaintext), AES.block_size):
        block = padded_plaintext[i:i+AES.block_size]
        block_to_encrypt = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block = cipher.encrypt(block_to_encrypt)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    return ciphertext

def decCBC(ciphertext, cipher, iv):
    padded_plaintext = b""
    previous_block = iv
    for i in range(0, len(ciphertext), AES.block_size):
        block = ciphertext[i:i+AES.block_size]
        decrypted_block = cipher.decrypt(block)
        plaintext_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
        padded_plaintext += plaintext_block
        previous_block = block
    return padded_plaintext

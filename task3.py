from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

n_length = 2048
FLAG = True

def gen_key():
    # 1 - select p, q
    p = number.getPrime(n_length)
    q = number.getPrime(n_length)

    # 2
    n = p * q

    # 3
    phi = (p - 1) * (q - 1)

    # 4 Select e
    e = 65537

    # 5 Calculate d
    d = pow(e, -1, phi)

    # 6
    PU = (e, n)

    # 7
    PR = (d, n)

    return (PU, PR)

def encrypt(plaintext, PU):
    e = PU[0]
    n = PU[1]

    ciphertext = pow(plaintext, e, n)
    return ciphertext

def decrypt(ciphertext, PR):
    d = PR[0]
    n = PR[1]

    plaintext = pow(ciphertext, d, n)
    return plaintext

def main():
    PU, PR = gen_key()

    print("Part 1\n")
    if (FLAG):
        msg = "Hello!"
    else:
        msg = input("Please enter your message: ")

    print("Message: ", msg)

    num = int(msg.encode("ascii").hex(), 16)
    print("Message (int): ", num)

    encrypted = encrypt(num, PU)
    print("Encrypted: ", encrypted)

    decrypted = decrypt(encrypted, PR)
    print("Decrypted (int): ", decrypted)

    original = bytes.fromhex(hex(decrypted)[2:]).decode("ascii")
    print("Decrypted: ", original)


    print("----------------------")
    print("Part 2\n")

    # Step 0: Alice creates keys (PU, PR)
    PU_A, PR_A = gen_key()

    # Step 1: Alice sends (n, e) (PU) to Bob (& Mallory)

    # Step 2: Bob computes s. 

    PU_B, PR_B = gen_key()
    c = pow(PR_B[0], PU_A[0], PU_A[1])  # c = s^e mod n_A

    # Step 3: Bob sends c to Alice (Mallory Intercepts)
    # Step 3.5: Mallory computes c'
    PU_M, PR_M = gen_key()
    cPrime = c * pow(PR_M[0], PU_A[0], PU_A[1])

    # Step 4: Alice receives cPrime and calculates sPrime
    sPrime = pow(cPrime, PR_A[0], PR_A[1])

    # Step 5: Alice calculates k with SHA256(s)
    k = SHA256.new(str(sPrime).encode()).digest()

    # Step 6: Alice encrypts message with k and sends c_0
    msg = "Hi Bob!"
    cipher = AES.new(k, AES.MODE_CBC)
    c_0 = cipher.encrypt(pad(msg.encode(), AES.block_size))

    # Step 7: Mallory can decrypt message, and Bob cannot


    
    msg = "Hey, where are you?".encode("ascii")
    num = int(msg.hex(), 16)

    encrypted = encrypt(num, PU)

    #This message c' is sent off and Alice decrypts it
    decrypted = decrypt(encrypted, PR)

    #Both Mallory and Alice compute SHA256(num) and then Mallory can find c_0
    k = SHA256.new(msg).digest()

    # assume the iv is part of it
    iv = get_random_bytes(16)
    cipher = AES.new(k, AES.MODE_CBC, iv = iv)

    plaintext = "At the mall in Legends Comic Store".encode()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    transmission = iv + ciphertext

    #Mallory (with the key) can decrypt the message
    cipher = AES.new(k, AES.MODE_CBC, iv=iv)
    original = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    print(original)




main()

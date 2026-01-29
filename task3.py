from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import math

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

    # Step 2: Bob computes s
    s = random.randrange(2, PU_A[1])
    while math.gcd(s, PU_A[1]) != 1:
        s = random.randrange(2, PU_A[1])
    c = pow(s, PU_A[0], PU_A[1])

    # Step 3: Bob sends c to Alice (Mallory Intercepts)
    # Step 3.5: Mallory computes c'
    r = random.randrange(2, PU_A[1])
    while math.gcd(r, PU_A[1]) != 1:
        r = random.randrange(2, PU_A[1])
    cPrime = 0  #{0,1, k*n} where k is any integer

    # Step 4: Alice calculates s
    sPrime = pow(cPrime, PR_A[0], PR_A[1])

    # Step 5: Alice calculates k with SHA256(s)
    k = SHA256.new(str(sPrime).encode()).digest()

    # Step 6: Alice encrypts message with k and sends c_0
    msg = "Hi Bob!"
    print("Original:", msg)
    cipher = AES.new(k, AES.MODE_CBC)
    iv = cipher.iv
    c_0 = cipher.encrypt(pad(msg.encode(), AES.block_size))

    # Step 7: Mallory can decrypt message, and Bob cannot
    sPrime2 = cPrime

    kRecovered = SHA256.new(str(sPrime2).encode()).digest()
    cipher = AES.new(kRecovered, AES.MODE_CBC, iv=iv)
    mRecovered = unpad(cipher.decrypt(c_0), AES.block_size)
    print("Decrypted:", mRecovered.decode())


    print("\n-----------------------------")
    print("Part 3 -- Signature Malleability")

    #Alice computes each of these messages using the private key
    msg1 = "hello bob!".encode("ascii")
    msg2 = "How are you?".encode("ascii")
    num1 = int(msg1.hex(), 16)
    num2 = int(msg2.hex(), 16)

    sig1 = pow(num1, PR_A[0], PR_A[1])
    sig2 = pow(num2, PR_A[0], PR_A[1])

    #Mallory gets both the msgs and the signatures
    #Mallory creates a new message and a valid signature

    sig3 = (sig1 * sig2) % PU_A[1]
    num3 = (num1 * num2) % PU_A[1]

    print(pow(sig3, PU_A[0], PU_A[1]))
    print(num3)

main()

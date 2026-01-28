from Crypto.Util import number
from Crypto.Hash import SHA256

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

    msg = "Hey, where are you?"
    num = int(msg.encode("ascii").hex(), 16)

    encrypted = encrypt(num, PU)

    #This message c' is sent off and Alice decrypts it
    decrypted = decrypt(encrypted, PR)

    #Both Mallory and Alice compute SHA256(num)
    k = SHA256.new(num).digest()





main()

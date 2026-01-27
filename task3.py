from Crypto.Util import number

n_length = 2048

#1 - select p, q
p = number.getPrime(n_length)
q = number.getPrime(n_length)

#2
n = p * q

#3
phi = (p-1) * (q-1)

#4 Select e
e = 65537

#5 Calculate d
d = pow(e, -1, n)

#5.5 Prepare values for storing in the keys
stringD = str(d.encode("hex"))
stringN = str(n.encode("hex"))
stringE = str(e.encode("hex"))

#6
PU = e + n

#7
PR = d + n


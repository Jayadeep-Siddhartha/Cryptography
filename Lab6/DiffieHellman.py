
def diffieHellman(n, g, x, y):
    xa = g ** x % n
    ya = g ** y % n

    print('Intermediate keys : ', xa, ya)

    xb = ya ** x % n
    yb = xa ** y % n

    print('Shared secret key for A : ', xb)
    print('Shared secret key for B : ', yb)

n = 11
g = 8

x = int(input('Enter A\'s Private Key : ' ))
y = int(input('Enter B\'s Private Key : ' ))

# print(x, y)

diffieHellman(n, g, x, y)
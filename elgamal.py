import random
import math
import sys


def gcd(a, b):
    if b != 0:
        return gcd(b, a % b)
    return a


def mod(base, exp, modulus):
    return pow(base, exp, modulus)


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a / b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1


def encode(plain_text_string, NUM_BITS):
    byte_array = bytearray(plain_text_string, 'utf-16')
    z = []
    k = NUM_BITS // 8
    j = -1 * k
    for i in range(len(byte_array)):
        if i % k == 0:
            j += k
            z.append(0)

        z[j // k] += byte_array[i] * (2 ** (8 * (i % k)))

    return z


def decode(plain_text, NUM_BITS):
    bytes_array = []
    k = NUM_BITS // 8

    for num in plain_text:
        for i in range(k):
            temp = num

            for j in range(i + 1, k):
                temp = temp % (2 ** (8 * j))

            letter = temp // (2 ** (8 * i))
            bytes_array.append(letter)
            num = num - (letter * (2 ** (8 * i)))

    decodedText = bytearray(b for b in bytes_array).decode("utf-8", "ignore")

    return decodedText


def encrypt(p, g, x, h, NUM_BITS, plain_text_string):
    z = encode(plain_text_string, NUM_BITS)
    cipher_pairs = []
    for i in z:
        y = random.randint(0, p)
        c = mod(g, y, p)
        d = (i * mod(h, y, p)) % p
        cipher_pairs.append([c, d])

    encrypted_str = ""
    for pair in cipher_pairs:
        encrypted_str += str(pair[0]) + ' ' + str(pair[1]) + ' '

    return encrypted_str


def decrypt(keyp, keyx, cipher):
    plaintext = []
    cipher_array = cipher.split()

    for i in range(0, len(cipher_array), 2):
        c = int(cipher_array[i])
        d = int(cipher_array[i + 1])
        s = mod(c, keyx, keyp)
        plain = (d * mod(s, keyp - 2, keyp)) % keyp
        plaintext.append(plain)

    decrypted_text = decode(plaintext, 256)
    decrypted_text = "".join([ch for ch in decrypted_text if ch != '\x00'])

    return decrypted_text


def signature_generate(p, g, x, m):
    while 1:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    l = mul_inv(k, p - 1)
    s = l * (m - x * r) % (p - 1)
    return r, s


def signature_version(p, a, y, r, s, m):
    if r < 1 or r > p - 1:
        return False

    v1 = pow(y, r, p) % p * pow(r, s, p) % p
    v2 = pow(a, m, p)

    return v1 == v2


public_key_p = ''
public_key_g = ''
public_key_y = ''
sign_r = ''
sign_s = ''
msg = ''
private_key_p = ''
private_key_g = ''
private_key_x = ''
public_key_h = ''
message = ''
if __name__ == '__main__':
    arg = sys.argv[1]

    if arg == "-k":
        elgamar_file = open("elgamal.txt", "r")
        p = ''
        g = ''

        for row, line in enumerate(elgamar_file):
            if row == 0:
                p = int(line)
            elif row == 1:
                g = int(line)

        x = random.randint(1, p)
        h = mod(g, x, p)
        
        private_file = open("private.txt", "w")
        private_file.write('%s\n%s\n%s' % (str(p), str(g), str(x)))
        public_file = open("public.txt", "w")
        public_file.write('%s\n%s\n%s' % (str(p), str(g), str(h)))

    elif arg == "-e":
        public_file = open("public.txt", "r")

        for row, line in enumerate(public_file):
            if row == 2:
                public_key_h = int(line)

        private_file = open("private.txt", "r")

        for row, line in enumerate(private_file):
            if row == 0:
                private_key_p = int(line)
            if row == 1:
                private_key_g = int(line)
            if row == 2:
                private_key_x = int(line)

        NUM_BITS = 256
        
        plain_file = open("plain.txt", "r")
        for line in plain_file:
            message = str(line)

        cipher = encrypt(private_key_p, private_key_g, private_key_x, public_key_h, NUM_BITS, message)
        crypto_file = open("crypto.txt", "w")
        crypto_file.write('%s' % (str(cipher)))

    elif arg == "-d":
        cipher = ''
        private_file = open("private.txt", "r")
        for row, line in enumerate(private_file):
            if row == 0:
                private_key_p = int(line)
            if row == 2:
                private_key_x = int(line)

        crypto_file = open("crypto.txt", "r")

        for line in crypto_file:
            cipher = str(line)

        decrypted = u''.join((decrypt(private_key_p, private_key_x, cipher))).encode('utf-8').strip()
        decrypted = str(decrypted, 'utf-8')
        edecrypt = open("decrypt.txt", "w")
        edecrypt.write('%s' % decrypted)

    elif arg == "-s":
        private_file = open("private.txt", "r")
        for row, line in enumerate(private_file):
            if row == 0:
                private_key_p = int(line)
            if row == 1:
                private_key_g = int(line)
            if row == 2:
                private_key_x = int(line)

        message = open("message.txt", "r")
        for line in message:
            msg = int(line)
        rr, ss = signature_generate(private_key_p, private_key_g, private_key_x, msg)
        signature_file = open("signature.txt", "w")
        signature_file.write('%s\n%s' % (str(rr), int(ss)))

    elif arg == "-v":
        signature_file = open("signature.txt", "r")
        for row, line in enumerate(signature_file):
            if row == 0: 
                sign_r = int(line)
            if row == 1: 
                sign_s = int(line)
                
        message = open("message.txt", "r")
        
        for line in message:
            msg = int(line)
            
        public_file = open("public.txt", "r")
        for row, line in enumerate(public_file):
            if row == 0: 
                public_key_p = int(line)
            if row == 1: 
                public_key_g = int(line)
            if row == 2: 
                public_key_y = int(line)
                
        is_signature_valid = signature_version(public_key_p, public_key_g, public_key_y, sign_r, sign_s, msg)
        verify = open("verify.txt", "w")
        verify.write('Verification: %s' % is_signature_valid)
        print("Verification: %s" % is_signature_valid)

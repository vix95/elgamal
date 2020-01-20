import random
import math
import sys


def gcd(a, b):
    if b != 0:
        return gcd(b, a % b)

    return a


def mod(base, exp, modulus):
    return pow(base, exp, modulus)


def mul(a, b):
    b0 = b
    x0, x1 = 0, 1

    if b == 1:
        return 1

    while a > 1:
        q = a / b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0

    if x1 < 0:
        x1 += b0

    return x1


def decode(plain_text):
    bytes_arr = []
    k = NUM_BITS // 8

    for num in plain_text:
        for i in range(k):
            temp = num

            for j in range(i + 1, k):
                temp = temp % (2 ** (8 * j))

            letter = temp // (2 ** (8 * i))
            bytes_arr.append(letter)
            num = num - (letter * (2 ** (8 * i)))

    decrypted_str = bytearray(b for b in bytes_arr).decode("utf-8", "ignore")

    return decrypted_str


def encode(plain_text_string):
    byte_arr = bytearray(plain_text_string, 'utf-8')
    arr = []
    k = NUM_BITS // 8
    j = -1 * k

    for i in range(len(byte_arr)):
        if i % k == 0:
            j += k
            arr.append(0)

        arr[j // k] += byte_arr[i] * (2 ** (8 * (i % k)))

    return arr


def encrypt(p_val, g_val, h_val, plain_text_string):
    z = encode(plain_text_string)
    cipher_pairs = []
    for i in z:
        y = random.randint(0, p_val)
        c = mod(g_val, y, p_val)
        d = (i * mod(h_val, y, p_val)) % p_val
        cipher_pairs.append([c, d])

    encrypted_str = ""
    for pair in cipher_pairs:
        encrypted_str += str(pair[0]) + ' ' + str(pair[1]) + ' '

    return encrypted_str


def decrypt(key_p, key_x, msg_str):
    plaintext = []
    cipher_array = msg_str.split()

    for i in range(0, len(cipher_array), 2):
        c = int(cipher_array[i])
        d = int(cipher_array[i + 1])
        s = mod(c, key_x, key_p)
        plain = (d * mod(s, key_p - 2, key_p)) % key_p
        plaintext.append(plain)

    decrypted_text = decode(plaintext)
    decrypted_text = "".join([ch for ch in decrypted_text if ch != '\x00'])

    return decrypted_text


def signature_generate(p_val, g_val, x_val, m):
    while 1:
        k = random.randint(1, p_val - 2)
        if gcd(k, p_val - 1) == 1:
            break
    r_val = pow(g_val, k, p_val)
    l_val = mul(k, p_val - 1)
    s_val = l_val * (m - x_val * r_val) % (p_val - 1)
    return r_val, s_val


def signature_version(p_val, a, y, r, s, m):
    if r < 1 or r > p_val - 1:
        return False

    v1 = pow(y, r, p_val) % p_val * pow(r, s, p_val) % p_val
    v2 = pow(a, m, p_val)

    return v1 == v2


NUM_BITS = 256
if __name__ == '__main__':
    private_key_p = None
    private_key_g = None
    private_key_x = None
    public_key_p = None
    public_key_g = None
    public_key_y = None
    public_key_h = None

    sign_r = None
    sign_s = None
    msg = None
    message = None

    arg = sys.argv[1]

    if arg == "-k":  # read p and g and generate keys
        p = 0
        g = 0

        with open("elgamal.txt", "r") as f:
            for row, line in enumerate(f):
                if row == 0:
                    p = int(line)
                elif row == 1:
                    g = int(line)

        x = random.randint(1, p)
        h = mod(g, x, p)

        with open("private.txt", "w") as f:
            f.write('%s\n%s\n%s' % (str(p), str(g), str(x)))

        with open("public.txt", "w") as f:
            f.write('%s\n%s\n%s' % (str(p), str(g), str(h)))

    elif arg == "-e":  # read public key and message to encrypt and save encrypted message
        public_file = open("public.txt", "r")

        for row, line in enumerate(public_file):
            if row == 2:
                public_key_h = int(line)

        with open("private.txt", "r") as f:
            for row, line in enumerate(f):
                if row == 0:
                    private_key_p = int(line)
                if row == 1:
                    private_key_g = int(line)
                if row == 2:
                    private_key_x = int(line)

        with open("plain.txt", "r") as f:
            for line in f:
                message = str(line)

        cipher = encrypt(private_key_p, private_key_g, public_key_h, message)

        with open("crypto.txt", "w") as f:
            f.write('%s' % (str(cipher)))

    elif arg == "-d":  # read private key and decrypt message
        cipher = ''
        with open("private.txt", "r") as f:
            for row, line in enumerate(f):
                if row == 0:
                    private_key_p = int(line)
                if row == 2:
                    private_key_x = int(line)

        crypto_file = open("crypto.txt", "r")

        for line in crypto_file:
            cipher = str(line)

        decrypted = u''.join((decrypt(private_key_p, private_key_x, cipher))).encode('utf-8').strip()
        decrypted = str(decrypted, 'utf-8')

        with open("decrypt.txt", "w") as f:
            f.write('%s' % decrypted)

    elif arg == "-s":  # read private key and do signature
        with open("private.txt", "r") as f:
            for row, line in enumerate(f):
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

    elif arg == "-v":  # read public key and verify signature
        with open("signature.txt", "r") as f:
            for row, line in enumerate(f):
                if row == 0:
                    sign_r = int(line)
                if row == 1:
                    sign_s = int(line)

        with open("message.txt", "r") as f:
            for line in f:
                msg = int(line)

        with open("public.txt", "r") as f:
            for row, line in enumerate(f):
                if row == 0:
                    public_key_p = int(line)
                if row == 1:
                    public_key_g = int(line)
                if row == 2:
                    public_key_y = int(line)

        is_signature_valid = signature_version(public_key_p, public_key_g, public_key_y, sign_r, sign_s, msg)

        with open("verify.txt", "w") as f:
            f.write('Verification: %s' % is_signature_valid)

        print("Verification: %s" % is_signature_valid)

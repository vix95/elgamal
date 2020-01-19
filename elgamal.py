import sys
import math
import random


def mod(base, exp, modulus):
    return pow(base, exp, modulus)


def encode(plan_text):
    byte_array = bytearray(plan_text, 'utf-16')
    z = []
    k = INT_BITS // 8
    j = -1 * k
    for x in range(len(byte_array)):
        if x % k == 0:
            j += k
            z.append(0)
        z[j // k] += byte_array[i] * (2 ** (8 * (x % k)))
    return z


def encrypt(p_num, g_num, h_num, plan_text):
    z = encode(plan_text)
    cipher_pairs = []
    for x in z:
        y = random.randint(0, p_num)
        c = mod(g_num, y, p_num)
        d = (x * mod(h_num, y, p_num)) % p_num
        cipher_pairs.append([c, d])

    encrypted_msg = ""
    for pair in cipher_pairs:
        encrypted_msg += str(pair[0]) + ' ' + str(pair[1]) + ' '

    return encrypted_msg


def decode(plain_msg):
    bytes_array = []
    k = INT_BITS // 8
    for num in plain_msg:
        for x in range(k):
            temp = num

            for j in range(x + 1, k):
                temp = temp % (2 ** (8 * j))

            letter = temp // (2 ** (8 * x))
            bytes_array.append(letter)
            num = num - (letter * (2 ** (8 * x)))

    decoded_msg = bytearray(b for b in bytes_array).decode("utf-8", "ignore")
    return decoded_msg


def decrypt(key_p, key_n, encrypted):
    plaintext = []
    encrypted_arr = encrypted.split()
    for x in range(0, len(encrypted_arr), 2):
        c = int(encrypted_arr[x])
        d = int(encrypted_arr[x + 1])
        s = mod(c, key_n, key_p)
        plain = (d * mod(s, key_p - 2, key_p)) % key_p
        plaintext.append(plain)

    decrypted_message = decode(plaintext)
    decrypted_message = "".join([ch for ch in decrypted_message if ch != '\x00'])
    return decrypted_message


def gcd(a, b):
    if b != 0:
        return gcd(b, a % b)
    return a


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1

    if b == 1:
        return 1

    while a > 1:
        q_num = a / b
        a, b = b, a % b
        x0, x1 = x1 - q_num * x0, x0

    if x1 < 0:
        x1 += b0

    return x1


def generate_signature(key_p, key_g, n_num, message):
    while 1:
        k = random.randint(1, key_p - 2)
        if gcd(k, key_p - 1) == 1:
            break

    r_side = pow(key_g, k, key_p)
    l_side = mul_inv(k, key_p - 1)
    s = l_side * (message - n_num * r_side) % (key_p - 1)
    return r_side, s


def check_signature(key_p, key_g, key_n, r_num, s_num, message):
    if r_num < 1 or r_num > key_p - 1:
        return False
    compare_1 = pow(key_n, r_num, key_p) % key_p * pow(r_num, s_num, key_p) % key_p
    compare_2 = pow(key_g, message, key_p)
    return compare_1 == compare_2


INT_BITS = 256
if __name__ == '__main__':
    arg = sys.argv[1]
    p = ''
    g = ''
    key_private_p = ''
    key_private_g = ''
    key_private_n = ''
    key_public = ''

    if arg == "-k":  # read p and g from file and generate keys
        file = open("elgamal.txt")
        for i, line in enumerate(file):
            if i == 0:
                p = int(line.rstrip())
            elif i == 1:
                g = int(line.rstrip())
        file.close()

        rand = random.randint(1, p)
        n = mod(g, rand, p)

        file_private = open("private.txt", "w")
        file_private.write('%s\n' % (str(p)))  # p
        file_private.write('%s\n' % (str(g)))  # g
        file_private.write('%s\n' % (str(rand)))  # rand
        file_private.close()

        file_public = open("public.txt", "w")
        file_public.write('%s\n' % (str(p)))  # p
        file_public.write('%s\n' % (str(g)))  # g
        file_public.write('%s\n' % (str(n)))  # n
        file_public.close()

    elif arg == "-e":  # read public key, plain message and save encrypted message
        file_public = open("public.txt", "r")
        for i, line in enumerate(file_public):
            if i == 2:
                key_public = int(line.rstrip())

        file_public.close()

        file_private = open("private.txt", "r")
        for i, line in enumerate(file_private):
            if i == 0:
                key_private_p = int(line.rstrip())
            if i == 1:
                key_private_g = int(line.rstrip())
            if i == 2:
                key_private_n = int(line.rstrip())

        file_private.close()

        file_plain = open("plain.txt", "r")
        msg = ''
        for line in file_plain:
            msg = str(line)

        cipher = encrypt(key_private_p, key_private_g, key_public, msg)
        encrypt_file = open("crypto.txt", "w")
        encrypt_file.write('%s' % (str(cipher)))

    elif arg == "-d":  # read private key and encrypted message and try to decrypt
        file_private = open("private.txt", "r")
        for i, line in enumerate(file_private):
            if i == 0:
                key_private_p = int(line.rstrip())
            if i == 2:
                key_private_n = int(line.rstrip())

        file_private.close()

        decrypted_msg = ''
        crypto_file = open("crypto.txt", "r")
        for line in crypto_file:
            decrypted_msg = str(line.rstrip())

        decrypted = u''.join((decrypt(key_private_p, key_private_n, decrypted_msg))).encode('utf-8').strip()
        decrypted = str(decrypted, 'utf-8')

        file_decrypt = open("decrypt.txt", "w")
        file_decrypt.write('%s' % decrypted)
        file_decrypt.close()

    elif arg == "-s":  # read private key, message and produce signature
        file_private = open("private.txt", "r")
        for i, line in enumerate(file_private):
            if i == 0:
                key_private_p = int(line.rstrip())
            if i == 1:
                key_private_g = int(line.rstrip())
            if i == 2:
                key_private_n = int(line.rstrip())

        file_private.close()

        file_message = open("message.txt", "r")
        msg = ''
        for line in file_message:
            msg = int(line.rstrip())

        file_message.close()

        q, w = generate_signature(key_private_p, key_private_g, key_private_n, msg)
        file_signature = open("signature.txt", "w")
        file_signature.write('%d\n' % (int(q)))
        file_signature.write('%d' % (int(w)))

    elif arg == "-v":  # verify signature
        signature_r = ''
        signature_s = ''
        file_signature = open("signature.txt", "r")
        for i, line in enumerate(file_signature):
            if i == 0:
                signature_r = int(line.rstrip())
            if i == 1:
                signature_s = int(line.rstrip())

        file_signature.close()

        msg = ''
        file_message = open("message.txt", "r")
        for line in file_message:
            msg = int(line.rstrip())

        file_message.close()

        key_public_p = ''
        key_public_g = ''
        key_public_n = ''
        file_public = open("public.txt", "r")
        for i, line in enumerate(file_public):
            if i == 0:
                key_public_p = int(line.rstrip())
            if i == 1:
                key_public_g = int(line.rstrip())
            if i == 2:
                key_public_n = int(line.rstrip())

        file_public.close()

        is_valid = check_signature(key_public_p, key_public_g, key_public_n, signature_r, signature_r, msg)
        file_verify = open("verify.txt", "w")
        file_verify.write('Verify: %s' % is_valid)
        print("Verify: %s" % is_valid)

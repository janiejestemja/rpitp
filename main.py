import sys
import socket

from time import sleep
from random import randint

from hashlib import sha256
from hmac import new as hmac_new

import elliptic_curves as ec
from aes_ctr_rspy import AesCtrSecret as ACS

def main():
    secp256k1, G = get_curve_r()

    ipvfour = input("IPv4: ")
    if ipvfour == "":
        ipvfour = "127.0.0.100"

    portnumber = input("Port: ")

    if portnumber == "":
        portnumber = 12345

    else:
        try:
            portnumber = int(portnumber)
        except TypeError:
            sys.exit("Portnumber not a number")

    if sys.argv[1] == "h":
        server(ipvfour, portnumber, secp256k1, G)

    elif sys.argv[1] == "c":
        client(ipvfour, portnumber, secp256k1, G)

def server(ipvfour, portnumber, curve, G):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ipvfour, portnumber))
    server_socket.listen()
    print("Server is listening...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")

        a_pri, a_pub = gen_keypair(curve, G)

        # Send public variables to client
        client_socket.send(bytes(str(a_pub.x).encode()))
        sleep(0.01)
        client_socket.send(bytes(str(a_pub.y).encode()))
        sleep(0.01)
        client_socket.send(bytes(str("exit()").encode()))
        print("Public variables send")

        # Recieve public variable from client
        pub_vars = []
        while True:
            message = client_socket.recv(1024)
            if message.decode() == "exit()":
                break
            else:
                pub_vars.append(message.decode())

        b_pub = ec.ECPoint(curve, int(pub_vars[0]), int(pub_vars[1]))
        shared_secret = hkdf_extract_expand(b_pub.multiply(a_pri))

        key = bytearray([shared_secret[i] for i in range(0, 32)])
        nonce = bytearray([shared_secret[-i] for i in range(1, 9)])
        secret = ACS(key, nonce)

        data = bytearray("This is a little longer test message than usual, to check if CTR is working as intended...".encode())

        ciphertext = secret.encrypt(data)
        client_socket.send(bytes(ciphertext))

        print("Closing connection")
        client_socket.close()
        server_socket.close()
        break

def client(ipvfour : str, portnumber: int, curve, G):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ipvfour, portnumber))

    # Recieve public variable from server
    pub_vars = []
    while True:
        message = client_socket.recv(1024)
        if message.decode() == "exit()":
            break
        else:
            pub_vars.append(message.decode())

    a_pub = ec.ECPoint(curve, int(pub_vars[0]), int(pub_vars[1]))
    b_pri, b_pub = gen_keypair(curve, G)

    # Send public variables to server
    client_socket.send(bytes(str(b_pub.x).encode()))
    sleep(0.01)
    client_socket.send(bytes(str(b_pub.y).encode()))
    sleep(0.01)
    client_socket.send(bytes(str("exit()").encode()))
    print("Public variables send") 

    shared_secret = hkdf_extract_expand(a_pub.multiply(b_pri))
    key = bytearray([shared_secret[i] for i in range(0, 32)])
    nonce = bytearray([shared_secret[-i] for i in range(1, 9)])
    secret = ACS(key, nonce)

    ciphertext = client_socket.recv(1024)
    plaintext = secret.encrypt(bytearray(ciphertext))
    print(plaintext)

    print("Closing connection")
    client_socket.close()

def get_curve_k():
    secp256k1 = ec.EllipticCurve(
        0, 
        7, 
        0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
    )

    G = ec.ECPoint(
        secp256k1, 
        0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798, 
        0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
    )
    return (secp256k1, G)


def get_curve_r():
    secp256r1 = ec.EllipticCurve(
        0xffffffff_00000001_00000000_00000000_00000000_ffffffff_ffffffff_fffffffc,
        0x5ac635d8_aa3a93e7_b3ebbd55_769886bc_651d06b0_cc53b0f6_3bce3c3e_27d2604b,
        0xffffffff_00000001_00000000_00000000_00000000_ffffffff_ffffffff_ffffffff
    )

    G = ec.ECPoint(
        secp256r1, 
        0x6b17d1f2_e12c4247_f8bce6e5_63a440f2_77037d81_2deb33a0_f4a13945_d898c296, 
        0x4fe342e2_fe1a7f9b_8ee7eb4a_7c0f9e16_2bce3357_6b315ece_cbb64068_37bf51f5
    )
    return (secp256r1, G)

def gen_keypair(curve, G):
    pri_key = randint(1, curve.p - 1)
    pub_key = G.multiply(pri_key)

    # Recursion if pub_key is point at inf
    if pub_key == ec.ECPoint(curve, None, None):
        return gen_keypair(curve, G)

    return pri_key, pub_key

def hkdf_extract_expand(shared_secret, salt=b"some_salt", info=b"AES key"):
    prk = hmac_new(salt, shared_secret.x.to_bytes(32, "big"), sha256).digest()
    okm = hmac_new(prk, info + b"\x01", sha256).digest()
    return [bit for bit in okm[:32]]

if __name__ == "__main__":
    main()

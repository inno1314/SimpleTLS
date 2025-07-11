from pwn import process
import base64
import json

from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Random.random import getrandbits
from Crypto.Util.Padding import pad, unpad


p = process("./server.py")

p.recvuntil(b"p: ")
p_hex = p.recvline().strip().decode()
print(f"[DEBUG] p: {p_hex}")
p_value = int(p_hex, 16)

p.recvuntil(b"g: ")
g_hex = p.recvline().strip().decode()
print(f"[DEBUG] g: {g_hex}")
g_value = int(g_hex, 16)

p.recvuntil(b"root key d: ")
root_d_hex = p.recvline().strip().decode()
print(f"[DEBUG] root key d: {root_d_hex}")
root_d_value = int(root_d_hex, 16)

p.recvuntil(b"root certificate (b64): ")
root_cert_b64 = p.recvline().strip().decode()
print(f"[DEBUG] root certificate b64: {root_cert_b64}")

p.recvuntil(b"root certificate signature (b64): ")
root_cert_sig_b64 = p.recvline().strip().decode()
print(f"[DEBUG] root certificate signature b64: {root_cert_sig_b64}")

p.recvuntil(b"name: ")
name = p.recvline().strip().decode()
print(f"[DEBUG] name: {name}")

p.recvuntil(b"A: ")
A_hex = p.recvline().strip().decode()
print(f"[DEBUG] A: {A_hex}")
A = int(A_hex, 16)


b = getrandbits(2048)
B = pow(g_value, b, p_value)
print(f"[DEBUG] Sending B: {hex(B)}")
p.sendline(hex(B).encode())

shared_secret = pow(A, b, p_value)
key = SHA256Hash(shared_secret.to_bytes(256, "little")).digest()[:16]
cipher_encrypt = AES.new(key, AES.MODE_CBC, iv=b"\0" * 16)
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=b"\0" * 16)

user_key = RSA.generate(1024)
user_certificate = {
    "name": name,
    "key": {
        "e": user_key.e,
        "n": user_key.n,
    },
    "signer": "root",
}

root_certificate = base64.b64decode(root_cert_b64).decode()
root_certificate = json.loads(root_certificate)
root_key = root_certificate["key"]
root_key_n = root_key["n"]

user_certificate_data = json.dumps(user_certificate).encode()
user_certificate_hash = SHA256Hash(user_certificate_data).digest()
user_certificate_signature = pow(
    int.from_bytes(user_certificate_hash, "little"), root_d_value, root_key_n
).to_bytes(256, "little")


user_signature_data = (
    name.encode().ljust(256, b"\0")
    + A.to_bytes(256, "little")
    + B.to_bytes(256, "little")
)
user_signature_hash = SHA256Hash(user_signature_data).digest()
user_signature = pow(
    int.from_bytes(user_signature_hash, "little"), user_key.d, user_key.n
).to_bytes(256, "little")


def aes_encrypt_and_show(label, data):
    encrypted = cipher_encrypt.encrypt(pad(data, AES.block_size))
    print(f"[DEBUG] Sending {label}: {base64.b64encode(encrypted).decode()}")
    p.sendline(base64.b64encode(encrypted))


aes_encrypt_and_show("user certificate", user_certificate_data)
aes_encrypt_and_show("user certificate signature", user_certificate_signature)
aes_encrypt_and_show("user signature", user_signature)

p.recvuntil(b"secret ciphertext (b64): ")
ciphertext_b64 = p.recvline().strip().decode()
print(f"[DEBUG] secret ciphertext b64: {ciphertext_b64}")

ciphertext = base64.b64decode(ciphertext_b64)
flag = unpad(cipher_decrypt.decrypt(ciphertext), AES.block_size)
print(f"[+] FLAG: {flag.decode()}")

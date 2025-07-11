# 🔐 Упрощенная модель TLS handshake
Данный мини-проект был реализован при решении CTF задачи на платформе [pwn.college](https://pwn.college/intro-to-cybersecurity/cryptography/) и реализует на практике полученные знания из разделов криптографии и веб безопасности:
- обмен ключами Diffie–Hellman Key Exchange (DHKE)
- RSA подпись сертификатов
- AES для шифрования данных после установки защищенного канала передачи информации.

Задача (и цель проекта) состоит в создании упрощенной реализации ключевых этапов TLS рукопожатия.
## Техническая реализация.
Процесс создания защищенного канала связи можно разбить на следующие этапы: обмен параметрами `DHKE`, передача и проверка `RSA` сигнатур, верефикация пользовательской подписи, обмен зашифрованными данными (`AES`).
Пройдем по каждому пункту.
### 1. Diffie–Hellman Key Exchange
Первое, что нужно сделать для создания защищенного канала — согласовать общий секретный ключ. Описанный ниже алгоритм DHKE позволяет сделать это в условиях открытого канала связи.
1. Стороны согласуют два числа, которые могут быть известны всем: большое простое число p и основание g.
```python
p = int.from_bytes(
    bytes.fromhex(
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
        "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
    ),
    "big",
)
g = 2

show_hex("p", p)
show_hex("g", g)
```
2. Каждая сторона выбирает секретно число, которое нельзя никому сообщать: `a = getrandbits(2048)`.
3. Стороны считают открытые значения по формуле `A=g^a mod p` для передачи друг другу: `A = pow(g, a, p)`.
4. После обмена этими значениями, каждая сторона вычисляет секретный ключ: `s = B^a mod p = A^b mod p`.

Благодаря математической проблеме, известной под названием "проблема дискретного логарифмирования", третьи лица не смогут вычислить секрет, даже зная значения параметров `A`, `B`, `p` и `g`.
Когда обмен завершен, стороны могут использовать общий секретный ключ для шифрования передаваемой информации.
### 2. RSA-подписи и сертификаты
Данная процедура предназначена для проверки подлинности: клиенту нужно убедиться в том, что сервер действительно тот, за кого себя выдает, и наоборот.
В данной модели роль удостоверения играют простые структуры с ключем и именем, подписанные с помощью `RSA`:
- У нас есть корневой ключ `root_key = RSA.generate(2048)`, которому стороны доверяют по умолчанию
- Клиент и сервер создают сертификаты с именем и публичным ключом:
```python
root_certificate = {
    "name": "root",
    "key": {
        "e": root_key.e,
        "n": root_key.n,
    },
    "signer": "root",
}
```
- Сертификат подписывается корневым ключом:
```python
user_certificate = {
    "name": name,
    "key": {
        "e": user_key.e,
        "n": user_key.n,
    },
    "signer": "root",
}

user_certificate_data = json.dumps(user_certificate).encode()
user_certificate_hash = SHA256Hash(user_certificate_data).digest()
user_certificate_signature = pow(
    int.from_bytes(user_certificate_hash, "little"), root_d_value, root_key_n
).to_bytes(256, "little")
```
- Сервер проводит проверку подлинности:
```python
user_signer_key = root_trusted_certificates[user_signer]["key"]
user_certificate_hash = SHA256Hash(user_certificate_data).digest()
user_certificate_check = pow(
    int.from_bytes(user_certificate_signature, "little"),
    user_signer_key["e"],
    user_signer_key["n"],
).to_bytes(256, "little")[: len(user_certificate_hash)]

if user_certificate_check != user_certificate_hash:
    print("Untrusted user certificate: invalid signature", file=sys.stderr)
    exit(1)
```
### 3. Верификация пользователя
- Клиент также подписывает уникальные для сессии данные (name + A + B), чтобы доказать, что он действительно владеет приватным ключом, соответствующим открытому из сертификата:
```python
user_signature_data = (
    name.encode().ljust(256, b"\0")
    + A.to_bytes(256, "little")
    + B.to_bytes(256, "little")
)
user_signature_hash = SHA256Hash(user_signature_data).digest()
user_signature = pow(
    int.from_bytes(user_signature_hash, "little"), user_key.d, user_key.n
).to_bytes(256, "little")
```
Проверка на стороне сервера:
```python
user_signature_data = (
    name.encode().ljust(256, b"\0")
    + A.to_bytes(256, "little")
    + B.to_bytes(256, "little")
)
user_signature_hash = SHA256Hash(user_signature_data).digest()
user_signature_check = pow(
    int.from_bytes(user_signature, "little"), user_key["e"], user_key["n"]
).to_bytes(256, "little")[: len(user_signature_hash)]

if user_signature_check != user_signature_hash:
    print("Untrusted user: invalid signature", file=sys.stderr)
    exit(1)
```
Данная процедура необходима для защит от атак типа MITM, и в реальных имплементациях она выглядит гораздо сложнее 
(сертификаты содержат много дополнительных полей и проверок, вместо самоподписанного root ключа обычно используется иерархия доверенных центров сертификации,
применяются более сложные схемы подписи и хэширования). Все упрощения нужны для понимания основных принципов.
### 4. Обмен зашифрованными данными
Когда стороны удостоверились в том, с кем они коммуницируют, и договорились об общем секретном ключе шифрования, происходит передача данных.
Т.к. данный проект является решением CTF задачи, передаваемые данные есть ни что иное, как флаг:
```python
ciphertext = cipher_encrypt.encrypt(pad(flag.encode(), cipher_encrypt.block_size))
show_b64("secret ciphertext", ciphertext)
```
Программа, имитирующая клиента, автоматизирует получение и расшифровку данных:
```python
p.recvuntil(b"secret ciphertext (b64): ")
ciphertext_b64 = p.recvline().strip().decode()
print(f"[DEBUG] secret ciphertext b64: {ciphertext_b64}")

ciphertext = base64.b64decode(ciphertext_b64)
flag = unpad(cipher_decrypt.decrypt(ciphertext), AES.block_size)
print(f"[+] FLAG: {flag.decode()}")
```
## Заключение
Данная упрощенная модель должна упростить понимание основных принципов TLS и разобраться с тем, для чего нужны те или иные механизмы защищенных соединений и какие задачи они решают.
Для запуска локально:
```bash
git clone https://github.com/inno1314/SimpleTLS.git

cd SimpleTLS/
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt

chmod +x ./server.py
python3 client.py
```


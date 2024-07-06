from pygost.gost28147_mac import MAC
from pygost.gost3410 import CURVES
from schemas import *
from export import getPrimaryKey
from os import path as p
from base64 import standard_b64encode
from textwrap import fill
from getpass import getpass
from uuid import uuid4
import sys

# OID -> Curve, upd 06.07.24
curves = {
    "1.2.643.7.1.2.1.1.1": CURVES["id-tc26-gost-3410-12-256-paramSetA"],
    "1.2.643.7.1.2.1.1.2": CURVES["id-tc26-gost-3410-12-256-paramSetB"],
    "1.2.643.7.1.2.1.1.3": CURVES["id-tc26-gost-3410-12-256-paramSetC"],
    "1.2.643.7.1.2.1.1.4": CURVES["id-tc26-gost-3410-12-256-paramSetD"],
    "1.2.643.7.1.2.1.2.0": CURVES["id-tc26-gost-3410-12-512-paramSetTest"],
    "1.2.643.7.1.2.1.2.1": CURVES["id-tc26-gost-3410-12-512-paramSetA"],
    "1.2.643.7.1.2.1.2.2": CURVES["id-tc26-gost-3410-12-512-paramSetB"],
    "1.2.643.7.1.2.1.2.3": CURVES["id-tc26-gost-3410-12-512-paramSetC"],
    "1.2.643.2.2.35.0": CURVES["id-GostR3410-2001-TestParamSet"],
    "1.2.643.2.2.35.1": CURVES["id-tc26-gost-3410-12-256-paramSetB"], # CryptoPro Paramset A
    "1.2.643.2.2.35.2": CURVES["id-tc26-gost-3410-12-256-paramSetC"], # CryptoPro Paramset B
    "1.2.643.2.2.35.3": CURVES["id-tc26-gost-3410-12-256-paramSetD"], # CryptoPro Paramset C
    "1.2.643.2.2.36.0": CURVES["id-GostR3410-2001-CryptoPro-XchA-ParamSet"],
    "1.2.643.2.2.36.1": CURVES["id-GostR3410-2001-CryptoPro-XchB-ParamSet"],
    "1.2.643.2.9.1.8.1": CURVES["GostR3410_2001_ParamSet_cc"]
}

print("ckey by li0ard")
passw = getpass("Введите пароль: ")

path = sys.argv[1]

header = open(p.join(path, "header.key"), "rb")
header, _ = GostKeyContainer().decode(header.read())

mask = open(p.join(path, "masks.key"), "rb")
mask, _ = GostKeyMask().decode(mask.read())

primary = open(p.join(path, "primary.key"), "rb")
primary, _ = GostKeyPrimary().decode(primary.read())
primary = primary["value"]

curve = header["keyContainerContent"]["primaryPrivateKeyParameters"]["privateKeyAlgorithm"]["parameters"]["curve"]
curve = curves[str(curve)]

key, pub = getPrimaryKey(
    bytes(mask["salt"]),
    bytes(mask["mask"]),
    bytes(primary),
    passw.encode("utf-8"),
    curve
)
fp = pub[:8]
if fp == bytes(header["keyContainerContent"]["primaryFP"]):
    algo = ObjectIdentifier("1.2.643.7.1.1.1.1")
    if ObjectIdentifier("1.2.643.7.1.1.6.2") == header["keyContainerContent"]["primaryPrivateKeyParameters"]["privateKeyAlgorithm"]["dh"]:
        algo = ObjectIdentifier("1.2.643.7.1.1.1.2") # 512
    algorithm = KeyAlgorithm()
    algorithm["dh"] = algo
    algorithm["parameters"] = header["keyContainerContent"]["primaryPrivateKeyParameters"]["privateKeyAlgorithm"]["parameters"]

    pkey = PrivateKey()
    pkey["version"] = Integer(0)
    pkey["params"] = algorithm
    pkey["key"] = OctetString(key)
    
    encodedKey = '-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n'.format(fill(standard_b64encode(pkey.encode()).decode("ascii"), 64))
    uid = str(uuid4())
    f = open("exported_" + uid + ".pem", "w")
    f.write(encodedKey)
    f.close()
    print("Сохранено в exported_" + uid + ".pem")
else:
    print("Ошибка валидации публичного ключа\nВозможно вы ввели неправильный пароль.")
    print("Ожидается: " + bytes(header["keyContainerContent"]["primaryFP"]).hex())
    print("Получено: " + fp.hex())
    print("Если вы считаете что так быть не должно - создайте issue")
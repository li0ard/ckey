from cpkdf import derive
from pygost.gost28147 import ecb_decrypt
from pygost.gost3410 import prv_unmarshal, public_key, pub_marshal
from pygost.gost34112012256 import GOST34112012256
from pygost.utils import bytes2long, long2bytes, modinvert

def getPrimaryKey(salt: bytes, mask: bytes, prim: bytes, passphrase: bytes, curve):
    primaryKey = ecb_decrypt(
        key=derive(GOST34112012256, passphrase, salt),
        data=prim,
        sbox="id-tc26-gost-28147-param-Z"
    )
    # Реверсим primaryKey
    primaryKey = primaryKey[::-1]
    pk = bytes2long(primaryKey)

    # Реверсим маску
    mask = mask[::-1]
    m = bytes2long(mask)
    raw = long2bytes((pk * modinvert(m, curve.q)).__mod__(curve.q))
    raw = raw[::-1]
    pub = pub_marshal(public_key(curve, prv_unmarshal(raw)))
    return (raw, pub)
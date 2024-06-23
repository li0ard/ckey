from cpkdf import derive
from pygost.gost28147 import ecb_decrypt
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from pygost.gost3410 import prv_unmarshal, public_key, pub_marshal

def reverse(d):
    d = d[::-1]
    return d

def getPrimaryKey(salt, mask, prim, passphrase, curve):
    primaryKey = ecb_decrypt(
        key=derive(salt, passphrase),
        data=prim,
        sbox="id-tc26-gost-28147-param-Z"
    )
    # Reverse primary key
    primaryKey = reverse(primaryKey)
    pk = bytes_to_long(primaryKey)

    # Reverse mask
    mask = reverse(mask)
    m = bytes_to_long(mask)
    raw = long_to_bytes((pk * inverse(m, curve.q)).__mod__(curve.q))
    raw = reverse(raw)
    pub = pub_marshal(public_key(curve, prv_unmarshal(raw)))
    return (raw, pub)
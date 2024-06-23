from pyderasn import Sequence, OctetString, Any, IA5String, ObjectIdentifier, tag_ctxc, tag_ctxp, BitString, Integer
from pygost.asn1schemas.x509 import Certificate

gost2001_dh = ObjectIdentifier("1.2.643.2.2.98")
gost2012_256_dh = ObjectIdentifier("1.2.643.7.1.1.6.1")
gost2012_512_dh = ObjectIdentifier("1.2.643.7.1.1.6.2")

class KeyAlgorithmParameters(Sequence):
    schema = (
        ("curve", ObjectIdentifier()),
        ("digest", ObjectIdentifier())
    )

class KeyAlgorithm(Sequence):
    schema = (
        ("dh", ObjectIdentifier()),
        ("parameters", KeyAlgorithmParameters())
    )

class PrivateKey(Sequence):
    schema = (
        ("version", Integer(0)),
		("params", KeyAlgorithm()),
		("key", OctetString())
    )

class GostKeyContainerContentAttributes(BitString):
    schema = (
        ("kccaSoftPassword", 0),
        ("kccaReservePrimary", 1),
        ("kccaPrimaryKeyAbsent", 2),
        ("kccaFKCShared", 3)
    )

class GostPrivateKeyAttributes(BitString):
    schema = (
        ("pkaExportable", 0),
        ("pkaUserProtect", 1),
        ("pkaExchange", 2),
        ("pkaEphemeral", 3),
        ("pkaNonCachable", 4),
        ("pkaDhAllowed", 5)
    )

class GostPrivateKeyParameters(Sequence):
    schema = (
        ("attributes", GostPrivateKeyAttributes()),
        ("privateKeyAlgorithm", KeyAlgorithm(impl=tag_ctxc(0)))
    )

class CertificateLink(Sequence):
    schema = (
        ("path", IA5String()),
        ("hmac", OctetString()),
    )

class GostKeyContainerContent(Sequence):
    schema = (
        ("containerAlgoritmIdentifier", ObjectIdentifier(optional=True, expl=tag_ctxc(0))),
        ("containerName", IA5String(optional=True)),
        ("attributes", GostKeyContainerContentAttributes()),
        ("primaryPrivateKeyParameters", GostPrivateKeyParameters()),
        ("hmacPassword", OctetString(optional=True, impl=tag_ctxp(2))),
        ("secondaryEncryptedPrivateKey", Any(optional=True, expl=tag_ctxc(3))),
        ("secondaryPrivateKeyParameters", GostPrivateKeyParameters(optional=True, impl=tag_ctxc(4))),
        ("primaryCertificate", Certificate(optional=True, expl=tag_ctxp(5))),
        ("secondaryCertificate", Certificate(optional=True, expl=tag_ctxp(6))),
        ("encryptionContainerName", IA5String(optional=True, impl=tag_ctxp(7))),
        ("primaryCertificateLink", CertificateLink(optional=True, impl=tag_ctxc(8))),
        ("secondaryCertificateLink", CertificateLink(optional=True, impl=tag_ctxc(9))),
        ("primaryFP", OctetString(impl=tag_ctxp(10))),
        ("secondaryFP", OctetString(optional=True, impl=tag_ctxp(11))),
        ("passwordPolicy", ObjectIdentifier(optional=True)),
        ("containerSecurityLevel", Integer(optional=True)),
        ("extensions", Any(optional=True, expl=tag_ctxc(12))),
        ("secondaryEncryptionContainerName", IA5String(optional=True, impl=tag_ctxp(13)))
    )

class GostKeyContainer(Sequence):
    schema = (
        ("keyContainerContent", GostKeyContainerContent()),
        ("hmacKeyContainerContent", OctetString())
    )

class GostKeyMask(Sequence):
    schema = (
        ("mask", OctetString()),
        ("salt", OctetString()),
        ("hmac", OctetString())
    )

class GostKeyPrimary(Sequence):
    schema = (
        ("value", OctetString()),
    )
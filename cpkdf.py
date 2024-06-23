from pygost.gost34112012256 import GOST34112012256

def derive(salt: bytes, passphrase: bytes):
    hasher = GOST34112012256()
    bs = hasher.digest_size * 2
    if len(passphrase) * 4 > 1024:
        raise ValueError("passphrase cannot be longer than 256 symbols")

    # Делаем пароль в 4 раза больше. Зачем? Я не знаю
    pin = bytearray(b"\x00" * len(passphrase) * 4)
    for i in range(len(passphrase)):
        pin[i*4] = passphrase[i]

    # Первый этап - получаем хэш соли и пароля (если задан)
    hasher.update(salt)
    if len(passphrase) != 0:
        hasher.update(pin)
    hash = hasher.digest()
    hasher = GOST34112012256()

    # Создание основого и вторичных массивов
    c = bytearray("DENEFH028.760246785.IUEFHWUIO.EF", "utf-8")
    if len(c) < bs:
        c = c.ljust(bs, b'\x00')
    m0 = bytearray(64)
    m1 = bytearray(64)

    # Устанавливаем кол-во итераций
    iterations = 2
    if len(passphrase) != 0:
        iterations = 2000

    # Второй этап - мульти-итеративное хэширование
    for j in range(iterations):
        for i in range(len(c)):
            m0[i] = c[i] ^ 0x36
            m1[i] = c[i] ^ 0x5C

        hasher.update(m0)
        hasher.update(hash)
        hasher.update(m1)
        hasher.update(hash)

        c = hasher.digest()
        if len(c) < bs:
            c = c.ljust(bs, b'\x00')
        hasher = GOST34112012256()

    # Третий этап - получаем хэш соли и вторичных массивов
    for i in range(len(c)):
        m0[i] = c[i] ^ 0x36
        m1[i] = c[i] ^ 0x5C

    hasher.update(m0[0:32])
    hasher.update(salt)
    hasher.update(m1[0:32])
    if len(passphrase) != 0:
        hasher.update(pin)

    c = hasher.digest()
    if len(c) < bs:
        c = c.ljust(bs, b'\x00')
    hasher = GOST34112012256()
    hasher.update(c[0:32])
    return hasher.digest()

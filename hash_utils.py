import hashlib
import bcrypt


def hash_string(text: str, algorithm: str) -> str:
    if algorithm.lower() == 'md5':
        return hashlib.md5(text.encode()).hexdigest()

    elif algorithm.lower() == 'sha1':
        return hashlib.sha1(text.encode()).hexdigest()

    elif algorithm.lower() == 'sha256':
        return hashlib.sha256(text.encode()).hexdigest()

    elif algorithm.lower() == 'sha512':
        return hashlib.sha512(text.encode()).hexdigest()

    elif algorithm.lower() == 'bcrypt':
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(text.encode(), salt)
        return hashed.decode()

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def verify_bcrypt(plain_text: str, hashed_bcrypt: str) -> bool:
    try:
        return bcrypt.checkpw(plain_text.encode(), hashed_bcrypt.encode())
    except Exception:
        return False

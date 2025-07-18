import requests
import hashlib

API_KEY = "44beab5b2f77f9de"
API_EMAIL = "barryjen@acceleratedschoolsop.org"


def dictionary_attack(hash_value: str, algorithm: str, dict_file="rockyou.txt") -> str | None:
    try:
        with open(dict_file, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"⚠️ Dictionary file '{dict_file}' not found.")
        return None

    for pwd in passwords:
        if algorithm == 'md5':
            hashed = hashlib.md5(pwd.encode()).hexdigest()
        elif algorithm == 'sha1':
            hashed = hashlib.sha1(pwd.encode()).hexdigest()
        elif algorithm == 'sha256':
            hashed = hashlib.sha256(pwd.encode()).hexdigest()
        elif algorithm == 'sha512':
            hashed = hashlib.sha512(pwd.encode()).hexdigest()
        else:
            continue

        if hashed == hash_value.lower():
            return pwd

    return None


def lookup_hash(hash_value: str) -> str | None:
    hash_len = len(hash_value)
    if hash_len == 32:
        hash_type = 'md5'
    elif hash_len == 40:
        hash_type = 'sha1'
    elif hash_len == 64:
        hash_type = 'sha256'
    else:
        print("⚠️ Unsupported hash length for lookup.")
        return None

    url = "https://md5decrypt.net/Api/api.php"
    params = {
        'hash': hash_value,
        'hash_type': hash_type,
        'email': API_EMAIL,
        'code': API_KEY,
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            plaintext = response.text.strip()
            if plaintext and plaintext != 'CODE DOES NOT EXIST':
                return plaintext
        else:
            print(f"⚠️ API request failed with status {response.status_code}")
    except Exception as e:
        print(f"⚠️ API request error: {e}")

    print("🔎 Trying local dictionary attack fallback...")
    return dictionary_attack(hash_value, hash_type)

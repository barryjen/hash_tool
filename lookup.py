import requests
import hashlib
import itertools
import string

API_KEY = "44beab5b2f77f9de"
API_EMAIL = "barryjen@acceleratedschoolsop.org"

cache = {}

def load_dictionary_cache(algorithm: str, dict_file="wordlists/rockyou.txt"):
    global cache
    if algorithm in cache:
        return cache[algorithm]

    try:
        with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"⚠️ Dictionary file '{dict_file}' not found.")
        return {}

    hash_map = {}
    for pwd in passwords:
        if algorithm == 'md5':
            h = hashlib.md5(pwd.encode()).hexdigest()
        elif algorithm == 'sha1':
            h = hashlib.sha1(pwd.encode()).hexdigest()
        elif algorithm == 'sha256':
            h = hashlib.sha256(pwd.encode()).hexdigest()
        elif algorithm == 'sha512':
            h = hashlib.sha512(pwd.encode()).hexdigest()
        else:
            continue

        hash_map[h] = pwd

    cache[algorithm] = hash_map
    return hash_map


def dictionary_attack(hash_value: str, algorithm: str, dict_file="rockyou.txt") -> str | None:
    hash_map = load_dictionary_cache(algorithm, dict_file)
    return hash_map.get(hash_value.lower())


def lookup_hash(hash_value: str) -> str | None:
    hash_len = len(hash_value)
    if hash_len == 32:
        hash_type = 'md5'
    elif hash_len == 40:
        hash_type = 'sha1'
    elif hash_len == 64:
        hash_type = 'sha256'
    else:
        print("⚠️ Unsupported hash length for API lookup.")
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

    return None


def brute_force_attack(hash_value: str, algorithm: str, max_length: int = 4) -> str | None:
    print(f"⏳ Starting brute-force attack with max length = {max_length}...")

    charset = string.ascii_lowercase  # Extend if needed

    def get_hash(s):
        s = s.encode()
        if algorithm == 'md5':
            return hashlib.md5(s).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(s).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(s).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(s).hexdigest()
        return None

    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            guess = ''.join(attempt)
            if get_hash(guess) == hash_value:
                return guess

    return None
from hash_utils import hash_string, verify_bcrypt
from lookup import dictionary_attack, lookup_hash

HASHES_FILE = "saved_hashes.txt"


def save_hash(text, algorithm, hashed_value):
    with open(HASHES_FILE, "a", encoding="utf-8") as f:
        f.write(f"{algorithm}:{text}:{hashed_value}\n")
    print(f"✅ Hash saved to {HASHES_FILE}")


def load_hashes():
    try:
        with open(HASHES_FILE, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            if not lines:
                print("⚠️ No hashes saved yet.")
                return
            print("Saved hashes:")
            for i, line in enumerate(lines, 1):
                algo, plain, hashed = line.split(":", 2)
                print(f"{i}. [{algo}] {plain} -> {hashed}")
    except FileNotFoundError:
        print("⚠️ No saved hashes file found.")


def generate_hash():
    text = input("Enter the text to hash: ")

    print("\nChoose a hash algorithm:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-256")
    print("4. SHA-512")
    print("5. bcrypt (for passwords)")

    choice = input("Enter choice [1-5]: ")

    algorithm_map = {
        "1": "md5",
        "2": "sha1",
        "3": "sha256",
        "4": "sha512",
        "5": "bcrypt"
    }

    algorithm = algorithm_map.get(choice)

    if algorithm is None:
        print("❌ Invalid choice.")
        return

    try:
        hashed = hash_string(text, algorithm)
        print(f"\n✅ Hashed result using {algorithm.upper()}:\n{hashed}")
        save = input("Do you want to save this hash? (y/n): ").lower()
        if save == "y":
            save_hash(text, algorithm, hashed)
    except Exception as e:
        print(f"⚠️ Error: {e}")


def verify_bcrypt_hash():
    plain = input("Enter the original text (e.g. password): ")
    hashed = input("Enter the bcrypt hash to verify: ")

    if verify_bcrypt(plain, hashed):
        print("✅ Match! The password is correct.")
    else:
        print("❌ No match. Incorrect password or invalid hash.")


def lookup_hash_cli():
    hash_value = input("Enter the hash to lookup: ")
    print("Supported algorithms: md5, sha1, sha256, sha512")
    algorithm = input("Enter hash algorithm: ").lower()

    # Try API lookup first
    result = lookup_hash(hash_value)
    if result:
        print(f"✅ Found plaintext via API: {result}")
        return

    # If API lookup fails, do dictionary attack using given algorithm
    print("🔎 Trying local dictionary attack fallback...")
    result = dictionary_attack(hash_value, algorithm)

    if result:
        print(f"✅ Found plaintext via dictionary attack: {result}")
    else:
        print("❌ Plaintext not found.")


def main():
    print("🔐 Hash Tool")
    print("===================")

    print("1. Generate Hash")
    print("2. Verify bcrypt Hash")
    print("3. Lookup Hash")
    print("4. View Saved Hashes")

    action = input("Choose an action [1-4]: ")

    if action == "1":
        generate_hash()
    elif action == "2":
        verify_bcrypt_hash()
    elif action == "3":
        lookup_hash_cli()
    elif action == "4":
        load_hashes()
    else:
        print("❌ Invalid option.")


if __name__ == "__main__":
    main()

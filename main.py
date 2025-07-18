from hash_utils import hash_string, verify_bcrypt
from lookup import lookup_hash


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
    result = lookup_hash(hash_value)

    if result:
        print(f"✅ Found plaintext: {result}")
    else:
        print("❌ Plaintext not found in database.")


def main():
    print("🔐 Hash Tool")
    print("===================")

    print("1. Generate Hash")
    print("2. Verify bcrypt Hash")
    print("3. Lookup Hash")

    action = input("Choose an action [1-3]: ")

    if action == "1":
        generate_hash()
    elif action == "2":
        verify_bcrypt_hash()
    elif action == "3":
        lookup_hash_cli()
    else:
        print("❌ Invalid option.")


if __name__ == "__main__":
    main()

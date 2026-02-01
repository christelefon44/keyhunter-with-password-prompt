#!/usr/bin/env python3
"""
Bitcoin key hunter + basic encrypted wallet support
Scans raw files/devices for:
- Unencrypted private keys (ASN.1 style prefix)
- Bitcoin Core encrypted keys (mkey + ckey patterns)
Asks for passphrase and attempts decryption if found.
"""

import binascii
import hashlib
import hmac
import os
import sys
import getpass
import struct
from typing import Set, Optional, List, Dict, Tuple

# ───────────────────────────────────────────────
#  Constants
# ───────────────────────────────────────────────

READ_CHUNK_SIZE = 10 * 1024 * 1024      # 10 MiB chunks
OVERLAP_MARGIN  = 200                       # bytes to overlap chunks

# Magic patterns from Bitcoin Core wallet.dat (Berkeley DB format)
MKEY_PATTERN    = b'\x09\x00\x01\x04mkey'   # type prefix for master key
CKEY_PATTERN    = b'\x27\x00\x01\x04ckey'   # type prefix for encrypted key
ASN1_PRIV_PREFIX = b'\x01\x30\x82\x01\x13\x02\x01\x01\x04\x20'  # old DER-ish prefix

# Base58 alphabet
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58_BASE = len(B58)

# Bitcoin mainnet private key version byte
PRIVKEY_VERSION = b'\x80'


# ───────────────────────────────────────────────
#  Base58 + Checksum
# ───────────────────────────────────────────────

def b58encode(v: bytes) -> str:
    """Encode bytes to Bitcoin Base58 (with leading '1' for zeros)"""
    num = int.from_bytes(v, 'big')
    result = []
    while num:
        num, rem = divmod(num, B58_BASE)
        result.append(B58[rem])
    pad = len(v) - len(v.lstrip(b'\x00'))
    return B58[0] * pad + ''.join(reversed(result))


def hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def base58check_encode(payload: bytes) -> str:
    """payload → versioned → double sha256 → checksum 4 bytes → base58"""
    checksum = hash256(payload)[:4]
    return b58encode(payload + checksum)


def wif_from_privkey(privkey_32: bytes, compressed: bool = True) -> str:
    """32-byte private key → WIF"""
    extended = PRIVKEY_VERSION + privkey_32
    if compressed:
        extended += b'\x01'
    return base58check_encode(extended)


# ───────────────────────────────────────────────
#  PBKDF2 key derivation (Bitcoin Core style)
# ───────────────────────────────────────────────

def derive_aes_key(passphrase: bytes, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-SHA512 → 32-byte AES key + 16-byte IV (Bitcoin Core method)"""
    key = hashlib.pbkdf2_hmac(
        'sha512',
        passphrase,
        salt,
        iterations,
        dklen=48               # 32 byte key + 16 byte IV
    )
    return key[:32], key[32:]


# ───────────────────────────────────────────────
#  AES-CBC decrypt (pycryptodome preferred)
# ───────────────────────────────────────────────

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_BACKEND = "pycryptodome"
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.backends import default_backend
        CRYPTO_BACKEND = "cryptography"
    except ImportError:
        CRYPTO_BACKEND = None
        print("WARNING: No AES library found (pycryptodome or cryptography).")
        print("         Cannot decrypt encrypted keys without it.")
        print("         Install with:  pip install pycryptodome\n")


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
    if CRYPTO_BACKEND is None:
        return None

    try:
        if CRYPTO_BACKEND == "pycryptodome":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = cipher.decrypt(ciphertext)
            return unpad(padded, AES.block_size)
        else:  # cryptography
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None


# ───────────────────────────────────────────────
#  Pattern search & parsing
# ───────────────────────────────────────────────

def scan_file_for_keys(filename: str, passphrase: Optional[bytes] = None) -> None:
    """
    Main scanning logic:
    - Looks for unencrypted keys (ASN.1 style)
    - Looks for mkey and ckey patterns
    - If passphrase given + mkey found → tries to decrypt ckeys
    """
    print(f"\nScanning: {filename}")
    if passphrase:
        print(f"Passphrase provided (length {len(passphrase)} bytes) → will attempt decryption")
    else:
        print("No passphrase → only looking for unencrypted keys")

    master_keys: List[Dict] = []           # list of found mkey info
    encrypted_keys: List[Dict] = []        # list of (pubkey, encrypted_privkey)

    with open(filename, "rb") as f:
        offset = 0
        while True:
            chunk = f.read(READ_CHUNK_SIZE)
            if not chunk:
                break

            # ─── Unencrypted raw keys (old style) ───
            pos = 0
            while True:
                pos = chunk.find(ASN1_PRIV_PREFIX, pos)
                if pos == -1:
                    break
                key_start = pos + len(ASN1_PRIV_PREFIX)
                if key_start + 32 <= len(chunk):
                    priv = chunk[key_start : key_start + 32]
                    wif = wif_from_privkey(priv, compressed=True)
                    print(f"[UNENCRYPTED]  {offset + key_start:10d}    WIF: {wif}")
                pos += 1

            # ─── mkey ───
            pos = 0
            while True:
                pos = chunk.find(MKEY_PATTERN, pos)
                if pos == -1:
                    break

                # Typical mkey layout after pattern: encrypted_key(48) + salt(8) + method(4) + iterations(4) + ...
                start = pos + len(MKEY_PATTERN)
                if start + 48 + 8 + 4 + 4 > len(chunk):
                    pos += 1
                    continue

                enc_master = chunk[start : start + 48]
                salt      = chunk[start + 48 : start + 56]
                method    = struct.unpack("<I", chunk[start + 56 : start + 60])[0]
                iters     = struct.unpack("<I", chunk[start + 60 : start + 64])[0]

                master_keys.append({
                    "offset": offset + start,
                    "enc_master": enc_master,
                    "salt": salt,
                    "method": method,
                    "iterations": iters
                })

                print(f"[MKEY found]  offset={offset+start:10d}  iterations={iters}  method={method}")

                pos += 1

            # ─── ckey ───
            pos = 0
            while True:
                pos = chunk.find(CKEY_PATTERN, pos)
                if pos == -1:
                    break

                # ckey layout: pubkey (usually 33 or 65 bytes) + encrypted_privkey (48 bytes)
                start = pos + len(CKEY_PATTERN)

                # Try to read compact size for pubkey length
                if start >= len(chunk):
                    pos += 1
                    continue

                pubkey_len = chunk[start]
                start += 1
                if start + pubkey_len + 48 > len(chunk):
                    pos += 1
                    continue

                pubkey = chunk[start : start + pubkey_len]
                enc_priv = chunk[start + pubkey_len : start + pubkey_len + 48]

                encrypted_keys.append({
                    "offset": offset + pos,
                    "pubkey": pubkey,
                    "enc_priv": enc_priv
                })

                pub_hex = binascii.hexlify(pubkey).decode()
                print(f"[CKEY found]  offset={offset+pos:10d}  pubkey={pub_hex[:16]}...")

                pos += 1

            # Prepare next chunk with overlap
            if len(chunk) == READ_CHUNK_SIZE:
                f.seek(f.tell() - OVERLAP_MARGIN)

            offset += len(chunk) - OVERLAP_MARGIN

    # ─── Decryption phase ───
    if passphrase and master_keys and encrypted_keys:
        print("\n" + "="*70)
        print("Attempting decryption with provided passphrase...")
        print("="*70)

        for mk in master_keys:
            if mk["method"] != 0:
                print(f"  Skipping mkey (unsupported method {mk['method']})")
                continue

            print(f"  Using mkey @ offset {mk['offset']}, {mk['iterations']} iterations")

            aes_key, aes_iv_base = derive_aes_key(passphrase, mk["salt"], mk["iterations"])

            # Decrypt master key
            master_key = aes_decrypt(mk["enc_master"], aes_key, aes_iv_base)
            if not master_key or len(master_key) != 32:
                print("  → Master key decryption failed (wrong passphrase?)")
                continue

            print("  → Master key decrypted successfully!")

            # Now try to decrypt each ckey with this master key
            for ck in encrypted_keys:
                pubkey = ck["pubkey"]
                enc_priv = ck["enc_priv"]

                # IV = SHA256(pubkey) first 16 bytes (Bitcoin Core behavior)
                iv = hashlib.sha256(pubkey).digest()[:16]

                priv_dec = aes_decrypt(enc_priv, master_key, iv)
                if not priv_dec or len(priv_dec) not in (32, 33):
                    continue

                # Strip padding if PKCS7-like
                if len(priv_dec) == 33 and priv_dec[-1] == 0x01:
                    priv_dec = priv_dec[:-1]

                if len(priv_dec) != 32:
                    continue

                # Verify: regenerate pubkey and compare
                try:
                    import ecdsa
                    sk = ecdsa.SigningKey.from_string(priv_dec, curve=ecdsa.SECP256k1)
                    vk = sk.verifying_key
                    computed_pub = b'\x04' + vk.to_string()  # uncompressed
                    if computed_pub[1:] == pubkey[1:] or computed_pub == pubkey:
                        wif = wif_from_privkey(priv_dec, compressed=(pubkey[0] in (2,3)))
                        print(f"  DECRYPTED KEY @ offset {ck['offset']}")
                        print(f"     WIF       : {wif}")
                        print(f"     Pubkey    : {binascii.hexlify(pubkey).decode()}")
                        print(f"     Priv (hex): {binascii.hexlify(priv_dec).decode()}")
                except Exception as e:
                    pass  # not a valid key

    # ─── Summary ───
    total = len(master_keys) + len(encrypted_keys)
    print(f"\nScan complete. Found {total} wallet-related structures.")
    print(f"  • mkey entries: {len(master_keys)}")
    print(f"  • ckey entries: {len(encrypted_keys)}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_or_device> [--passphrase \"secret\"]")
        print("  Scans for unencrypted keys and Bitcoin Core encrypted wallet structures")
        sys.exit(1)

    filename = sys.argv[1]
    passphrase_str: Optional[str] = None

    # Command-line passphrase
    if len(sys.argv) > 3 and sys.argv[2] == "--passphrase":
        passphrase_str = sys.argv[3]

    # Interactive prompt if no passphrase given
    if passphrase_str is None:
        print(f"\nScanning: {filename}")
        print("If the wallet is encrypted, enter the passphrase now.")
        print("Press Enter twice (empty line) to skip / scan without decryption.\n")

        lines = []
        while True:
            try:
                line = getpass.getpass("Passphrase line (empty to finish): ")
                if not line:
                    break
                lines.append(line)
            except KeyboardInterrupt:
                print("\nCancelled.")
                sys.exit(0)

        passphrase_str = "".join(lines)

    passphrase_bytes = passphrase_str.encode('utf-8') if passphrase_str else None

    scan_file_for_keys(filename, passphrase_bytes)


if __name__ == "__main__":
    main()

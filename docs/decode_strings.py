#!/usr/bin/env python3
"""
Hikari String Decoder
=====================
This script decodes obfuscated strings from Hikari-obfuscated IDA/Hex-Rays decompiler output.

Supports multiple obfuscation techniques:
1. Hikari LLVM String Encryption - XOR-based encoding with per-string keys
2. StringDecrypt() - Base64 + AES-256 decryption (RusskovT2RActivator style)
3. FWTObfuscator - PBKDF2 key derivation + AES
4. AES-128-CBC and AES-256-CBC for decryptMyData/decryptData functions

Usage:
    python decode_strings.py <filename.c>
    python decode_strings.py --help

Author: Decoded for educational/research purposes
"""

import re
import sys
import base64
import struct
import argparse
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

# Try to import cryptography for AES support
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    HAS_CRYPTO = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import unpad

        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False


@dataclass
class EncodedString:
    """Represents an encoded string found in the dump"""

    name: str
    encoded_bytes: bytes
    decoded_string: Optional[str] = None
    xor_key: Optional[bytes] = None
    line_number: int = 0
    encoding_type: str = "unknown"


def parse_hex_string(hex_str: str) -> bytes:
    """
    Parse a C-style string with hex escapes into bytes.
    Handles: \\xNN, \\n, \\t, \\r, \\uNNNN, regular chars, etc.
    """
    result = bytearray()
    i = 0
    while i < len(hex_str):
        if hex_str[i] == "\\" and i + 1 < len(hex_str):
            next_char = hex_str[i + 1]
            if next_char == "x" and i + 3 < len(hex_str):
                # Hex escape \xNN
                try:
                    hex_val = hex_str[i + 2 : i + 4]
                    result.append(int(hex_val, 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            elif next_char == "u" and i + 5 < len(hex_str):
                # Unicode escape \uNNNN
                try:
                    hex_val = hex_str[i + 2 : i + 6]
                    code_point = int(hex_val, 16)
                    result.extend(chr(code_point).encode("utf-8", errors="replace"))
                    i += 6
                    continue
                except ValueError:
                    pass
            elif next_char == "n":
                result.append(ord("\n"))
                i += 2
                continue
            elif next_char == "t":
                result.append(ord("\t"))
                i += 2
                continue
            elif next_char == "r":
                result.append(ord("\r"))
                i += 2
                continue
            elif next_char == "0":
                result.append(0)
                i += 2
                continue
            elif next_char == "\\":
                result.append(ord("\\"))
                i += 2
                continue
            elif next_char == '"':
                result.append(ord('"'))
                i += 2
                continue

        # Regular character
        result.append(ord(hex_str[i]))
        i += 1

    return bytes(result)


def is_base64(s: str) -> bool:
    """Check if a string looks like valid base64"""
    if len(s) < 4:
        return False
    # Base64 pattern: alphanumeric, +, /, =
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]+=*$")
    if not base64_pattern.match(s):
        return False
    # Check length is valid for base64
    return len(s) % 4 == 0 or s.endswith("=")


def try_base64_decode(s: str) -> Optional[bytes]:
    """Try to decode a base64 string"""
    try:
        # Handle potential padding issues
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.b64decode(s)
    except Exception:
        return None


def aes256_decrypt(data: bytes, key: bytes) -> Optional[bytes]:
    """Decrypt AES-256 ECB/CBC data"""
    if not HAS_CRYPTO:
        return None
    try:
        # Pad key to 32 bytes if needed
        if len(key) < 32:
            key = key.ljust(32, b"\x00")
        elif len(key) > 32:
            key = key[:32]

        # Try ECB mode first (no IV)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(data)
        try:
            decrypted = unpad(decrypted, AES.block_size)
        except ValueError:
            pass

        # Check if result is printable
        try:
            result = decrypted.decode("utf-8", errors="strict")
            if result.isprintable() or "\n" in result or "\t" in result:
                return decrypted
        except UnicodeDecodeError:
            pass

        # Try CBC mode with zero IV
        iv = b"\x00" * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        try:
            decrypted = unpad(decrypted, AES.block_size)
        except ValueError:
            pass

        try:
            result = decrypted.decode("utf-8", errors="strict")
            if result.isprintable() or "\n" in result or "\t" in result:
                return decrypted
        except UnicodeDecodeError:
            pass

    except Exception:
        pass
    return None


def extract_encryption_keys(content: str) -> Dict[str, str]:
    """Extract encryption keys from the code"""
    keys = {}

    # Pattern for strcpy with base64 key (EncryptionKey pattern)
    # strcpy(aO_3, "RUE1NkNFODlBQzNCRA==");
    pattern = r'strcpy\(\w+,\s*"([A-Za-z0-9+/=]{10,})"\)'
    for match in re.finditer(pattern, content):
        b64_key = match.group(1)
        if is_base64(b64_key):
            decoded = try_base64_decode(b64_key)
            if decoded:
                keys[b64_key] = decoded.decode("utf-8", errors="replace")

    # Look for qmemcpy with potential keys
    pattern2 = r'qmemcpy\(\w+,\s*"([^"]{8,32})",\s*\d+\)'
    for match in re.finditer(pattern2, content):
        potential_key = match.group(1)
        if potential_key.isascii() and len(potential_key) in [16, 24, 32]:
            keys[f"aes_key_{len(potential_key)}"] = potential_key

    return keys


def extract_encoded_strings(content: str) -> List[EncodedString]:
    """Extract all encoded string variables from the C dump"""
    strings = []

    # Pattern for char array declarations with encoded data
    # e.g., char asc_100260DE2[2] = "/\x16";
    pattern1 = r'char\s+(asc_[0-9A-Fa-f]+|a[A-Za-z0-9_]+)\[(\d+)\]\s*=\s*"([^"]*)"'

    for match in re.finditer(pattern1, content):
        name = match.group(1)
        size = int(match.group(2))
        raw_str = match.group(3)
        try:
            encoded = parse_hex_string(raw_str)
            strings.append(
                EncodedString(name=name, encoded_bytes=encoded, encoding_type="hex_array")
            )
        except Exception:
            pass

    # Pattern for CFSTR with encoded data (Hikari XOR)
    # e.g., CFSTR("\xF2\x0B\xCF\xB6\xBA")
    pattern2 = r'CFSTR\("([^"]+)"\)'
    cfstr_strings = set()
    for match in re.finditer(pattern2, content):
        raw_str = match.group(1)
        if any(c in raw_str for c in ["\\x", "\\X"]):
            try:
                encoded = parse_hex_string(raw_str)
                # Use first 8 bytes as identifier
                key = encoded[:8].hex() if len(encoded) >= 8 else encoded.hex()
                if key not in cfstr_strings:
                    cfstr_strings.add(key)
                    strings.append(
                        EncodedString(
                            name=f"CFSTR_{key}", encoded_bytes=encoded, encoding_type="cfstr_hex"
                        )
                    )
            except Exception:
                pass

    # Pattern for StringDecrypt(CFSTR("...")) - Base64 encoded then AES encrypted
    pattern3 = r'StringDecrypt\(CFSTR\("([^"]+)"\)\)'
    for match in re.finditer(pattern3, content):
        raw_str = match.group(1)
        try:
            encoded = parse_hex_string(raw_str)
            key = encoded[:8].hex() if len(encoded) >= 8 else encoded.hex()
            strings.append(
                EncodedString(
                    name=f"StringDecrypt_{key}",
                    encoded_bytes=encoded,
                    encoding_type="string_decrypt",
                )
            )
        except Exception:
            pass

    # Pattern for Resource_Link, Api_Link, V_Link type variables
    pattern4 = r"StringDecrypt\((Resource_Link|Api_Link|V_Link|[A-Za-z_]+_Link)\)"
    for match in re.finditer(pattern4, content):
        var_name = match.group(1)
        strings.append(
            EncodedString(
                name=f"StringDecrypt_var_{var_name}",
                encoded_bytes=b"",
                encoding_type="string_decrypt_var",
            )
        )

    return strings


def extract_byte_definitions(content: str) -> Dict[str, int]:
    """
    Extract byte variable definitions like:
    char byte_10002D100 = '\xa5'; // weak
    char byte_10002D101 = '\xc9'; // weak
    """
    byte_vars = {}

    # Pattern for hex escape: char byte_XXX = '\xNN';
    pattern_hex = r"char\s+(byte_[0-9A-Fa-f]+)\s*=\s*'\\x([0-9A-Fa-f]{2})';"
    for match in re.finditer(pattern_hex, content):
        var_name = match.group(1)
        hex_val = int(match.group(2), 16)
        byte_vars[var_name] = hex_val

    # Pattern for regular char: char byte_XXX = 'X';
    pattern_char = r"char\s+(byte_[0-9A-Fa-f]+)\s*=\s*'([^\\'])';"
    for match in re.finditer(pattern_char, content):
        var_name = match.group(1)
        char_val = ord(match.group(2))
        byte_vars[var_name] = char_val

    # Pattern for escaped chars like '\t', '\n', '\\', etc.
    pattern_escaped = r"char\s+(byte_[0-9A-Fa-f]+)\s*=\s*'\\([nrtv0\\\"'])';"
    escape_map = {"n": 10, "r": 13, "t": 9, "v": 11, "0": 0, "\\": 92, '"': 34, "'": 39}
    for match in re.finditer(pattern_escaped, content):
        var_name = match.group(1)
        escape_char = match.group(2)
        if escape_char in escape_map:
            byte_vars[var_name] = escape_map[escape_char]

    return byte_vars


def extract_qword_definitions(content: str) -> Dict[str, int]:
    """
    Extract qword (64-bit) variable definitions like:
    __int64 qword_10002D4D8 = 8577658799953033328LL; // weak
    """
    qword_vars = {}

    # Pattern for positive qword: __int64 qword_XXX = NNLL;
    pattern_pos = r"__int64\s+(qword_[0-9A-Fa-f]+)\s*=\s*(\d+)LL;"
    for match in re.finditer(pattern_pos, content):
        var_name = match.group(1)
        val = int(match.group(2))
        qword_vars[var_name] = val

    # Pattern for negative qword: __int64 qword_XXX = -NNLL;
    pattern_neg = r"__int64\s+(qword_[0-9A-Fa-f]+)\s*=\s*-(\d+)LL;"
    for match in re.finditer(pattern_neg, content):
        var_name = match.group(1)
        val = -int(match.group(2))
        # Convert to unsigned 64-bit
        qword_vars[var_name] = val & 0xFFFFFFFFFFFFFFFF

    return qword_vars


def extract_xor_decoded_strings(
    content: str, byte_vars: Dict[str, int], qword_vars: Dict[str, int] = None
) -> Dict[str, str]:
    """
    Extract strings decoded via XOR operations like:
    asc_10002D10E[0] = byte_10002D100 ^ 0xF0;
    asc_10002D10E[1] = byte_10002D101 ^ 0xA7;

    Also handles obfuscated patterns:
    - byte - ((2 * byte) & A) + B  (arithmetic obfuscation)
    - byte - ((2 * byte) & A) - B
    - ~((byte | A) & (~byte | B))  (bitwise obfuscation)
    - veor_s8 SIMD vector XOR operations
    """
    if qword_vars is None:
        qword_vars = {}

    char_arrays = {}

    # Pattern 1: array[N] = byte_XXX ^ 0xHH;
    xor_pattern = r"(\w+)\[(\d+)\]\s*=\s*(byte_[0-9A-Fa-f]+)\s*\^\s*0x([0-9A-Fa-f]+);"
    for match in re.finditer(xor_pattern, content):
        array_name = match.group(1)
        index = int(match.group(2))
        byte_var = match.group(3)
        xor_key = int(match.group(4), 16)

        if byte_var in byte_vars:
            decrypted_byte = byte_vars[byte_var] ^ xor_key
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            char_arrays[array_name][index] = decrypted_byte & 0xFF

    # Pattern 1b: array[N] = byte_XXX ^ N; (decimal XOR key)
    xor_decimal_pattern = r"(\w+)\[(\d+)\]\s*=\s*(byte_[0-9A-Fa-f]+)\s*\^\s*(\d+);"
    for match in re.finditer(xor_decimal_pattern, content):
        array_name = match.group(1)
        index = int(match.group(2))
        byte_var = match.group(3)
        xor_key = int(match.group(4))

        if byte_var in byte_vars and xor_key < 256:
            decrypted_byte = byte_vars[byte_var] ^ xor_key
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            if index not in char_arrays.get(array_name, {}):
                char_arrays[array_name][index] = decrypted_byte & 0xFF

    # Pattern 2: array[N] = byte_XXX - ((2 * byte_XXX) & 0xHH) + N;
    # This is an obfuscated transformation
    arith_add_pattern = r"(\w+)\[(\d+)\]\s*=\s*(byte_[0-9A-Fa-f]+)\s*-\s*\(\(2\s*\*\s*\3\)\s*&\s*0x([0-9A-Fa-f]+)\)\s*\+\s*(\d+);"
    for match in re.finditer(arith_add_pattern, content):
        array_name = match.group(1)
        index = int(match.group(2))
        byte_var = match.group(3)
        mask = int(match.group(4), 16)
        addend = int(match.group(5))

        if byte_var in byte_vars:
            byte_val = byte_vars[byte_var]
            # Compute: byte - ((2 * byte) & mask) + addend
            doubled = (2 * byte_val) & 0xFF
            masked = doubled & mask
            result = (byte_val - masked + addend) & 0xFF
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            if index not in char_arrays.get(array_name, {}):
                char_arrays[array_name][index] = result

    # Pattern 3: array[N] = byte_XXX - ((2 * byte_XXX) & 0xHH) - N;
    arith_sub_pattern = r"(\w+)\[(\d+)\]\s*=\s*(byte_[0-9A-Fa-f]+)\s*-\s*\(\(2\s*\*\s*\3\)\s*&\s*0x([0-9A-Fa-f]+)\)\s*-\s*(\d+);"
    for match in re.finditer(arith_sub_pattern, content):
        array_name = match.group(1)
        index = int(match.group(2))
        byte_var = match.group(3)
        mask = int(match.group(4), 16)
        subtrahend = int(match.group(5))

        if byte_var in byte_vars:
            byte_val = byte_vars[byte_var]
            # Compute: byte - ((2 * byte) & mask) - subtrahend
            doubled = (2 * byte_val) & 0xFF
            masked = doubled & mask
            result = (byte_val - masked - subtrahend) & 0xFF
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            if index not in char_arrays.get(array_name, {}):
                char_arrays[array_name][index] = result

    # Pattern 4: array[N] = ~((byte_XXX | 0xHH) & (~byte_XXX | 0xHH));
    bitwise_pattern = r"(\w+)\[(\d+)\]\s*=\s*~\(\((byte_[0-9A-Fa-f]+)\s*\|\s*0x([0-9A-Fa-f]+)\)\s*&\s*\(~\3\s*\|\s*0x([0-9A-Fa-f]+)\)\);"
    for match in re.finditer(bitwise_pattern, content):
        array_name = match.group(1)
        index = int(match.group(2))
        byte_var = match.group(3)
        or_val1 = int(match.group(4), 16)
        or_val2 = int(match.group(5), 16)

        if byte_var in byte_vars:
            byte_val = byte_vars[byte_var]
            # Compute: ~((byte | or_val1) & (~byte | or_val2))
            not_byte = (~byte_val) & 0xFF
            term1 = (byte_val | or_val1) & 0xFF
            term2 = (not_byte | or_val2) & 0xFF
            result = (~(term1 & term2)) & 0xFF
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            if index not in char_arrays.get(array_name, {}):
                char_arrays[array_name][index] = result

    # Pattern 5: array[N] = byte_XXX + ((2 * byte_XXX) & 0xHH) + N; (less common variant)
    arith_add2_pattern = r"(\w+)\[(\d+)\]\s*=\s*(byte_[0-9A-Fa-f]+)\s*\+\s*\(\(2\s*\*\s*\3\)\s*&\s*0x([0-9A-Fa-f]+)\)\s*\+\s*(\d+);"
    for match in re.finditer(arith_add2_pattern, content):
        array_name = match.group(1)
        index = int(match.group(2))
        byte_var = match.group(3)
        mask = int(match.group(4), 16)
        addend = int(match.group(5))

        if byte_var in byte_vars:
            byte_val = byte_vars[byte_var]
            doubled = (2 * byte_val) & 0xFF
            masked = doubled & mask
            result = (byte_val + masked + addend) & 0xFF
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            if index not in char_arrays.get(array_name, {}):
                char_arrays[array_name][index] = result

    # Pattern 6: Variable indirection - vN = byte_XXX; ... array[i] = vN ^ 0xHH;
    # First, build a map of simple variable assignments: vN = byte_XXX
    var_to_byte = {}
    var_assign_pattern = r"(v\d+)\s*=\s*(byte_[0-9A-Fa-f]+);"
    for match in re.finditer(var_assign_pattern, content):
        var_name = match.group(1)
        byte_var = match.group(2)
        if byte_var in byte_vars:
            var_to_byte[var_name] = byte_vars[byte_var]

    # Now find array[N] = vN ^ 0xHH; patterns
    var_xor_pattern = r"(\w+)\[(\d+)\]\s*=\s*(v\d+)\s*\^\s*0x([0-9A-Fa-f]+);"
    for match in re.finditer(var_xor_pattern, content):
        array_name = match.group(1)
        index = int(match.group(2))
        var_name = match.group(3)
        xor_key = int(match.group(4), 16)

        if var_name in var_to_byte:
            decrypted_byte = var_to_byte[var_name] ^ xor_key
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            if index not in char_arrays.get(array_name, {}):
                char_arrays[array_name][index] = decrypted_byte & 0xFF

    # Pattern 7: SIMD vector XOR - veor_s8
    # *(int8x8_t *)&array[N] = veor_s8((int8x8_t)qword_XXX, (int8x8_t)0xHHHHLL);
    simd_pattern = r"\*\(int8x8_t \*\)&(\w+)\[(\d+)\]\s*=\s*veor_s8\(\(int8x8_t\)(qword_[0-9A-Fa-f]+),\s*\(int8x8_t\)0x([0-9A-Fa-f]+)LL\);"
    for match in re.finditer(simd_pattern, content):
        array_name = match.group(1)
        start_index = int(match.group(2))
        qword_var = match.group(3)
        xor_key = int(match.group(4), 16)

        if qword_var in qword_vars:
            qword_val = qword_vars[qword_var]
            # XOR the qword values and extract 8 bytes (little-endian)
            result = qword_val ^ xor_key
            result_bytes = struct.pack("<Q", result & 0xFFFFFFFFFFFFFFFF)
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            for i, b in enumerate(result_bytes):
                if start_index + i not in char_arrays.get(array_name, {}):
                    char_arrays[array_name][start_index + i] = b

    # Also handle variant: *(int8x8_t *)array = veor_s8(...)
    simd_pattern2 = r"\*\(int8x8_t \*\)(\w+)\s*=\s*veor_s8\(\(int8x8_t\)(qword_[0-9A-Fa-f]+),\s*\(int8x8_t\)0x([0-9A-Fa-f]+)LL\);"
    for match in re.finditer(simd_pattern2, content):
        array_name = match.group(1)
        qword_var = match.group(2)
        xor_key = int(match.group(3), 16)

        if qword_var in qword_vars:
            qword_val = qword_vars[qword_var]
            result = qword_val ^ xor_key
            result_bytes = struct.pack("<Q", result & 0xFFFFFFFFFFFFFFFF)
            if array_name not in char_arrays:
                char_arrays[array_name] = {}
            for i, b in enumerate(result_bytes):
                if i not in char_arrays.get(array_name, {}):
                    char_arrays[array_name][i] = b

    # Convert to strings
    decoded = {}
    for array_name, chars in char_arrays.items():
        if chars:
            max_idx = max(chars.keys())
            result = []
            for i in range(max_idx + 1):
                if i in chars:
                    val = chars[i]
                    if 0 < val < 256:
                        result.append(chr(val))
                    elif val == 0:
                        break  # Null terminator
                else:
                    # Gap in array - might be using different pattern for this index
                    result.append("?")
            if result and len([c for c in result if c != "?"]) > 0:
                decoded[array_name] = "".join(result).rstrip("?")

    return decoded


def extract_decoded_strings(content: str) -> Dict[str, str]:
    """
    Extract known plaintext strings from strcpy statements.
    These reveal the decoded values of obfuscated strings.
    """
    decoded = {}

    # Pattern: strcpy(variable, "plaintext");
    pattern = r'strcpy\((\w+),\s*"([^"]+)"\)'

    for match in re.finditer(pattern, content):
        var_name = match.group(1)
        plaintext = match.group(2)
        decoded[var_name] = plaintext

    # Pattern: qmemcpy(variable, "plaintext", size);
    pattern2 = r'qmemcpy\((\w+),\s*"([^"]+)",\s*\d+\)'
    for match in re.finditer(pattern2, content):
        var_name = match.group(1)
        plaintext = match.group(2)
        decoded[var_name] = plaintext

    # Pattern: variable[N] = XX; (character by character assignments)
    # e.g., aFJ[0] = 100; aFJ[1] = 97; ...
    char_pattern = r"(\w+)\[(\d+)\]\s*=\s*(\d+);"
    char_arrays = {}

    for match in re.finditer(char_pattern, content):
        var_name = match.group(1)
        index = int(match.group(2))
        char_val = int(match.group(3))

        if var_name not in char_arrays:
            char_arrays[var_name] = {}
        char_arrays[var_name][index] = char_val

    # Convert character arrays to strings
    for var_name, chars in char_arrays.items():
        if chars:
            max_idx = max(chars.keys())
            result = []
            for i in range(max_idx + 1):
                if i in chars and chars[i] != 0:
                    # Only accept printable ASCII characters
                    if 0 < chars[i] < 256:
                        if chars[i] < 128:
                            result.append(chr(chars[i]))
                        else:
                            # Extended ASCII - try to include
                            try:
                                result.append(chr(chars[i]))
                            except ValueError:
                                break
                    else:
                        break
                else:
                    break
            if result:
                decoded[var_name] = "".join(result)

    # NEW: Also extract XOR-based decoded strings (OtixOpenmenuMACOS pattern)
    byte_vars = extract_byte_definitions(content)
    qword_vars = extract_qword_definitions(content)
    if byte_vars or qword_vars:
        xor_decoded = extract_xor_decoded_strings(content, byte_vars, qword_vars)
        # Merge XOR decoded strings
        for name, value in xor_decoded.items():
            if name not in decoded:  # Don't override direct assignments
                decoded[name] = value

    return decoded


def extract_urls(content: str) -> List[str]:
    """Extract all URLs from the dump (both encoded and decoded)"""
    urls = set()

    # Direct URL patterns
    url_pattern = r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+"
    for match in re.finditer(url_pattern, content):
        urls.add(match.group(0))

    return sorted(urls)


def compute_xor_key(encoded: bytes, decoded: str) -> bytes:
    """Compute XOR key given encoded bytes and decoded plaintext"""
    decoded_bytes = decoded.encode("utf-8")
    key = bytearray()

    for i in range(min(len(encoded), len(decoded_bytes))):
        key.append(encoded[i] ^ decoded_bytes[i])

    return bytes(key)


def xor_decode(encoded: bytes, key: bytes) -> str:
    """Decode XOR-encoded bytes using the given key (repeating if needed)"""
    result = bytearray()
    for i, b in enumerate(encoded):
        if key:
            result.append(b ^ key[i % len(key)])
        else:
            result.append(b)

    try:
        # Try to decode as UTF-8, removing null terminator
        decoded = result.rstrip(b"\x00").decode("utf-8", errors="replace")
        return decoded
    except:
        return result.hex()


def try_common_xor_keys(encoded: bytes) -> List[Tuple[str, bytes]]:
    """Try decoding with common XOR key patterns"""
    results = []

    # Single byte keys
    for key_byte in range(256):
        key = bytes([key_byte])
        decoded = xor_decode(encoded, key)
        if decoded.isprintable() and len(decoded) > 3:
            results.append((decoded, key))

    return results


def detect_string_decrypt_usage(content: str) -> Dict[str, dict]:
    """Detect StringDecrypt function and its encryption parameters"""
    info = {
        "has_string_decrypt": False,
        "has_fwt_obfuscator": False,
        "encryption_keys": [],
        "base64_keys": [],
    }

    # Check for StringDecrypt function
    if "StringDecrypt" in content:
        info["has_string_decrypt"] = True

    # Check for FWTObfuscator
    if "FWTObfuscator" in content:
        info["has_fwt_obfuscator"] = True

    # Extract encryption keys
    # Pattern: strcpy(xxx, "BASE64KEY");
    key_pattern = r'strcpy\(\w+,\s*"([A-Za-z0-9+/=]{16,})"\)'
    for match in re.finditer(key_pattern, content):
        b64_key = match.group(1)
        if is_base64(b64_key):
            decoded = try_base64_decode(b64_key)
            if decoded:
                info["base64_keys"].append(
                    {"encoded": b64_key, "decoded": decoded.decode("utf-8", errors="replace")}
                )

    # Pattern for EncryptionKey function returning base64
    enc_key_pattern = r'EncryptionKey\(\)[\s\S]{0,500}CFSTR\("([^"]+)"\)'
    for match in re.finditer(enc_key_pattern, content):
        cfstr_val = match.group(1)
        info["encryption_keys"].append(cfstr_val)

    return info


def extract_cfstring_definitions(content: str) -> Dict[str, str]:
    """Extract __CFString definitions which hold actual string values"""
    cfstrings = {}

    # Pattern: __CFString cfstr_XXX = { ..., "string_value", ... };
    pattern = r'__CFString\s+(cfstr_\w+|stru_[0-9A-Fa-f]+)\s*=\s*\{[^}]*"([^"]*)"[^}]*\}'
    for match in re.finditer(pattern, content):
        name = match.group(1)
        value = match.group(2)
        cfstrings[name] = value

    # Also pattern: id XXX_Link = &cfstr_YYY;
    link_pattern = r"id\s+(\w+_Link)\s*=\s*&(cfstr_\w+|stru_[0-9A-Fa-f]+)"
    for match in re.finditer(link_pattern, content):
        link_name = match.group(1)
        cfstr_ref = match.group(2)
        if cfstr_ref in cfstrings:
            cfstrings[link_name] = cfstrings[cfstr_ref]

    return cfstrings


def analyze_string_patterns(content: str) -> dict:
    """Analyze patterns in encoded strings to identify encoding schemes"""
    patterns = {
        "hikari_xor": [],
        "base64": [],
        "aes_encrypted": [],
        "plaintext": [],
        "string_decrypt": [],
    }

    # Find CFSTR strings that look like base64
    base64_pattern = r'CFSTR\("([A-Za-z0-9+/=]+)"\)'
    for match in re.finditer(base64_pattern, content):
        s = match.group(1)
        if len(s) >= 4 and is_base64(s):
            patterns["base64"].append(s)

    # Find StringDecrypt calls
    sd_pattern = r"StringDecrypt\([^)]+\)"
    patterns["string_decrypt"] = re.findall(sd_pattern, content)

    return patterns


def main():
    parser = argparse.ArgumentParser(
        description="Decode obfuscated strings from Hikari-obfuscated C dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python decode_strings.py AldazA12.c
    python decode_strings.py RusskovT2RActivator.c
    python decode_strings.py ./dump.c --output decoded_output.txt
        """,
    )
    parser.add_argument("filename", help="Path to the C dump file to analyze")
    parser.add_argument("--output", "-o", help="Output file for results (optional)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    dump_path = args.filename

    print("=" * 70)
    print("Hikari String Decoder")
    print("=" * 70)

    try:
        with open(dump_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Could not find {dump_path}")
        sys.exit(1)

    print(f"\nLoaded dump file: {dump_path}")
    print(f"File size: {len(content):,} characters")

    # Detect encryption methods used
    print("\n" + "=" * 70)
    print("ENCRYPTION METHODS DETECTED")
    print("=" * 70)

    string_decrypt_info = detect_string_decrypt_usage(content)

    if string_decrypt_info["has_string_decrypt"]:
        print("\n  [+] StringDecrypt() function found - Base64 + AES256 encryption")
        if string_decrypt_info["base64_keys"]:
            print("      Encryption keys found:")
            for key_info in string_decrypt_info["base64_keys"]:
                print(f"        Base64: {key_info['encoded']}")
                print(f"        Decoded: {key_info['decoded']}")

    if string_decrypt_info["has_fwt_obfuscator"]:
        print("\n  [+] FWTObfuscator found - PBKDF2 + AES encryption")

    # Check for simple Hikari XOR (decimal assignments)
    char_assign_count = len(re.findall(r"\[\d+\]\s*=\s*\d+;", content))
    if char_assign_count > 10:
        print(f"\n  [+] Hikari XOR encoding found - {char_assign_count} character assignments")

    # Check for XOR with byte variables (OtixOpenmenuMACOS pattern)
    byte_var_count = len(re.findall(r"char\s+byte_[0-9A-Fa-f]+\s*=\s*'", content))
    xor_expr_count = len(re.findall(r"\[\d+\]\s*=\s*byte_[0-9A-Fa-f]+\s*\^", content))
    if byte_var_count > 0 and xor_expr_count > 0:
        print(
            f"\n  [+] Hikari XOR with byte variables - {byte_var_count} byte definitions, {xor_expr_count} XOR expressions"
        )

    # Extract URLs (most useful for understanding functionality)
    print("\n" + "=" * 70)
    print("EXTRACTED URLs")
    print("=" * 70)

    urls = extract_urls(content)
    print(f"\nFound {len(urls)} unique URLs:\n")
    for url in urls:
        print(f"  {url}")

    # Extract decoded strings from strcpy statements
    print("\n" + "=" * 70)
    print("DECODED STRINGS (from strcpy/qmemcpy/char assignments)")
    print("=" * 70)

    decoded_strings = extract_decoded_strings(content)

    # Extract CFString definitions
    cfstrings = extract_cfstring_definitions(content)

    # Merge CFStrings that look like URLs or interesting values
    for name, value in cfstrings.items():
        if value and len(value) > 3:
            decoded_strings[f"cfstr_{name}"] = value

    # Filter for interesting strings
    interesting_strings = {}
    keywords = [
        "http",
        "com.apple",
        "Library",
        "API",
        "activation",
        "device",
        "mobile",
        "apple.com",
        "icloud",
        "ssh",
        "Activation",
        "OTA",
        "plist",
        "backup",
        "Error",
        "error",
        "password",
        "key",
        "token",
        "auth",
        "cert",
        "serial",
        "ECID",
        "CPID",
        "ramdisk",
        "boot",
        "dfu",
        "recovery",
    ]

    for var, text in decoded_strings.items():
        # Include if matches keywords or is a URL or path
        if (
            any(kw.lower() in text.lower() for kw in keywords)
            or text.startswith("http")
            or text.startswith("/")
            or ".com" in text
            or ".plist" in text
        ):
            interesting_strings[var] = text

    print(
        f"\nFound {len(decoded_strings)} decoded strings, {len(interesting_strings)} interesting ones:\n"
    )

    # Sort by content for readability
    for var, text in sorted(interesting_strings.items(), key=lambda x: x[1]):
        # Truncate long strings
        display_text = text[:100] + "..." if len(text) > 100 else text
        print(f"  {var}: {display_text}")

    # Show all decoded strings if verbose
    if args.verbose:
        print("\n" + "=" * 70)
        print("ALL DECODED STRINGS")
        print("=" * 70)
        for var, text in sorted(decoded_strings.items(), key=lambda x: x[0]):
            display_text = text[:80] + "..." if len(text) > 80 else text
            print(f"  {var}: {display_text}")

    # Extract encryption keys
    print("\n" + "=" * 70)
    print("ENCRYPTION KEYS FOUND")
    print("=" * 70)

    enc_keys = extract_encryption_keys(content)
    if enc_keys:
        for name, value in enc_keys.items():
            print(f"\n  {name}: {value}")
    else:
        print("\n  No explicit encryption keys found")

    # Try to decrypt StringDecrypt-style strings if we have keys
    # The encrypted strings are first decoded via Hikari XOR (character assignments)
    # then the resulting base64 strings need to be AES decrypted
    aes_decrypted_strings = {}

    if HAS_CRYPTO and string_decrypt_info["base64_keys"]:
        print("\n" + "=" * 70)
        print("ATTEMPTING AES256 DECRYPTION OF BASE64 STRINGS")
        print("=" * 70)

        # Look for base64-looking strings in the decoded strings
        b64_pattern = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")

        for key_info in string_decrypt_info["base64_keys"]:
            key = key_info["decoded"].encode("utf-8")
            # Pad key to 32 bytes
            if len(key) < 32:
                key = key + b"\x00" * (32 - len(key))

            print(f"\n  Using key: {key_info['decoded'][:20]}... (from {key_info['encoded']})")

            decrypted_count = 0
            for var_name, text in decoded_strings.items():
                # Skip the key itself
                if text == key_info["encoded"]:
                    continue

                # Check if it looks like base64
                if b64_pattern.match(text):
                    try:
                        encrypted = base64.b64decode(text)

                        # Must be block-aligned for AES
                        if len(encrypted) % 16 != 0:
                            continue

                        # Try CBC with zero IV
                        iv = b"\x00" * 16
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        decrypted = cipher.decrypt(encrypted)

                        try:
                            decrypted = unpad(decrypted, AES.block_size)
                        except ValueError:
                            pass

                        try:
                            decrypted_text = decrypted.decode("utf-8", errors="strict")
                            # Check if mostly printable
                            if len(decrypted_text) > 0:
                                printable_ratio = sum(
                                    1 for c in decrypted_text if c.isprintable() or c in "\n\t\r"
                                ) / len(decrypted_text)
                                if printable_ratio > 0.8:
                                    print(f"    {var_name}: {decrypted_text}")
                                    aes_decrypted_strings[var_name] = decrypted_text
                                    decrypted_count += 1
                        except UnicodeDecodeError:
                            pass
                    except Exception:
                        pass

            print(f"\n  Successfully decrypted {decrypted_count} strings with this key")

            if decrypted_count > 0:
                break  # Found the right key

    elif not HAS_CRYPTO and string_decrypt_info["has_string_decrypt"]:
        print("\n  Note: Install pycryptodome for AES decryption support:")
        print("        pip install pycryptodome")

    # Show encryption method details
    print("\n" + "=" * 70)
    print("DECRYPTION METHODS FOUND IN BINARY")
    print("=" * 70)

    methods_found = []

    if "AES256DecryptWithKey" in content:
        methods_found.append("""
  1. AES256DecryptWithKey (StringDecrypt pattern)
     - Input is Base64 encoded encrypted data
     - Key from EncryptionKey() function (typically base64 encoded)
     - Uses AES-256 for decryption
     - Returns plaintext string""")

    if "decryptData" in content.lower():
        methods_found.append("""
  2. decryptData() - AES-256-CBC
     - Key size: 32 bytes (0x20)
     - Uses global 'key' and 'iv' variables
     - CCCrypt(1, 0, 1, key, 0x20, iv, ...)
     - Input: Base64 string -> decode -> AES decrypt -> JSON""")

    if "decryptMyData" in content.lower():
        methods_found.append("""
  3. decryptMyData() - AES-128-CBC
     - Key size: 16 bytes (0x10)
     - Key base often hardcoded
     - CCCrypt(1, 0, 1, key, 0x10, iv, ...)""")

    if char_assign_count > 10:
        methods_found.append("""
  4. Hikari String Encryption (XOR)
     - Each string has unique XOR key
     - Runtime decoding via character-by-character assignment
     - Pattern: var[N] = decimal_value;""")

    if string_decrypt_info["has_fwt_obfuscator"]:
        methods_found.append("""
  5. FWTObfuscator
     - Uses PBKDF2 for key derivation
     - AES encryption with password, IV, and salt
     - Pattern: decryptedDataForData:password:iv:salt:error:""")

    if methods_found:
        for method in methods_found:
            print(method)
    else:
        print("\n  No known encryption methods detected")

    # Write output files
    output_base = args.output if args.output else dump_path.rsplit(".", 1)[0]

    urls_file = f"{output_base}_urls.txt"
    strings_file = f"{output_base}_decoded.txt"

    # Collect all URLs including decrypted ones
    all_urls = set(urls)
    for text in aes_decrypted_strings.values():
        if text.startswith("http"):
            all_urls.add(text)

    with open(urls_file, "w") as f:
        f.write(f"# URLs extracted from {dump_path}\n")
        f.write("# " + "=" * 50 + "\n\n")
        for url in sorted(all_urls):
            f.write(url + "\n")

    with open(strings_file, "w") as f:
        f.write(f"# Decoded strings from {dump_path}\n")
        f.write("# " + "=" * 50 + "\n\n")

        if aes_decrypted_strings:
            f.write("## AES-Decrypted Strings (StringDecrypt)\n\n")
            for var, text in sorted(aes_decrypted_strings.items(), key=lambda x: x[0]):
                f.write(f"{var}: {text}\n")
            f.write("\n")

        f.write("## Interesting Strings\n\n")
        for var, text in sorted(interesting_strings.items(), key=lambda x: x[1]):
            f.write(f"{var}: {text}\n")
        f.write("\n## All Decoded Strings\n\n")
        for var, text in sorted(decoded_strings.items(), key=lambda x: x[0]):
            f.write(f"{var}: {text}\n")

    print("\n" + "=" * 70)
    print("OUTPUT FILES CREATED")
    print("=" * 70)
    print(f"\n  - {urls_file}    : All URLs found in dump")
    print(f"  - {strings_file}   : All decoded strings")

    print("\n" + "=" * 70)
    print("HOW THE STRING ENCODING WORKS")
    print("=" * 70)
    print("""
The Hikari obfuscator encrypts strings at compile time using XOR.
At runtime, strings are decoded by XORing each byte with a key.

Example from the dump:

  Encoded:  char asc_10026103C[5] = "\\xF2\\x0B\\xCF\\xB6\\xBA"
  Decoded:  asc_10026103C[0] = 100  (='d')

  To find XOR key for first byte:
    0xF2 ^ 'd' = 242 ^ 100 = 150 (0x96)

  The decoded string is "data" (used as JSON key)

For StringDecrypt pattern (RusskovT2RActivator style):
  1. CFSTR contains base64-encoded encrypted data
  2. EncryptionKey() returns the AES key (often base64 encoded)
  3. Data is base64 decoded, then AES-256 decrypted
  4. Result is the plaintext string
""")

    return 0


if __name__ == "__main__":
    sys.exit(main())

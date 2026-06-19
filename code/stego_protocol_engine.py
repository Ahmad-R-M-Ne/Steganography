#!/usr/bin/env python3

import os
import time
import struct
import hashlib
from dataclasses import dataclass
from typing import Dict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


MAGIC = b"NS"
VERSION = 1
MSG_TYPE_CHAT = 1
CHUNK_SIZE = 2


@dataclass
class Session:
    password: str
    local_ip: str
    peer_ip: str
    session_id: int
    key: bytes


def derive_key(password: str, local_ip: str, peer_ip: str) -> bytes:
    """
    Derive a 32-byte ChaCha20-Poly1305 key from password + fixed lab salt.
    Both sides must use the same password and same IP-pair logic.
    """
    ip_pair = "|".join(sorted([local_ip, peer_ip]))
    salt = hashlib.sha256(ip_pair.encode()).digest()

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,
        dklen=32
    )


def build_plaintext(message_id: int, text: str) -> bytes:
    """
    Internal plaintext before encryption:

    MAGIC       2 bytes
    VERSION     1 byte
    MSG_TYPE    1 byte
    MESSAGE_ID  4 bytes
    TIMESTAMP   4 bytes
    TEXT_LEN    2 bytes
    TEXT        variable
    """
    text_bytes = text.encode("utf-8")
    timestamp = int(time.time())

    header = struct.pack(
        "!2sBBIIH",
        MAGIC,
        VERSION,
        MSG_TYPE_CHAT,
        message_id,
        timestamp,
        len(text_bytes)
    )

    return header + text_bytes


def parse_plaintext(data: bytes) -> Dict:
    """
    Parse decrypted plaintext and validate structure.
    """
    header_size = struct.calcsize("!2sBBIIH")

    if len(data) < header_size:
        raise ValueError("Plaintext too short")

    magic, version, msg_type, message_id, timestamp, text_len = struct.unpack(
        "!2sBBIIH",
        data[:header_size]
    )

    if magic != MAGIC:
        raise ValueError("Invalid MAGIC")

    if version != VERSION:
        raise ValueError("Unsupported protocol version")

    text_bytes = data[header_size:header_size + text_len]

    if len(text_bytes) != text_len:
        raise ValueError("Invalid text length")

    return {
        "version": version,
        "msg_type": msg_type,
        "message_id": message_id,
        "timestamp": timestamp,
        "text": text_bytes.decode("utf-8")
    }


def encrypt_message(key: bytes, message_id: int, text: str) -> bytes:
    """
    Encrypt the full message once.
    Output format:

    nonce 12 bytes + ciphertext/tag
    """
    plaintext = build_plaintext(message_id, text)

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)

    associated_data = b"network-stego-v2"

    encrypted = cipher.encrypt(
        nonce,
        plaintext,
        associated_data
    )

    return nonce + encrypted


def decrypt_message(key: bytes, encrypted_blob: bytes) -> Dict:
    """
    Decrypt nonce + ciphertext/tag and parse plaintext.
    """
    if len(encrypted_blob) < 12 + 16:
        raise ValueError("Encrypted blob too short")

    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]

    cipher = ChaCha20Poly1305(key)

    associated_data = b"network-stego-v2"

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        associated_data
    )

    return parse_plaintext(plaintext)


def split_into_chunks(data: bytes) -> Dict[int, int]:
    """
    Split encrypted data into 2-byte chunks.

    Return:
        {
            chunk_number: ip_id_value
        }

    Each ip_id_value is suitable for IPv4 Identification field.
    """
    chunks = {}

    for index in range(0, len(data), CHUNK_SIZE):
        chunk_number = (index // CHUNK_SIZE) + 1
        chunk = data[index:index + CHUNK_SIZE]

        if len(chunk) == 1:
            chunk += b"\x00"

        ip_id_value = int.from_bytes(chunk, "big")
        chunks[chunk_number] = ip_id_value

    return chunks


def reassemble_chunks(chunks: Dict[int, int], total_chunks: int, original_length: int) -> bytes:
    """
    Reassemble 2-byte IPv4-ID values back into encrypted bytes.
    """
    result = bytearray()

    for chunk_number in range(1, total_chunks + 1):
        if chunk_number not in chunks:
            raise ValueError(f"Missing chunk {chunk_number}")

        result.extend(chunks[chunk_number].to_bytes(2, "big"))

    return bytes(result[:original_length])


def demo_local_protocol_test() -> None:
    """
    Local test without network.
    This simulates:

    message -> encrypt -> chunk -> reassemble -> decrypt
    """

    print("=" * 60)
    print(" Network Steganography Messenger v2 - Local Protocol Test")
    print("=" * 60)

    local_ip = input("Enter local IP: ").strip()
    peer_ip = input("Enter peer IP: ").strip()
    password = input("Enter shared password: ").strip()

    session_id = int.from_bytes(os.urandom(2), "big")

    key = derive_key(password, local_ip, peer_ip)

    session = Session(
        password=password,
        local_ip=local_ip,
        peer_ip=peer_ip,
        session_id=session_id,
        key=key
    )

    print(f"\nSession ID: {session.session_id}")
    print("Protocol engine is ready.")
    print("Type @finish to exit.\n")

    message_id = 1

    while True:
        user_input = input("me: ").strip()

        if user_input == "@finish":
            print("Closing protocol test.")
            break

        if not user_input:
            continue

        encrypted_blob = encrypt_message(
            session.key,
            message_id,
            user_input
        )

        chunks = split_into_chunks(encrypted_blob)

        print("\n[TX] Message encrypted successfully")
        print(f"[TX] Encrypted length: {len(encrypted_blob)} bytes")
        print(f"[TX] Total 2-byte chunks: {len(chunks)}")

        print("\n[TX] Simulated IPv4-ID values:")
        for chunk_no, ip_id in chunks.items():
            print(f"     Chunk {chunk_no:03d} -> IPv4-ID: {ip_id:05d} / 0x{ip_id:04X}")

        received_chunks = dict(chunks)

        reassembled = reassemble_chunks(
            received_chunks,
            total_chunks=len(chunks),
            original_length=len(encrypted_blob)
        )

        decoded = decrypt_message(
            session.key,
            reassembled
        )

        print("\n[RX] Reassembly complete")
        print("[RX] Decryption/authentication successful")
        print(f"peer: {decoded['text']}")
        print()

        message_id += 1


if __name__ == "__main__":
    demo_local_protocol_test()
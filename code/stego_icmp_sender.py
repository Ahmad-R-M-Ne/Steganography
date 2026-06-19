#!/usr/bin/env python3

import os
import time
import struct
import hashlib
from typing import Dict

from scapy.all import IP, ICMP, Raw, send
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


MAGIC = b"NS"
VERSION = 1
MSG_TYPE_CHAT = 1
CHUNK_SIZE = 2

ICMP_START_SEQ = 0
ICMP_END_SEQ = 65534
COVER_PAYLOAD = b"NETWORK-STEG-LAB"


def derive_key(password: str, local_ip: str, peer_ip: str) -> bytes:
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


def encrypt_message(key: bytes, message_id: int, text: str) -> bytes:
    plaintext = build_plaintext(message_id, text)

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)

    encrypted = cipher.encrypt(
        nonce,
        plaintext,
        b"network-stego-v2"
    )

    return nonce + encrypted


def split_into_chunks(data: bytes) -> Dict[int, int]:
    chunks = {}

    for index in range(0, len(data), CHUNK_SIZE):
        chunk_number = (index // CHUNK_SIZE) + 1
        chunk = data[index:index + CHUNK_SIZE]

        if len(chunk) == 1:
            chunk += b"\x00"

        chunks[chunk_number] = int.from_bytes(chunk, "big")

    return chunks


def send_start_packet(dst_ip: str, session_id: int, message_id: int) -> None:
    pkt = (
        IP(dst=dst_ip, id=message_id & 0xFFFF)
        / ICMP(type=8, code=0, id=session_id, seq=ICMP_START_SEQ)
        / Raw(load=COVER_PAYLOAD)
    )

    send(pkt, verbose=False)


def send_data_packet(dst_ip: str, session_id: int, chunk_number: int, ip_id_value: int) -> None:
    pkt = (
        IP(dst=dst_ip, id=ip_id_value)
        / ICMP(type=8, code=0, id=session_id, seq=chunk_number)
        / Raw(load=COVER_PAYLOAD)
    )

    send(pkt, verbose=False)


def send_end_packet(dst_ip: str, session_id: int, total_chunks: int) -> None:
    pkt = (
        IP(dst=dst_ip, id=total_chunks & 0xFFFF)
        / ICMP(type=8, code=0, id=session_id, seq=ICMP_END_SEQ)
        / Raw(load=COVER_PAYLOAD)
    )

    send(pkt, verbose=False)


def send_stego_message(
    dst_ip: str,
    session_id: int,
    key: bytes,
    message_id: int,
    text: str,
    delay: float = 0.05
) -> None:
    encrypted_blob = encrypt_message(key, message_id, text)
    chunks = split_into_chunks(encrypted_blob)

    print(f"[TX] Message ID: {message_id}")
    print(f"[TX] Encrypted length: {len(encrypted_blob)} bytes")
    print(f"[TX] Total chunks: {len(chunks)}")

    print("[TX] Sending START")
    send_start_packet(dst_ip, session_id, message_id)
    time.sleep(delay)

    for chunk_number, ip_id_value in chunks.items():
        print(f"[TX] DATA chunk={chunk_number:03d}, IPv4-ID=0x{ip_id_value:04X}")
        send_data_packet(dst_ip, session_id, chunk_number, ip_id_value)
        time.sleep(delay)

    print("[TX] Sending END")
    send_end_packet(dst_ip, session_id, len(chunks))

    print("[TX] Done\n")


def main() -> None:
    print("=" * 60)
    print(" Network Steganography Messenger v2 - ICMP Sender")
    print("=" * 60)

    local_ip = input("Enter local IP: ").strip()
    peer_ip = input("Enter destination IP: ").strip()
    password = input("Enter shared password: ").strip()

    key = derive_key(password, local_ip, peer_ip)

    session_id = int.from_bytes(os.urandom(2), "big")
    message_id = 1

    print(f"\nSession ID: {session_id}")
    print("Type @finish to exit.\n")

    while True:
        text = input("me: ").strip()

        if text == "@finish":
            print("Closing sender.")
            break

        if not text:
            continue

        send_stego_message(
            dst_ip=peer_ip,
            session_id=session_id,
            key=key,
            message_id=message_id,
            text=text
        )

        message_id += 1


if __name__ == "__main__":
    main()
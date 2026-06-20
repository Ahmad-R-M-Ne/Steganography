#####################################################################################################
#                             Network Steganography Messenger                                       #
#####################################################################################################

import os
import time
import struct
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional
from scapy.all import IP, ICMP, Raw, send, sniff
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"NS"
VERSION = 1
MSG_TYPE_CHAT = 1
CHUNK_SIZE = 2
ICMP_START_SEQ = 0
ICMP_END_SEQ = 65534
COVER_PAYLOAD = b"NETWORK-STEG-LAB"
ASSOCIATED_DATA = b"network-stego-v2"

@dataclass
class MessageBuffer:
    message_id: int
    chunks: Dict[int, int] = field(default_factory=dict)
    total_chunks: Optional[int] = None
    created_at: float = field(default_factory=time.time)

@dataclass
class ChatSession:
    local_ip: str
    peer_ip: str
    password: str
    session_id: int
    key: bytes
    running: bool = True
    debug: bool = False
    next_message_id: int = 1
    received_buffers: Dict[int, MessageBuffer] = field(default_factory=dict)

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

def parse_plaintext(data: bytes) -> Dict:
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
    plaintext = build_plaintext(message_id, text)

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)

    encrypted = cipher.encrypt(
        nonce,
        plaintext,
        ASSOCIATED_DATA
    )

    return nonce + encrypted

def decrypt_message(key: bytes, encrypted_blob: bytes) -> Dict:
    if len(encrypted_blob) < 12 + 16:
        raise ValueError("Encrypted blob too short")

    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]

    cipher = ChaCha20Poly1305(key)

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        ASSOCIATED_DATA
    )

    return parse_plaintext(plaintext)

def split_into_chunks(data: bytes) -> Dict[int, int]:
    chunks = {}

    for index in range(0, len(data), CHUNK_SIZE):
        chunk_number = (index // CHUNK_SIZE) + 1
        chunk = data[index:index + CHUNK_SIZE]

        if len(chunk) == 1:
            chunk += b"\x00"

        chunks[chunk_number] = int.from_bytes(chunk, "big")

    return chunks

def reassemble_chunks(chunks: Dict[int, int], total_chunks: int) -> bytes:
    result = bytearray()

    for chunk_number in range(1, total_chunks + 1):
        if chunk_number not in chunks:
            raise ValueError(f"Missing chunk {chunk_number}")

        result.extend(chunks[chunk_number].to_bytes(2, "big"))

    return bytes(result)

def send_icmp_packet(dst_ip: str, session_id: int, seq: int, ip_id: int) -> None:
    pkt = (
        IP(dst=dst_ip, id=ip_id & 0xFFFF)
        / ICMP(type=8, code=0, id=session_id & 0xFFFF, seq=seq & 0xFFFF)
        / Raw(load=COVER_PAYLOAD)
    )

    send(pkt, verbose=False)

def send_stego_message(session: ChatSession, text: str, delay: float = 0.03) -> None:
    message_id = session.next_message_id
    session.next_message_id += 1

    encrypted_blob = encrypt_message(
        session.key,
        message_id,
        text
    )

    chunks = split_into_chunks(encrypted_blob)

    print(f"[sending message_id={message_id}, chunks={len(chunks)}]")

    send_icmp_packet(
        dst_ip=session.peer_ip,
        session_id=session.session_id,
        seq=ICMP_START_SEQ,
        ip_id=message_id
    )

    time.sleep(delay)

    for chunk_number, ip_id_value in chunks.items():
        send_icmp_packet(
            dst_ip=session.peer_ip,
            session_id=session.session_id,
            seq=chunk_number,
            ip_id=ip_id_value
        )

        if session.debug:
            print(f"[TX] chunk={chunk_number:03d}, ip_id=0x{ip_id_value:04X}")

        time.sleep(delay)

    send_icmp_packet(
        dst_ip=session.peer_ip,
        session_id=session.session_id,
        seq=ICMP_END_SEQ,
        ip_id=len(chunks)
    )

    print("[sent]\n")

def process_received_packet(session: ChatSession, pkt) -> None:
    if IP not in pkt or ICMP not in pkt:
        return

    ip = pkt[IP]
    icmp = pkt[ICMP]

    if ip.src != session.peer_ip:
        return

    if ip.dst != session.local_ip:
        return

    if icmp.type != 8:
        return

    if icmp.id != session.session_id:
        return

    seq = int(icmp.seq)
    ip_id = int(ip.id)

    if seq == ICMP_START_SEQ:
        message_id = ip_id

        session.received_buffers[message_id] = MessageBuffer(
            message_id=message_id
        )

        if session.debug:
            print(f"\n[RX] START message_id={message_id}")

        return

    if seq == ICMP_END_SEQ:
        total_chunks = ip_id

        if not session.received_buffers:
            if session.debug:
                print("\n[RX] END ignored: no active message")
            return

        message_id = max(session.received_buffers.keys())
        buffer = session.received_buffers[message_id]
        buffer.total_chunks = total_chunks

        if session.debug:
            print(f"\n[RX] END message_id={message_id}, total_chunks={total_chunks}")

        try:
            encrypted_blob = reassemble_chunks(
                buffer.chunks,
                buffer.total_chunks
            )

            decoded = decrypt_message(
                session.key,
                encrypted_blob
            )

            print(f"\npeer: {decoded['text']}")
            print("me: ", end="", flush=True)

            del session.received_buffers[message_id]

        except Exception as exc:
            print(f"\n[RX] Decode failed: {exc}")
            print("me: ", end="", flush=True)

        return

    if 0 < seq < ICMP_END_SEQ:
        if not session.received_buffers:
            if session.debug:
                print("\n[RX] DATA ignored: no START")
            return

        message_id = max(session.received_buffers.keys())
        buffer = session.received_buffers[message_id]
        buffer.chunks[seq] = ip_id

        if session.debug:
            print(f"\n[RX] DATA chunk={seq:03d}, ip_id=0x{ip_id:04X}")

        return

def receiver_thread(session: ChatSession) -> None:
    sniff(
        filter="icmp",
        prn=lambda pkt: process_received_packet(session, pkt),
        store=False
    )

def show_help() -> None:
    print("""
Commands:

@help          Show this help
@finish        Exit program
@status        Show session status
@debug on      Enable technical logs
@debug off     Disable technical logs

Current limitation:
- Both sides must enter the same session ID manually.
- ACK/NACK is not implemented yet.
""")

def show_status(session: ChatSession) -> None:
    print("\nSession status")
    print("-" * 40)
    print(f"Local IP:       {session.local_ip}")
    print(f"Peer IP:        {session.peer_ip}")
    print(f"Session ID:     {session.session_id}")
    print(f"Next Msg ID:    {session.next_message_id}")
    print(f"Debug:          {session.debug}")
    print(f"Active RX Buffers: {len(session.received_buffers)}")
    print("-" * 40 + "\n")

def handle_command(session: ChatSession, command: str) -> None:
    if command == "@help":
        show_help()

    elif command == "@finish":
        session.running = False

    elif command == "@status":
        show_status(session)

    elif command == "@debug on":
        session.debug = True
        print("Debug enabled.")

    elif command == "@debug off":
        session.debug = False
        print("Debug disabled.")

    else:
        print("Unknown command. Type @help.")

def main() -> None:
    print("=" * 66)
    print(" Network Steganography Messenger v2")
    print(" ICMP Echo / IPv4 Identification / ChaCha20-Poly1305")
    print("=" * 66)

    local_ip = input("Enter local IP: ").strip()
    peer_ip = input("Enter peer IP: ").strip()
    password = input("Enter shared password: ").strip()

    print("\nSession ID mode:")
    print("1. Generate new session ID")
    print("2. Enter existing session ID")
    mode = input("Choose 1 or 2: ").strip()

    if mode == "1":
        session_id = int.from_bytes(os.urandom(2), "big")
        print(f"\nGenerated session ID: {session_id}")
        print("The peer must enter this same session ID.")
    else:
        session_id = int(input("Enter session ID: ").strip())

    key = derive_key(password, local_ip, peer_ip)

    session = ChatSession(
        local_ip=local_ip,
        peer_ip=peer_ip,
        password=password,
        session_id=session_id,
        key=key
    )

    thread = threading.Thread(
        target=receiver_thread,
        args=(session,),
        daemon=True
    )
    thread.start()

    print("\nReceiver thread started.")
    print("Type @help for commands.")
    print("Start chatting.\n")

    while session.running:
        try:
            text = input("me: ").strip()

            if not text:
                continue

            if text.startswith("@"):
                handle_command(session, text)
                continue

            send_stego_message(session, text)

        except KeyboardInterrupt:
            session.running = False
            break

        except Exception as exc:
            print(f"[ERROR] {exc}")

    print("\nClosing messenger.")

# Main ##############################################################################################

if __name__ == "__main__":
    main()

# End ###############################################################################################
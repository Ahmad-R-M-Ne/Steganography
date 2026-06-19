from pathlib import Path

code = r'''#!/usr/bin/env python3
"""
Network Steganography Messenger v2 - Safe Local Simulator

Purpose:
    This simulator keeps the protocol-engineering parts of the ICMP/IPv4-ID
    messenger project, but it does NOT send covert data over real network
    protocol fields.

It simulates:
    - CLI chat behavior
    - ChaCha20-Poly1305 encryption/decryption
    - message framing
    - 2-byte "IPv4-ID-like" chunking
    - START / DATA / END control flow
    - ACK
    - selective NACK
    - selective retransmission
    - full retransmission on authentication failure
    - receive buffer timeout cleanup
    - thread-safe session state

Install:
    pip install cryptography

Run:
    python3 stego_chat_simulator.py
"""

import os
import time
import struct
import hashlib
import queue
import random
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, List

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ============================================================
# Protocol constants
# ============================================================

MAGIC = b"NS"
VERSION = 1
MSG_TYPE_CHAT = 1

CHUNK_SIZE = 2

PKT_START = "START"
PKT_DATA = "DATA"
PKT_END = "END"
PKT_ACK = "ACK"
PKT_NACK = "NACK"
PKT_FULL_RETRY = "FULL_RETRY"

ASSOCIATED_DATA = b"network-stego-v2-simulator"

RX_BUFFER_TIMEOUT = 30
ACK_TIMEOUT = 3
MAX_FULL_RETRIES = 2


# ============================================================
# Data classes
# ============================================================

@dataclass
class SimulatedPacket:
    """
    This represents a protocol packet in the simulator.

    In the real ICMP/IPv4-ID design:
        session_id   -> ICMP Identifier
        message_id   -> START/control metadata
        chunk_number -> ICMP Sequence
        chunk_value  -> IPv4 Identification field

    In this simulator:
        all fields are local Python object fields.
    """
    packet_type: str
    session_id: int
    message_id: int
    chunk_number: Optional[int] = None
    chunk_value: Optional[int] = None
    total_chunks: Optional[int] = None
    missing_chunks: Optional[List[int]] = None


@dataclass
class MessageBuffer:
    message_id: int
    chunks: Dict[int, int] = field(default_factory=dict)
    total_chunks: Optional[int] = None
    created_at: float = field(default_factory=time.time)
    full_retry_count: int = 0


@dataclass
class ChatSession:
    local_name: str
    peer_name: str
    password: str
    session_id: int
    key: bytes

    running: bool = True
    debug: bool = False
    next_message_id: int = 1

    lock: threading.Lock = field(default_factory=threading.Lock)

    rx_queue: queue.Queue = field(default_factory=queue.Queue)
    tx_queue: queue.Queue = field(default_factory=queue.Queue)

    received_buffers: Dict[int, MessageBuffer] = field(default_factory=dict)
    acked_messages: Set[int] = field(default_factory=set)

    sent_messages: Dict[int, str] = field(default_factory=dict)
    sent_chunks: Dict[int, Dict[int, int]] = field(default_factory=dict)
    sent_total_chunks: Dict[int, int] = field(default_factory=dict)
    full_retry_count: Dict[int, int] = field(default_factory=dict)

    # Lab/test controls
    simulate_loss_percent: int = 0
    simulate_corrupt_percent: int = 0


# ============================================================
# Crypto and framing
# ============================================================

def derive_key(password: str, local_name: str, peer_name: str) -> bytes:
    """
    Derive a 32-byte ChaCha20-Poly1305 key.

    Both simulator peers must use the same password and endpoint names.
    """
    name_pair = "|".join(sorted([local_name, peer_name]))
    salt = hashlib.sha256(name_pair.encode("utf-8")).digest()

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,
        dklen=32,
    )


def build_plaintext(message_id: int, text: str) -> bytes:
    """
    Internal plaintext frame before encryption.

    Format:
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
        len(text_bytes),
    )

    return header + text_bytes


def parse_plaintext(data: bytes) -> Dict:
    header_size = struct.calcsize("!2sBBIIH")

    if len(data) < header_size:
        raise ValueError("Plaintext too short")

    magic, version, msg_type, message_id, timestamp, text_len = struct.unpack(
        "!2sBBIIH",
        data[:header_size],
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
        "text": text_bytes.decode("utf-8"),
    }


def encrypt_message(key: bytes, message_id: int, text: str) -> bytes:
    plaintext = build_plaintext(message_id, text)
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)

    encrypted = cipher.encrypt(
        nonce,
        plaintext,
        ASSOCIATED_DATA,
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
        ASSOCIATED_DATA,
    )

    return parse_plaintext(plaintext)


# ============================================================
# Chunking and reassembly
# ============================================================

def split_into_chunks(data: bytes) -> Dict[int, int]:
    """
    Split encrypted data into 2-byte chunks.

    This simulates the real design where each 2-byte value would fit into
    the IPv4 Identification field.
    """
    chunks: Dict[int, int] = {}

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


# ============================================================
# Simulated transport
# ============================================================

def maybe_drop_or_corrupt(session: ChatSession, pkt: SimulatedPacket) -> Optional[SimulatedPacket]:
    """
    Simulate packet loss and chunk corruption for testing reliability logic.
    """
    if session.simulate_loss_percent > 0:
        if random.randint(1, 100) <= session.simulate_loss_percent:
            if session.debug:
                print(f"[SIM] Dropped packet: {pkt}")
            return None

    if (
        pkt.packet_type == PKT_DATA
        and session.simulate_corrupt_percent > 0
        and pkt.chunk_value is not None
    ):
        if random.randint(1, 100) <= session.simulate_corrupt_percent:
            pkt = SimulatedPacket(
                packet_type=pkt.packet_type,
                session_id=pkt.session_id,
                message_id=pkt.message_id,
                chunk_number=pkt.chunk_number,
                chunk_value=pkt.chunk_value ^ 0x0001,
                total_chunks=pkt.total_chunks,
                missing_chunks=pkt.missing_chunks,
            )
            if session.debug:
                print(f"[SIM] Corrupted chunk {pkt.chunk_number} in message {pkt.message_id}")

    return pkt


def send_packet(session: ChatSession, pkt: SimulatedPacket) -> None:
    """
    Send packet into the peer queue.

    In this simulator, tx_queue points to the other side's rx_queue.
    """
    pkt = maybe_drop_or_corrupt(session, pkt)

    if pkt is None:
        return

    session.tx_queue.put(pkt)


def send_start(session: ChatSession, message_id: int) -> None:
    send_packet(
        session,
        SimulatedPacket(
            packet_type=PKT_START,
            session_id=session.session_id,
            message_id=message_id,
        ),
    )


def send_data_chunk(session: ChatSession, message_id: int, chunk_number: int, chunk_value: int) -> None:
    send_packet(
        session,
        SimulatedPacket(
            packet_type=PKT_DATA,
            session_id=session.session_id,
            message_id=message_id,
            chunk_number=chunk_number,
            chunk_value=chunk_value,
        ),
    )


def send_end(session: ChatSession, message_id: int, total_chunks: int) -> None:
    send_packet(
        session,
        SimulatedPacket(
            packet_type=PKT_END,
            session_id=session.session_id,
            message_id=message_id,
            total_chunks=total_chunks,
        ),
    )


def send_ack(session: ChatSession, message_id: int) -> None:
    send_packet(
        session,
        SimulatedPacket(
            packet_type=PKT_ACK,
            session_id=session.session_id,
            message_id=message_id,
        ),
    )

    if session.debug:
        print(f"[TX] ACK sent for message_id={message_id}")


def send_nack(session: ChatSession, message_id: int, missing_chunks: List[int]) -> None:
    send_packet(
        session,
        SimulatedPacket(
            packet_type=PKT_NACK,
            session_id=session.session_id,
            message_id=message_id,
            missing_chunks=missing_chunks,
        ),
    )

    if session.debug:
        print(f"[TX] NACK sent for message_id={message_id}, missing_chunks={missing_chunks}")


def send_full_retry_request(session: ChatSession, message_id: int) -> None:
    send_packet(
        session,
        SimulatedPacket(
            packet_type=PKT_FULL_RETRY,
            session_id=session.session_id,
            message_id=message_id,
        ),
    )

    if session.debug:
        print(f"[TX] FULL_RETRY request sent for message_id={message_id}")


# ============================================================
# Message transmission logic
# ============================================================

def prepare_message(session: ChatSession, message_id: int, text: str) -> Dict[int, int]:
    encrypted_blob = encrypt_message(session.key, message_id, text)
    chunks = split_into_chunks(encrypted_blob)

    with session.lock:
        session.sent_messages[message_id] = text
        session.sent_chunks[message_id] = chunks
        session.sent_total_chunks[message_id] = len(chunks)
        session.full_retry_count.setdefault(message_id, 0)

    return chunks


def transmit_prepared_message(session: ChatSession, message_id: int, delay: float = 0.01) -> None:
    with session.lock:
        chunks = dict(session.sent_chunks[message_id])
        total_chunks = session.sent_total_chunks[message_id]

    print(f"[sending message_id={message_id}, chunks={total_chunks}]")

    send_start(session, message_id)
    time.sleep(delay)

    for chunk_number, chunk_value in chunks.items():
        send_data_chunk(session, message_id, chunk_number, chunk_value)

        if session.debug:
            print(
                f"[TX] message_id={message_id}, "
                f"chunk={chunk_number:03d}, simulated-ip-id=0x{chunk_value:04X}"
            )

        time.sleep(delay)

    send_end(session, message_id, total_chunks)


def send_chat_message(session: ChatSession, text: str) -> None:
    with session.lock:
        message_id = session.next_message_id
        session.next_message_id += 1

    prepare_message(session, message_id, text)
    transmit_prepared_message(session, message_id)

    print("[sent, waiting for ACK]")

    start = time.time()
    while time.time() - start < ACK_TIMEOUT:
        with session.lock:
            if message_id in session.acked_messages:
                print("[delivered]\n")
                return

        time.sleep(0.1)

    print("[warning] No ACK received before timeout\n")


def retransmit_missing_chunks(session: ChatSession, message_id: int, missing_chunks: List[int]) -> None:
    with session.lock:
        chunks = dict(session.sent_chunks.get(message_id, {}))

    if not chunks:
        print(f"[warning] Cannot retransmit message_id={message_id}; chunks not found")
        return

    print(f"[retransmitting selective chunks for message_id={message_id}: {missing_chunks}]")

    for chunk_number in missing_chunks:
        if chunk_number not in chunks:
            print(f"[warning] Chunk {chunk_number} not found in sent cache")
            continue

        send_data_chunk(session, message_id, chunk_number, chunks[chunk_number])

        if session.debug:
            print(
                f"[TX] retransmitted message_id={message_id}, "
                f"chunk={chunk_number}, simulated-ip-id=0x{chunks[chunk_number]:04X}"
            )

        time.sleep(0.01)

    with session.lock:
        total_chunks = session.sent_total_chunks.get(message_id)

    if total_chunks is not None:
        send_end(session, message_id, total_chunks)


def full_retransmit(session: ChatSession, message_id: int) -> None:
    with session.lock:
        if message_id not in session.sent_messages:
            print(f"[warning] Cannot full retransmit message_id={message_id}; text not found")
            return

        retry_count = session.full_retry_count.get(message_id, 0)

        if retry_count >= MAX_FULL_RETRIES:
            print(f"[warning] Full retry limit reached for message_id={message_id}")
            return

        session.full_retry_count[message_id] = retry_count + 1
        text = session.sent_messages[message_id]

    print(f"[full retransmission message_id={message_id}, retry={retry_count + 1}]")

    # Important:
    # Full retransmission re-encrypts the full message and replaces all cached chunks.
    # Receiver should reset its buffer when START arrives again.
    prepare_message(session, message_id, text)
    transmit_prepared_message(session, message_id)


# ============================================================
# Receive logic
# ============================================================

def cleanup_old_buffers(session: ChatSession) -> None:
    now = time.time()

    with session.lock:
        expired = [
            msg_id
            for msg_id, buffer in session.received_buffers.items()
            if now - buffer.created_at > RX_BUFFER_TIMEOUT
        ]

        for msg_id in expired:
            del session.received_buffers[msg_id]

    for msg_id in expired:
        if session.debug:
            print(f"[RX] Expired receive buffer message_id={msg_id}")


def process_packet(session: ChatSession, pkt: SimulatedPacket) -> None:
    if pkt.session_id != session.session_id:
        return

    cleanup_old_buffers(session)

    if pkt.packet_type == PKT_ACK:
        with session.lock:
            session.acked_messages.add(pkt.message_id)

        if session.debug:
            print(f"\n[RX] ACK received for message_id={pkt.message_id}")

        return

    if pkt.packet_type == PKT_NACK:
        missing = pkt.missing_chunks or []

        print(
            f"\n[RX] NACK received | "
            f"message_id={pkt.message_id}, missing_chunks={missing}"
        )

        retransmit_missing_chunks(session, pkt.message_id, missing)
        print("me: ", end="", flush=True)
        return

    if pkt.packet_type == PKT_FULL_RETRY:
        print(f"\n[RX] FULL_RETRY request received for message_id={pkt.message_id}")
        full_retransmit(session, pkt.message_id)
        print("me: ", end="", flush=True)
        return

    if pkt.packet_type == PKT_START:
        with session.lock:
            # START resets existing buffer for same message_id.
            session.received_buffers[pkt.message_id] = MessageBuffer(
                message_id=pkt.message_id
            )

        if session.debug:
            print(f"\n[RX] START message_id={pkt.message_id}")

        return

    if pkt.packet_type == PKT_DATA:
        if pkt.chunk_number is None or pkt.chunk_value is None:
            return

        with session.lock:
            if pkt.message_id not in session.received_buffers:
                session.received_buffers[pkt.message_id] = MessageBuffer(
                    message_id=pkt.message_id
                )

            buffer = session.received_buffers[pkt.message_id]

            # Duplicate chunks are ignored if they already exist.
            if pkt.chunk_number not in buffer.chunks:
                buffer.chunks[pkt.chunk_number] = pkt.chunk_value

        if session.debug:
            print(
                f"\n[RX] DATA message_id={pkt.message_id}, "
                f"chunk={pkt.chunk_number:03d}, simulated-ip-id=0x{pkt.chunk_value:04X}"
            )

        return

    if pkt.packet_type == PKT_END:
        if pkt.total_chunks is None:
            return

        with session.lock:
            if pkt.message_id not in session.received_buffers:
                session.received_buffers[pkt.message_id] = MessageBuffer(
                    message_id=pkt.message_id
                )

            buffer = session.received_buffers[pkt.message_id]
            buffer.total_chunks = pkt.total_chunks

            missing_chunks = [
                chunk_no
                for chunk_no in range(1, pkt.total_chunks + 1)
                if chunk_no not in buffer.chunks
            ]

        if missing_chunks:
            print(
                f"\n[RX] Missing chunks for message_id={pkt.message_id}: "
                f"{missing_chunks}"
            )
            send_nack(session, pkt.message_id, missing_chunks)
            print("me: ", end="", flush=True)
            return

        try:
            with session.lock:
                chunks_copy = dict(buffer.chunks)
                total_chunks = buffer.total_chunks

            encrypted_blob = reassemble_chunks(chunks_copy, total_chunks)
            decoded = decrypt_message(session.key, encrypted_blob)

            print(f"\npeer: {decoded['text']}")
            print("me: ", end="", flush=True)

            send_ack(session, pkt.message_id)

            with session.lock:
                session.received_buffers.pop(pkt.message_id, None)

        except Exception as exc:
            print(f"\n[RX] Decryption/authentication failed for message_id={pkt.message_id}: {exc}")
            print("[RX] Selective NACK cannot identify corrupted chunk. Requesting full retransmission.")
            send_full_retry_request(session, pkt.message_id)
            print("me: ", end="", flush=True)

        return


def receiver_loop(session: ChatSession) -> None:
    while session.running:
        try:
            pkt = session.rx_queue.get(timeout=0.5)
            process_packet(session, pkt)
        except queue.Empty:
            cleanup_old_buffers(session)
            continue


# ============================================================
# CLI and commands
# ============================================================

def show_help() -> None:
    print("""
Commands:

@help              Show this help
@finish            Exit simulator
@status            Show session status
@debug on          Enable technical logs
@debug off         Disable technical logs
@loss N            Simulate packet loss percent, example: @loss 10
@corrupt N         Simulate chunk corruption percent, example: @corrupt 5
""")


def show_status(session: ChatSession) -> None:
    with session.lock:
        active_rx = list(session.received_buffers.keys())
        acked = sorted(session.acked_messages)
        sent = list(session.sent_messages.keys())
        cached_chunks = list(session.sent_chunks.keys())

    print("\nSession status")
    print("-" * 50)
    print(f"Local name:             {session.local_name}")
    print(f"Peer name:              {session.peer_name}")
    print(f"Session ID:             {session.session_id}")
    print(f"Next Msg ID:            {session.next_message_id}")
    print(f"Debug:                  {session.debug}")
    print(f"Simulated loss:         {session.simulate_loss_percent}%")
    print(f"Simulated corruption:   {session.simulate_corrupt_percent}%")
    print(f"Active RX Buffers:      {active_rx}")
    print(f"ACKed Messages:         {acked}")
    print(f"Stored TX Msgs:         {sent}")
    print(f"Cached TX Chunks:       {cached_chunks}")
    print("-" * 50 + "\n")


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

    elif command.startswith("@loss "):
        try:
            value = int(command.split()[1])
            session.simulate_loss_percent = max(0, min(100, value))
            print(f"Simulated packet loss set to {session.simulate_loss_percent}%")
        except Exception:
            print("Usage: @loss 10")

    elif command.startswith("@corrupt "):
        try:
            value = int(command.split()[1])
            session.simulate_corrupt_percent = max(0, min(100, value))
            print(f"Simulated corruption set to {session.simulate_corrupt_percent}%")
        except Exception:
            print("Usage: @corrupt 5")

    else:
        print("Unknown command. Type @help.")


# ============================================================
# Demo wiring: two simulated peers in one process
# ============================================================

def create_simulated_peer_pair(password: str) -> tuple[ChatSession, ChatSession]:
    """
    Create two local simulated peers:
        Alice <-> Bob

    The user controls Alice from CLI.
    Bob auto-replies to demonstrate full two-way protocol.
    """
    session_id = int.from_bytes(os.urandom(2), "big")

    alice_key = derive_key(password, "Alice", "Bob")
    bob_key = derive_key(password, "Bob", "Alice")

    alice_rx = queue.Queue()
    bob_rx = queue.Queue()

    alice = ChatSession(
        local_name="Alice",
        peer_name="Bob",
        password=password,
        session_id=session_id,
        key=alice_key,
        rx_queue=alice_rx,
        tx_queue=bob_rx,
    )

    bob = ChatSession(
        local_name="Bob",
        peer_name="Alice",
        password=password,
        session_id=session_id,
        key=bob_key,
        rx_queue=bob_rx,
        tx_queue=alice_rx,
    )

    return alice, bob


def bob_auto_reply_loop(bob: ChatSession) -> None:
    """
    Bob receives messages normally through receiver_loop.

    This simplified demo sends occasional manual-style replies when the user
    types messages to Alice. For a real two-terminal simulator, run two
    processes and connect queues via IPC.
    """
    receiver_loop(bob)


def main() -> None:
    print("=" * 72)
    print(" Network Steganography Messenger v2 - Safe Local Simulator")
    print(" Crypto / Chunking / ACK-NACK / Selective Retransmission / Timeouts")
    print("=" * 72)

    password = input("Enter shared password for simulator: ").strip()

    alice, bob = create_simulated_peer_pair(password)

    print(f"\nGenerated simulated session ID: {alice.session_id}")
    print("You are Alice. Peer is Bob.")
    print("Type @help for commands.")
    print("Type normal text to send a simulated encrypted/chunked message.\n")

    alice_rx_thread = threading.Thread(target=receiver_loop, args=(alice,), daemon=True)
    bob_rx_thread = threading.Thread(target=receiver_loop, args=(bob,), daemon=True)

    alice_rx_thread.start()
    bob_rx_thread.start()

    # Optional Bob auto response worker.
    # This keeps the simulator simple: user sends Alice->Bob;
    # Bob receives and ACKs. User can inspect delivery and reliability behavior.
    while alice.running:
        try:
            text = input("me: ").strip()

            if not text:
                continue

            if text.startswith("@"):
                handle_command(alice, text)

                # Mirror simulator conditions to Bob, so loss/corruption can be tested both ways if extended.
                bob.debug = alice.debug
                bob.simulate_loss_percent = alice.simulate_loss_percent
                bob.simulate_corrupt_percent = alice.simulate_corrupt_percent
                continue

            send_chat_message(alice, text)

        except KeyboardInterrupt:
            alice.running = False
            bob.running = False
            break

        except Exception as exc:
            print(f"[ERROR] {exc}")

    alice.running = False
    bob.running = False
    print("\nClosing simulator.")


if __name__ == "__main__":
    main()
'''

path = Path('/mnt/data/stego_chat_simulator.py')
path.write_text(code, encoding='utf-8')
print(f"Created: {path}")
print(f"Size: {path.stat().st_size} bytes")

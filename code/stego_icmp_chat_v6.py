#!/usr/bin/env python3

import os
import time
import struct
import hashlib
import hmac
import getpass
import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from scapy.all import IP, ICMP, Raw, send, sniff, sr1
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"NS"
VERSION = 1
MSG_TYPE_CHAT = 1
PLAINTEXT_HEADER_FORMAT = "!2sBBIIH"
PLAINTEXT_HEADER_SIZE = struct.calcsize(PLAINTEXT_HEADER_FORMAT)

CHUNK_SIZE = 2
MAX_ICMP_FIELD = 0xFFFF
MAX_DATA_SEQ = 65531
ENCRYPTION_OVERHEAD = 12 + 16
MAX_TEXT_BYTES = MAX_ICMP_FIELD - PLAINTEXT_HEADER_SIZE - ENCRYPTION_OVERHEAD

ICMP_START_SEQ = 0
ICMP_NACK_SEQ = 65532
ICMP_ACK_SEQ = 65533
ICMP_END_SEQ = 65534

COVER_PAYLOAD = b"NETWORK-STEG-LAB"
ASSOCIATED_DATA = b"network-stego-v2"
CONTROL_TAG_SIZE = 16
ACK_TIMEOUT_SECONDS = 3
MAX_SEND_ATTEMPTS = 3
HISTORY_LIMIT = 128


@dataclass
class MessageBuffer:
    message_id: int
    chunks: Dict[int, int] = field(default_factory=dict)
    total_chunks: Optional[int] = None
    total_bytes: Optional[int] = None
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
    active_rx_message_id: Optional[int] = None

    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    received_buffers: Dict[int, MessageBuffer] = field(default_factory=dict)
    acked_messages: Set[int] = field(default_factory=set)
    acked_message_order: List[int] = field(default_factory=list)
    delivered_rx_messages: Set[int] = field(default_factory=set)
    delivered_rx_order: List[int] = field(default_factory=list)
    sent_messages: Dict[int, str] = field(default_factory=dict)
    sent_chunks: Dict[int, Dict[int, int]] = field(default_factory=dict)
    sent_message_order: List[int] = field(default_factory=list)


def derive_key(password: str, local_ip: str, peer_ip: str) -> bytes:
    ip_pair = "|".join(sorted([local_ip, peer_ip]))
    salt = hashlib.sha256(ip_pair.encode()).digest()

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,
        dklen=32,
    )


def validate_ipv4(value: str, label: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid {label}: {value}") from exc


def validate_session_id(value: int) -> int:
    if not 0 <= value <= MAX_ICMP_FIELD:
        raise ValueError(f"Session ID must be between 0 and {MAX_ICMP_FIELD}")

    return value


def add_limited_history(item: int, values: Set[int], order: List[int]) -> None:
    if item in values:
        return

    values.add(item)
    order.append(item)

    while len(order) > HISTORY_LIMIT:
        oldest = order.pop(0)
        values.discard(oldest)


def remember_sent_message(session: ChatSession, message_id: int, text: str) -> None:
    if message_id not in session.sent_messages:
        session.sent_message_order.append(message_id)

    session.sent_messages[message_id] = text

    while len(session.sent_message_order) > HISTORY_LIMIT:
        oldest = session.sent_message_order.pop(0)
        session.sent_messages.pop(oldest, None)
        session.sent_chunks.pop(oldest, None)
        session.acked_messages.discard(oldest)


def mark_message_acked(session: ChatSession, message_id: int) -> None:
    add_limited_history(
        item=message_id,
        values=session.acked_messages,
        order=session.acked_message_order,
    )


def mark_message_delivered(session: ChatSession, message_id: int) -> None:
    add_limited_history(
        item=message_id,
        values=session.delivered_rx_messages,
        order=session.delivered_rx_order,
    )


def build_control_payload(
    key: bytes,
    session_id: int,
    marker: bytes,
    message_id: int,
    value: int = 0,
) -> bytes:
    header = struct.pack(
        "!2sHHH",
        marker,
        session_id & MAX_ICMP_FIELD,
        message_id & MAX_ICMP_FIELD,
        value & MAX_ICMP_FIELD,
    )
    tag = hmac.new(key, header, hashlib.sha256).digest()[:CONTROL_TAG_SIZE]

    return header + tag


def parse_control_payload(
    key: bytes,
    session_id: int,
    payload: bytes,
) -> tuple[bytes, int, int]:
    expected_size = struct.calcsize("!2sHHH") + CONTROL_TAG_SIZE

    if len(payload) < expected_size:
        raise ValueError("Control payload too short")

    header = payload[:struct.calcsize("!2sHHH")]
    tag = payload[struct.calcsize("!2sHHH"):expected_size]
    expected_tag = hmac.new(key, header, hashlib.sha256).digest()[:CONTROL_TAG_SIZE]

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Invalid control authentication tag")

    marker, payload_session_id, message_id, value = struct.unpack("!2sHHH", header)

    if payload_session_id != (session_id & MAX_ICMP_FIELD):
        raise ValueError("Control session ID mismatch")

    return marker, message_id, value


def build_plaintext(message_id: int, text: str) -> bytes:
    text_bytes = text.encode("utf-8")
    if len(text_bytes) > MAX_TEXT_BYTES:
        raise ValueError(f"Message text is too long; max {MAX_TEXT_BYTES} UTF-8 bytes")

    timestamp = int(time.time())

    header = struct.pack(
        PLAINTEXT_HEADER_FORMAT,
        MAGIC,
        VERSION,
        MSG_TYPE_CHAT,
        message_id,
        timestamp,
        len(text_bytes),
    )

    return header + text_bytes


def parse_plaintext(data: bytes) -> Dict:
    if len(data) < PLAINTEXT_HEADER_SIZE:
        raise ValueError("Plaintext too short")

    magic, version, msg_type, message_id, timestamp, text_len = struct.unpack(
        PLAINTEXT_HEADER_FORMAT,
        data[:PLAINTEXT_HEADER_SIZE],
    )

    if magic != MAGIC:
        raise ValueError("Invalid MAGIC")

    if version != VERSION:
        raise ValueError("Unsupported protocol version")

    if msg_type != MSG_TYPE_CHAT:
        raise ValueError("Unsupported message type")

    text_bytes = data[PLAINTEXT_HEADER_SIZE:PLAINTEXT_HEADER_SIZE + text_len]

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


def split_into_chunks(data: bytes) -> Dict[int, int]:
    chunks = {}

    if len(data) > MAX_ICMP_FIELD:
        raise ValueError(f"Encrypted message is too long; max {MAX_ICMP_FIELD} bytes")

    for index in range(0, len(data), CHUNK_SIZE):
        chunk_number = (index // CHUNK_SIZE) + 1

        if chunk_number > MAX_DATA_SEQ:
            raise ValueError(f"Message requires too many chunks; max {MAX_DATA_SEQ}")

        chunk = data[index:index + CHUNK_SIZE]

        if len(chunk) == 1:
            chunk += b"\x00"

        chunks[chunk_number] = int.from_bytes(chunk, "big")

    return chunks


def chunks_for_length(total_bytes: int) -> int:
    if total_bytes <= 0:
        raise ValueError("Invalid encrypted message length")

    return (total_bytes + CHUNK_SIZE - 1) // CHUNK_SIZE


def reassemble_chunks(chunks: Dict[int, int], total_chunks: int, total_bytes: int) -> bytes:
    result = bytearray()

    for chunk_number in range(1, total_chunks + 1):
        if chunk_number not in chunks:
            raise ValueError(f"Missing chunk {chunk_number}")

        result.extend(chunks[chunk_number].to_bytes(2, "big"))

    return bytes(result[:total_bytes])


def send_icmp_packet(
    dst_ip: str,
    session_id: int,
    seq: int,
    ip_id: int,
    src_ip: Optional[str] = None,
) -> None:
    ip_kwargs = {"dst": dst_ip, "id": ip_id & MAX_ICMP_FIELD}
    if src_ip:
        ip_kwargs["src"] = src_ip

    pkt = (
        IP(**ip_kwargs)
        / ICMP(type=8, code=0, id=session_id & MAX_ICMP_FIELD, seq=seq & MAX_ICMP_FIELD)
        / Raw(load=COVER_PAYLOAD)
    )

    send(pkt, verbose=False)


def check_connectivity(peer_ip: str, local_ip: Optional[str] = None, timeout: int = 2) -> bool:
    print("[check] Sending normal ICMP Echo Request...")

    ip_kwargs = {"dst": peer_ip}
    if local_ip:
        ip_kwargs["src"] = local_ip

    pkt = (
        IP(**ip_kwargs)
        / ICMP(type=8, code=0)
        / Raw(load=b"CONNECTIVITY-CHECK")
    )

    reply = sr1(pkt, timeout=timeout, verbose=False)

    if reply and ICMP in reply:
        print("[check] Connectivity OK.\n")
        return True

    print("[check] No ICMP reply received.\n")
    return False


def send_ack(session: ChatSession, message_id: int) -> None:
    payload = build_control_payload(
        key=session.key,
        session_id=session.session_id,
        marker=b"AK",
        message_id=message_id,
    )

    send_control_packet(
        dst_ip=session.peer_ip,
        session_id=session.session_id,
        seq=ICMP_ACK_SEQ,
        ip_id=message_id,
        payload=payload,
        src_ip=session.local_ip,
    )

    if session.debug:
        print(f"[TX] ACK sent for message_id={message_id}")


def send_nack(session: ChatSession, message_id: int, missing_chunks: list[int]) -> None:
    for chunk_number in missing_chunks:
        payload = build_control_payload(
            key=session.key,
            session_id=session.session_id,
            marker=b"NK",
            message_id=message_id,
            value=chunk_number,
        )

        send_control_packet(
            dst_ip=session.peer_ip,
            session_id=session.session_id,
            seq=ICMP_NACK_SEQ,
            ip_id=message_id,
            payload=payload,
            src_ip=session.local_ip,
        )

        if session.debug:
            print(f"[TX] NACK sent | message_id={message_id}, missing_chunk={chunk_number}")


def transmit_message_by_id(
    session: ChatSession,
    message_id: int,
    text: str,
    delay: float = 0.03,
    retransmit: bool = False,
) -> None:
    with session.lock:
        key = session.key
        peer_ip = session.peer_ip
        local_ip = session.local_ip
        session_id = session.session_id

    encrypted_blob = encrypt_message(key, message_id, text)
    chunks = split_into_chunks(encrypted_blob)

    with session.lock:
        session.sent_chunks[message_id] = chunks

    if retransmit:
        print(f"[retransmitting message_id={message_id}, chunks={len(chunks)}]")
    else:
        print(f"[sending message_id={message_id}, chunks={len(chunks)}]")

    send_icmp_packet(
        dst_ip=peer_ip,
        session_id=session_id,
        seq=ICMP_START_SEQ,
        ip_id=message_id,
        src_ip=local_ip,
    )

    time.sleep(delay)

    for chunk_number, ip_id_value in chunks.items():
        send_icmp_packet(
            dst_ip=peer_ip,
            session_id=session_id,
            seq=chunk_number,
            ip_id=ip_id_value,
            src_ip=local_ip,
        )

        if session.debug:
            print(f"[TX] chunk={chunk_number:03d}, ip_id=0x{ip_id_value:04X}")

        time.sleep(delay)

    send_icmp_packet(
        dst_ip=peer_ip,
        session_id=session_id,
        seq=ICMP_END_SEQ,
        ip_id=len(encrypted_blob),
        src_ip=local_ip,
    )

    if retransmit:
        print("[retransmit sent]")
    else:
        print("[sent, waiting for ACK]")


def send_stego_message(session: ChatSession, text: str) -> None:
    with session.lock:
        message_id = session.next_message_id
        session.next_message_id = (session.next_message_id % MAX_ICMP_FIELD) + 1
        remember_sent_message(session, message_id, text)

    for attempt in range(1, MAX_SEND_ATTEMPTS + 1):
        transmit_message_by_id(
            session=session,
            message_id=message_id,
            text=text,
            retransmit=attempt > 1,
        )

        wait_start = time.time()

        while time.time() - wait_start < ACK_TIMEOUT_SECONDS:
            with session.lock:
                if message_id in session.acked_messages:
                    print("[delivered]\n")
                    return

            time.sleep(0.1)

        if attempt < MAX_SEND_ATTEMPTS:
            print(f"[warning] No ACK received; retrying {attempt + 1}/{MAX_SEND_ATTEMPTS}")

    print("[warning] No ACK received after retries\n")


def retransmit_message(session: ChatSession, message_id: int) -> None:
    with session.lock:
        if message_id not in session.sent_messages:
            print(f"[warning] Cannot retransmit message_id={message_id}; original text not found")
            return

        text = session.sent_messages[message_id]

    transmit_message_by_id(
        session=session,
        message_id=message_id,
        text=text,
        retransmit=True,
    )


def try_complete_received_message(session: ChatSession, message_id: int) -> bool:
    if message_id not in session.received_buffers:
        return False

    buffer = session.received_buffers[message_id]

    if buffer.total_chunks is None:
        return False

    if buffer.total_bytes is None:
        return False

    missing_chunks = [
        chunk_no
        for chunk_no in range(1, buffer.total_chunks + 1)
        if chunk_no not in buffer.chunks
    ]

    if missing_chunks:
        print(f"\n[RX] Missing chunks for message_id={message_id}: {missing_chunks}")

        send_nack(
            session=session,
            message_id=message_id,
            missing_chunks=missing_chunks,
        )

        print("me: ", end="", flush=True)
        return False

    try:
        encrypted_blob = reassemble_chunks(
            chunks=buffer.chunks,
            total_chunks=buffer.total_chunks,
            total_bytes=buffer.total_bytes,
        )

        decoded = decrypt_message(
            key=session.key,
            encrypted_blob=encrypted_blob,
        )

        if decoded["message_id"] != message_id:
            raise ValueError("Decoded message ID mismatch")

        duplicate = message_id in session.delivered_rx_messages

        if not duplicate:
            print(f"\npeer: {decoded['text']}")
            mark_message_delivered(session, message_id)
        elif session.debug:
            print(f"\n[RX] Duplicate message_id={message_id}; ACK resent")

        print("me: ", end="", flush=True)

        send_ack(session, message_id)

        del session.received_buffers[message_id]

        if session.active_rx_message_id == message_id:
            session.active_rx_message_id = None

        return True

    except Exception as exc:
        print(f"\n[RX] Decode failed: {exc}")
        del session.received_buffers[message_id]

        if session.active_rx_message_id == message_id:
            session.active_rx_message_id = None

        print("me: ", end="", flush=True)
        return False


def process_received_packet(session: ChatSession, pkt) -> None:
    with session.lock:
        process_received_packet_locked(session, pkt)


def process_received_packet_locked(session: ChatSession, pkt) -> None:
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

    if seq == ICMP_ACK_SEQ:
        try:
            raw_payload = bytes(pkt[Raw].load)
            marker, message_id, _ = parse_control_payload(
                key=session.key,
                session_id=session.session_id,
                payload=raw_payload,
            )

            if marker != b"AK" or message_id != ip_id:
                return

            mark_message_acked(session, message_id)

        except Exception as exc:
            if session.debug:
                print(f"\n[RX] Invalid ACK packet: {exc}")
            return

        if session.debug:
            print(f"\n[RX] ACK received for message_id={ip_id}")

        return

    if seq == ICMP_NACK_SEQ:
        try:
            raw_payload = bytes(pkt[Raw].load)
            marker, message_id, missing_chunk = parse_control_payload(
                key=session.key,
                session_id=session.session_id,
                payload=raw_payload,
            )

            if marker != b"NK" or message_id != ip_id:
                return

            print(
                f"\n[RX] NACK received | "
                f"message_id={message_id}, missing_chunk={missing_chunk}"
            )

            retransmit_missing_chunk(
                session=session,
                message_id=message_id,
                chunk_number=missing_chunk,
            )

            print("me: ", end="", flush=True)

        except Exception as exc:
            if session.debug:
                print(f"\n[RX] Invalid NACK packet: {exc}")

        return

    if seq == ICMP_START_SEQ:
        message_id = ip_id

        if session.active_rx_message_id is not None and session.active_rx_message_id != message_id:
            if session.debug:
                print(
                    f"\n[RX] START message_id={message_id} replaced "
                    f"incomplete message_id={session.active_rx_message_id}"
                )

            session.received_buffers.pop(session.active_rx_message_id, None)

        session.received_buffers[message_id] = MessageBuffer(
            message_id=message_id,
        )
        session.active_rx_message_id = message_id

        if session.debug:
            print(f"\n[RX] START message_id={message_id}")

        return

    if seq == ICMP_END_SEQ:
        total_bytes = ip_id

        if session.active_rx_message_id is None:
            if session.debug:
                print("\n[RX] END ignored: no active message")
            return

        message_id = session.active_rx_message_id
        buffer = session.received_buffers[message_id]
        buffer.total_bytes = total_bytes
        buffer.total_chunks = chunks_for_length(total_bytes)

        try_complete_received_message(session, message_id)

        return

    if 0 < seq < ICMP_END_SEQ:
        if session.active_rx_message_id is None:
            if session.debug:
                print("\n[RX] DATA ignored: no START")
            return

        message_id = session.active_rx_message_id
        buffer = session.received_buffers[message_id]

        buffer.chunks[seq] = ip_id

        if session.debug:
            print(f"\n[RX] DATA chunk={seq:03d}, ip_id=0x{ip_id:04X}")

        if buffer.total_chunks is not None:
            try_complete_received_message(session, message_id)

        return


def receiver_thread(session: ChatSession) -> None:
    def should_stop(_) -> bool:
        with session.lock:
            return not session.running

    sniff(
        filter="icmp",
        prn=lambda pkt: process_received_packet(session, pkt),
        stop_filter=should_stop,
        store=False,
    )


def change_destination_ip(session: ChatSession) -> None:
    new_ip = input("Enter new peer IP: ").strip()

    if not new_ip:
        print("Peer IP not changed.")
        return

    try:
        new_ip = validate_ipv4(new_ip, "peer IP")
    except ValueError as exc:
        print(exc)
        return

    with session.lock:
        old_ip = session.peer_ip
        session.peer_ip = new_ip

        session.key = derive_key(
            session.password,
            session.local_ip,
            session.peer_ip,
        )

        session.active_rx_message_id = None
        session.received_buffers.clear()
        session.acked_messages.clear()
        session.acked_message_order.clear()
        session.delivered_rx_messages.clear()
        session.delivered_rx_order.clear()
        session.sent_messages.clear()
        session.sent_chunks.clear()
        session.sent_message_order.clear()

    print(f"Peer IP changed: {old_ip} -> {session.peer_ip}")
    print("Encryption key regenerated because peer IP changed.")


def change_password(session: ChatSession) -> None:
    new_password = getpass.getpass("Enter new shared password: ").strip()

    if not new_password:
        print("Password not changed.")
        return

    with session.lock:
        session.password = new_password

        session.key = derive_key(
            session.password,
            session.local_ip,
            session.peer_ip,
        )

        session.active_rx_message_id = None
        session.received_buffers.clear()
        session.acked_messages.clear()
        session.acked_message_order.clear()
        session.delivered_rx_messages.clear()
        session.delivered_rx_order.clear()
        session.sent_messages.clear()
        session.sent_chunks.clear()
        session.sent_message_order.clear()

    print("Password changed.")
    print("Encryption key regenerated.")
    print("Important: peer must use the same password.")


def show_help() -> None:
    print("""
Commands:

@help          Show this help
@finish        Exit program
@status        Show session status
@check         Run ICMP connectivity check
@changeip      Change destination/peer IP
@password      Change shared password
@resend <id>   Retransmit a previous message
@debug on      Enable technical logs
@debug off     Disable technical logs
""")


def show_status(session: ChatSession) -> None:
    with session.lock:
        local_ip = session.local_ip
        peer_ip = session.peer_ip
        session_id = session.session_id
        next_message_id = session.next_message_id
        debug = session.debug
        active_rx_buffers = len(session.received_buffers)
        acked_messages = sorted(session.acked_messages)
        stored_tx_messages = list(session.sent_messages.keys())

    print("\nSession status")
    print("-" * 45)
    print(f"Local IP:          {local_ip}")
    print(f"Peer IP:           {peer_ip}")
    print(f"Session ID:        {session_id}")
    print(f"Next Msg ID:       {next_message_id}")
    print(f"Debug:             {debug}")
    print(f"Active RX Buffers: {active_rx_buffers}")
    print(f"ACKed Messages:    {acked_messages}")
    print(f"Stored TX Msgs:    {stored_tx_messages}")
    print("-" * 45 + "\n")


def handle_command(session: ChatSession, command: str) -> None:
    if command == "@help":
        show_help()

    elif command == "@finish":
        with session.lock:
            session.running = False

    elif command == "@status":
        show_status(session)

    elif command == "@check":
        with session.lock:
            peer_ip = session.peer_ip
            local_ip = session.local_ip

        check_connectivity(peer_ip, local_ip=local_ip)

    elif command in ("@changeip", "@changedstip"):
        change_destination_ip(session)

    elif command == "@password":
        change_password(session)

    elif command.startswith("@resend "):
        try:
            message_id = int(command.split(maxsplit=1)[1])
            validate_session_id(message_id)
            retransmit_message(session, message_id)
        except ValueError as exc:
            print(f"Invalid message ID: {exc}")

    elif command == "@debug on":
        with session.lock:
            session.debug = True
        print("Debug enabled.")

    elif command == "@debug off":
        with session.lock:
            session.debug = False
        print("Debug disabled.")

    else:
        print("Unknown command. Type @help.")
        
def send_control_packet(
    dst_ip: str,
    session_id: int,
    seq: int,
    ip_id: int,
    payload: bytes,
    src_ip: Optional[str] = None,
) -> None:
    ip_kwargs = {"dst": dst_ip, "id": ip_id & MAX_ICMP_FIELD}
    if src_ip:
        ip_kwargs["src"] = src_ip

    pkt = (
        IP(**ip_kwargs)
        / ICMP(type=8, code=0, id=session_id & MAX_ICMP_FIELD, seq=seq & MAX_ICMP_FIELD)
        / Raw(load=payload)
    )

    send(pkt, verbose=False)

def retransmit_missing_chunk(session: ChatSession, message_id: int, chunk_number: int) -> None:
    with session.lock:
        if message_id not in session.sent_chunks:
            print(f"[warning] Cannot retransmit message_id={message_id}; chunks not found")
            return

        chunks = session.sent_chunks[message_id]

        if chunk_number not in chunks:
            print(f"[warning] Cannot retransmit chunk={chunk_number}; not found")
            return

        ip_id_value = chunks[chunk_number]
        peer_ip = session.peer_ip
        local_ip = session.local_ip
        session_id = session.session_id

    send_icmp_packet(
        dst_ip=peer_ip,
        session_id=session_id,
        seq=chunk_number,
        ip_id=ip_id_value,
        src_ip=local_ip,
    )

    if session.debug:
        print(
            f"[TX] retransmitted chunk={chunk_number}, "
            f"message_id={message_id}, ip_id=0x{ip_id_value:04X}"
        )


def main() -> None:
    print("=" * 70)
    print(" Network Steganography Messenger v2")
    print(" ICMP Echo / IPv4 Identification / ChaCha20-Poly1305 / ACK-NACK")
    print("=" * 70)

    try:
        local_ip = validate_ipv4(input("Enter local IP: ").strip(), "local IP")
        peer_ip = validate_ipv4(input("Enter peer IP: ").strip(), "peer IP")
    except ValueError as exc:
        print(exc)
        return

    password = getpass.getpass("Enter shared password: ").strip()

    if not password:
        print("Shared password cannot be empty.")
        return

    print("\nSession ID mode:")
    print("1. Generate new session ID")
    print("2. Enter existing session ID")

    mode = input("Choose 1 or 2: ").strip()

    if mode == "1":
        session_id = int.from_bytes(os.urandom(2), "big")
        print(f"\nGenerated session ID: {session_id}")
        print("The peer must enter this same session ID.")
    else:
        try:
            session_id = validate_session_id(int(input("Enter session ID: ").strip()))
        except ValueError as exc:
            print(exc)
            return

    key = derive_key(
        password=password,
        local_ip=local_ip,
        peer_ip=peer_ip,
    )

    session = ChatSession(
        local_ip=local_ip,
        peer_ip=peer_ip,
        password=password,
        session_id=session_id,
        key=key,
    )

    thread = threading.Thread(
        target=receiver_thread,
        args=(session,),
        daemon=True,
    )
    thread.start()

    print("\nReceiver thread started.")
    check_connectivity(peer_ip, local_ip=local_ip)

    print("Type @help for commands.")
    print("Start chatting.\n")

    while True:
        with session.lock:
            if not session.running:
                break

        try:
            text = input("me: ").strip()

            if not text:
                continue

            if text.startswith("@"):
                handle_command(session, text)
                continue

            send_stego_message(session, text)

        except KeyboardInterrupt:
            with session.lock:
                session.running = False
            break

        except Exception as exc:
            print(f"[ERROR] {exc}")

    print("\nClosing messenger.")


if __name__ == "__main__":
    main()

#####################################################################################################
#                             Network Steganography Messenger                                       #
#####################################################################################################
"""
Network Steganography Messenger v6
==================================

Purpose
-------
This program implements a two-party command-line chat that hides encrypted
message data inside ordinary-looking ICMP Echo Request packets. It is designed
for controlled lab use and protocol experimentation, not for production
security or unauthorized network activity.

High-Level Design
-----------------
Each chat message is processed through these stages:

1. The user types plaintext into the local terminal.
2. The plaintext is wrapped in a small internal protocol header containing:
   - a magic marker (`MAGIC`) to identify this protocol,
   - a protocol version (`VERSION`),
   - a message type (`MSG_TYPE_CHAT`),
   - a 16-bit message identifier,
   - a Unix timestamp,
   - the UTF-8 byte length of the text.
3. The plaintext header and message body are encrypted with ChaCha20-Poly1305.
   The encrypted blob is:
   - 12-byte nonce,
   - ciphertext,
   - 16-byte Poly1305 authentication tag.
4. The encrypted blob is split into 2-byte chunks.
5. Each chunk is converted into a 16-bit integer and placed in the IPv4
   Identification field (`IP.id`) of an ICMP Echo Request.
6. The ICMP sequence field (`ICMP.seq`) identifies packet role:
   - `0` starts a message,
   - `1..65531` are encrypted data chunk numbers,
   - `65532` is a NACK control packet,
   - `65533` is an ACK control packet,
   - `65534` ends a message and carries the encrypted byte length.
7. The peer reassembles chunks in order, trims any padding byte from the last
   chunk, decrypts the encrypted blob, validates the plaintext header, prints
   the message, and sends an authenticated ACK.

Reliability Model
-----------------
ICMP does not guarantee delivery, ordering, or uniqueness. This program adds a
small reliability layer:

- START and END packets frame one active inbound message at a time.
- Missing data chunks are requested with authenticated NACK packets.
- Successful decode is confirmed with authenticated ACK packets.
- The sender retries a full message when no ACK arrives before timeout.
- Duplicate received messages are suppressed but ACKed again so a peer can
  recover from a lost ACK.

Security Model
--------------
Message confidentiality and integrity are provided by ChaCha20-Poly1305 using a
key derived from:

- shared password,
- local IP address,
- peer IP address.

ACK/NACK control packets are not encrypted, but they are authenticated with an
HMAC-SHA256 tag truncated to 16 bytes. This prevents unauthenticated control
packets from marking messages as delivered or forcing retransmission.

Operational Notes
-----------------
- Both peers must use the same password, peer/local IP pairing, and session ID.
- Both peers must use this same protocol version; older unauthenticated
  ACK/NACK packets are intentionally rejected.
- Sending raw ICMP packets usually requires administrator/root privileges.
- Firewalls, NAT, VPNs, OS ICMP policies, or routers may rewrite, block, or
  rate-limit ICMP traffic.
- This program tracks one active inbound message at a time. It is intended for
  interactive chat, not high-throughput concurrent message streams.
"""

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


# ---------------------------------------------------------------------------
# Protocol identifiers and plaintext message format
# ---------------------------------------------------------------------------

# Two-byte magic value stored inside the encrypted plaintext header. It lets the
# receiver reject decrypted bytes that do not belong to this protocol.
MAGIC = b"NS"

# Increment this when the encrypted plaintext header/body format changes in a
# backward-incompatible way.
VERSION = 1

# Only one application-level message type is currently implemented: chat text.
MSG_TYPE_CHAT = 1

# Encrypted plaintext header format:
#   2s = magic marker
#   B  = protocol version
#   B  = message type
#   I  = message ID
#   I  = Unix timestamp
#   H  = UTF-8 text length
PLAINTEXT_HEADER_FORMAT = "!2sBBIIH"
PLAINTEXT_HEADER_SIZE = struct.calcsize(PLAINTEXT_HEADER_FORMAT)


# ---------------------------------------------------------------------------
# ICMP/IPv4 field limits and chunking rules
# ---------------------------------------------------------------------------

# IPv4 Identification is 16 bits. The protocol stores exactly two encrypted
# bytes per data packet by mapping those bytes into this field.
CHUNK_SIZE = 2

# Maximum integer representable in the 16-bit IPv4 Identification and ICMP
# sequence fields.
MAX_ICMP_FIELD = 0xFFFF

# Data chunk sequence numbers stop before reserved control values.
MAX_DATA_SEQ = 65531

# ChaCha20-Poly1305 framing overhead: 12-byte nonce + 16-byte authentication
# tag. Ciphertext length itself equals plaintext length.
ENCRYPTION_OVERHEAD = 12 + 16

# Maximum user text length that still allows the complete encrypted blob to fit
# into the 16-bit END length field.
MAX_TEXT_BYTES = MAX_ICMP_FIELD - PLAINTEXT_HEADER_SIZE - ENCRYPTION_OVERHEAD


# ---------------------------------------------------------------------------
# Reserved ICMP sequence numbers
# ---------------------------------------------------------------------------

# START and END frame one logical message. ACK and NACK are authenticated
# control packets carried in the Raw payload.
ICMP_START_SEQ = 0
ICMP_NACK_SEQ = 65532
ICMP_ACK_SEQ = 65533
ICMP_END_SEQ = 65534


# ---------------------------------------------------------------------------
# Packet payloads, authentication, retry, and retention settings
# ---------------------------------------------------------------------------

# Normal data packets carry a fixed cover payload. The hidden data is not in the
# Raw payload; it is in IPv4 Identification.
COVER_PAYLOAD = b"NETWORK-STEG-LAB"

# AEAD associated data binds ciphertexts to this application/protocol context.
# It is authenticated but not encrypted and is not transmitted.
ASSOCIATED_DATA = b"network-stego-v2"

# Truncated HMAC tag size for ACK/NACK control packets.
CONTROL_TAG_SIZE = 16

# Sender waits this long for ACK before trying a full retransmission.
ACK_TIMEOUT_SECONDS = 3

# Total full-message send attempts before warning the user.
MAX_SEND_ATTEMPTS = 3

# Upper bound for remembered sent/ACK/delivered message IDs. This prevents
# long-running sessions from retaining unlimited plaintext and metadata.
HISTORY_LIMIT = 128


@dataclass
class MessageBuffer:
    """
    Temporary receive-side storage for one inbound message.

    Data chunks may arrive before the END packet, and retransmitted chunks may
    arrive after a NACK. This buffer keeps all chunks until the receiver knows
    the total encrypted byte length and can attempt decryption.
    """

    # Message identifier from the START packet IPv4 Identification field.
    message_id: int

    # Map of chunk_number -> 16-bit encrypted data value from IPv4 ID.
    chunks: Dict[int, int] = field(default_factory=dict)

    # Expected number of 2-byte chunks. This is known after the END packet
    # provides total encrypted byte length.
    total_chunks: Optional[int] = None

    # Exact encrypted blob size in bytes. This is needed because the final
    # 2-byte chunk may have one padding byte.
    total_bytes: Optional[int] = None

    # Timestamp used for diagnostics/future cleanup policies.
    created_at: float = field(default_factory=time.time)


@dataclass
class ChatSession:
    """
    Mutable runtime state shared by the input thread and receiver thread.

    The main thread reads user input and sends messages. The Scapy sniff thread
    processes inbound ICMP packets. Because both threads touch the same session
    fields, code that reads or mutates shared state should hold `lock`.
    """

    # Local/peer identity and shared cryptographic material.
    local_ip: str
    peer_ip: str
    password: str
    session_id: int
    key: bytes

    # Runtime flags and message sequencing.
    running: bool = True
    debug: bool = False
    next_message_id: int = 1

    # The receiver currently supports one active inbound framed message. This
    # value identifies the buffer to which DATA and END packets belong.
    active_rx_message_id: Optional[int] = None

    # Re-entrant lock is used because packet processing may call helpers that
    # also inspect session state.
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # Receive buffers keyed by message ID.
    received_buffers: Dict[int, MessageBuffer] = field(default_factory=dict)

    # Recently ACKed outbound messages. The set gives fast membership checks;
    # the list preserves insertion order for bounded cleanup.
    acked_messages: Set[int] = field(default_factory=set)
    acked_message_order: List[int] = field(default_factory=list)

    # Recently delivered inbound messages. This suppresses duplicate printing
    # when the sender retransmits after losing our ACK.
    delivered_rx_messages: Set[int] = field(default_factory=set)
    delivered_rx_order: List[int] = field(default_factory=list)

    # Recent outbound plaintext and encrypted chunks. These are needed for
    # manual resend and per-chunk NACK retransmission.
    sent_messages: Dict[int, str] = field(default_factory=dict)
    sent_chunks: Dict[int, Dict[int, int]] = field(default_factory=dict)
    sent_message_order: List[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Key derivation and input validation helpers
# ---------------------------------------------------------------------------

def derive_key(password: str, local_ip: str, peer_ip: str) -> bytes:
    """
    Derive the 32-byte ChaCha20-Poly1305 key for this peer pair.

    The salt is based on the sorted IP pair, so both peers derive the same key
    even though each peer enters local/peer IP in opposite order.
    """

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
    """Validate and normalize a user-provided IPv4 address string."""

    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid {label}: {value}") from exc


def validate_session_id(value: int) -> int:
    """Ensure the session ID fits into the 16-bit ICMP identifier field."""

    if not 0 <= value <= MAX_ICMP_FIELD:
        raise ValueError(f"Session ID must be between 0 and {MAX_ICMP_FIELD}")

    return value


# ---------------------------------------------------------------------------
# Bounded history helpers
# ---------------------------------------------------------------------------

def add_limited_history(item: int, values: Set[int], order: List[int]) -> None:
    """
    Add an integer item to a bounded set/list pair.

    `values` supports fast membership tests; `order` remembers insertion order
    so the oldest items can be removed when the limit is exceeded.
    """

    if item in values:
        return

    values.add(item)
    order.append(item)

    while len(order) > HISTORY_LIMIT:
        oldest = order.pop(0)
        values.discard(oldest)


def remember_sent_message(session: ChatSession, message_id: int, text: str) -> None:
    """
    Store outbound plaintext and keep only the latest HISTORY_LIMIT messages.

    Plaintext is retained only so the program can retransmit complete messages
    or respond to NACK requests. Old entries are removed to control memory use
    and avoid retaining unnecessary sensitive data.
    """

    if message_id not in session.sent_messages:
        session.sent_message_order.append(message_id)

    session.sent_messages[message_id] = text

    while len(session.sent_message_order) > HISTORY_LIMIT:
        oldest = session.sent_message_order.pop(0)
        session.sent_messages.pop(oldest, None)
        session.sent_chunks.pop(oldest, None)
        session.acked_messages.discard(oldest)


def mark_message_acked(session: ChatSession, message_id: int) -> None:
    """Record that a sent message has been acknowledged by the peer."""

    add_limited_history(
        item=message_id,
        values=session.acked_messages,
        order=session.acked_message_order,
    )


def mark_message_delivered(session: ChatSession, message_id: int) -> None:
    """Record that an inbound message has already been printed locally."""

    add_limited_history(
        item=message_id,
        values=session.delivered_rx_messages,
        order=session.delivered_rx_order,
    )


# ---------------------------------------------------------------------------
# Authenticated ACK/NACK control payloads
# ---------------------------------------------------------------------------

def build_control_payload(
    key: bytes,
    session_id: int,
    marker: bytes,
    message_id: int,
    value: int = 0,
) -> bytes:
    """
    Build an authenticated control payload for ACK or NACK packets.

    The payload is small and visible in the ICMP Raw layer, but it includes an
    HMAC tag. A peer accepts the control packet only if it can recompute the tag
    with the shared session key.

    `marker` is:
    - b"AK" for ACK,
    - b"NK" for NACK.

    `value` is currently used as the missing chunk number for NACK packets and
    zero for ACK packets.
    """

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
    """
    Validate and unpack an authenticated ACK/NACK control payload.

    Raises ValueError when the packet is malformed, has the wrong session ID, or
    fails HMAC verification.
    """

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
    """
    Build the encrypted-message plaintext before AEAD encryption.

    This plaintext is never sent directly. It is wrapped with protocol metadata
    so the receiver can validate version/type/length after decryption.
    """

    text_bytes = text.encode("utf-8")

    # The END packet carries encrypted byte length in a 16-bit field, so the
    # user text must leave room for plaintext header and AEAD overhead.
    if len(text_bytes) > MAX_TEXT_BYTES:
        raise ValueError(f"Message text is too long; max {MAX_TEXT_BYTES} UTF-8 bytes")

    timestamp = int(time.time())

    # Network byte order (`!`) makes the header deterministic across platforms.
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
    """
    Parse and validate decrypted plaintext.

    AEAD authentication has already verified that the encrypted blob was not
    modified. These checks validate the internal application protocol fields.
    """

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

    # Text length is explicit so the receiver can reject truncated plaintext.
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
    """
    Convert user text into an authenticated encrypted blob.

    Return format:
        nonce || ciphertext || poly1305_tag

    The nonce is randomly generated for every message. Reusing a nonce with the
    same key would be unsafe, so os.urandom(12) is used per message.
    """

    plaintext = build_plaintext(message_id, text)

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)

    # Associated data is authenticated with the ciphertext. A ciphertext from a
    # different protocol context will fail to decrypt here.
    encrypted = cipher.encrypt(
        nonce,
        plaintext,
        ASSOCIATED_DATA,
    )

    return nonce + encrypted


def decrypt_message(key: bytes, encrypted_blob: bytes) -> Dict:
    """
    Decrypt and parse an encrypted message blob.

    ChaCha20-Poly1305 verifies the Poly1305 tag before returning plaintext. If
    any byte of nonce/ciphertext/tag is wrong, `cipher.decrypt` raises.
    """

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
    """
    Split encrypted bytes into 2-byte values for IPv4 Identification.

    Each data packet carries:
        ICMP.seq = chunk number
        IP.id    = two encrypted bytes interpreted as a big-endian integer

    If the final encrypted blob length is odd, one zero byte is added only for
    transport. The exact encrypted byte length from END removes this padding
    during reassembly.
    """

    chunks = {}

    if len(data) > MAX_ICMP_FIELD:
        raise ValueError(f"Encrypted message is too long; max {MAX_ICMP_FIELD} bytes")

    for index in range(0, len(data), CHUNK_SIZE):
        chunk_number = (index // CHUNK_SIZE) + 1

        # Sequence numbers 65532..65534 are reserved for control packets.
        if chunk_number > MAX_DATA_SEQ:
            raise ValueError(f"Message requires too many chunks; max {MAX_DATA_SEQ}")

        chunk = data[index:index + CHUNK_SIZE]

        if len(chunk) == 1:
            chunk += b"\x00"

        chunks[chunk_number] = int.from_bytes(chunk, "big")

    return chunks


def chunks_for_length(total_bytes: int) -> int:
    """Return how many 2-byte chunks are required for total_bytes."""

    if total_bytes <= 0:
        raise ValueError("Invalid encrypted message length")

    return (total_bytes + CHUNK_SIZE - 1) // CHUNK_SIZE


def reassemble_chunks(chunks: Dict[int, int], total_chunks: int, total_bytes: int) -> bytes:
    """
    Rebuild encrypted bytes from received chunk values.

    The function requires every chunk from 1..total_chunks. After concatenating
    two-byte values, it trims to total_bytes to remove possible final padding.
    """

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
    """
    Send one ICMP Echo Request used for START, DATA, ACK-like framing, or END.

    For data packets, the hidden value is in IPv4 Identification (`ip_id`), not
    in the Raw payload. The Raw payload remains a constant cover string.
    """

    # Binding `src` helps multi-interface hosts send from the same IP that the
    # peer expects and that was used in key derivation.
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
    """
    Send a normal ICMP Echo Request to verify basic network reachability.

    This check is not encrypted or steganographic. It only confirms that an ICMP
    reply can be received from the peer address.
    """

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
    """
    Send an authenticated ACK for a fully decoded inbound message.

    ACK tells the peer it can stop retrying this message. The message ID is in
    both IP.id and the authenticated payload so spoofed or mismatched ACKs are
    rejected by the receiver.
    """

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
    """
    Ask the peer to retransmit specific missing chunks.

    One NACK packet is sent per missing chunk. The missing chunk number is
    stored in the authenticated control payload's `value` field.
    """

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
    """
    Send a complete message frame using an existing message ID.

    Packet order:
    1. START packet: seq=0, IP.id=message_id
    2. DATA packets: seq=chunk_number, IP.id=2 encrypted bytes
    3. END packet: seq=65534, IP.id=exact encrypted blob length

    The session key/IP/session ID are snapshotted before transmission so a user
    command such as @password or @changeip does not change parameters halfway
    through the packet stream.
    """

    # Snapshot shared session values under the lock, then release it before
    # sending packets. Holding the lock during network sends would block receive
    # processing and command handling.
    with session.lock:
        key = session.key
        peer_ip = session.peer_ip
        local_ip = session.local_ip
        session_id = session.session_id

    encrypted_blob = encrypt_message(key, message_id, text)
    chunks = split_into_chunks(encrypted_blob)

    # Store encrypted chunk values so a later NACK can retransmit exactly the
    # missing packet without rebuilding the whole message.
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

    # Small pacing delay reduces packet bursts and gives the peer/sniffer time
    # to process frames on lab networks.
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
    """
    Allocate a new message ID, transmit text, and wait for an ACK.

    If no ACK arrives before timeout, the full message is retransmitted. This
    handles lost START, DATA, END, or ACK packets at the cost of possible
    duplicates, which the receiver suppresses by message ID.
    """

    with session.lock:
        message_id = session.next_message_id

        # Message IDs live in 16-bit ICMP fields, so wrap after 65535.
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

        # Poll the ACK set. The sniff thread records ACKs asynchronously.
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
    """
    Manually retransmit a recent outbound message by ID.

    This backs the @resend command and is useful when a user wants to retry a
    message after a warning or suspected packet loss.
    """

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
    """
    Attempt to finish, decrypt, print, and ACK an inbound message.

    Returns True only when the message was fully decoded. It may return False
    because END has not arrived, chunks are missing, decryption failed, or the
    message buffer disappeared.
    """

    if message_id not in session.received_buffers:
        return False

    buffer = session.received_buffers[message_id]

    # total_chunks/total_bytes are learned from END. Before END, the receiver
    # cannot know whether all chunks have arrived.
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
        # Request only the missing chunks. When those retransmitted DATA packets
        # arrive, process_received_packet_locked calls this function again.
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

        # If the peer retransmits a message because our ACK was lost, do not
        # print the same chat text again. Still send ACK so the peer can stop.
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
    """
    Thread-safe wrapper for inbound packet processing.

    Scapy calls this function from the sniffer callback. The wrapper serializes
    packet handling with command-driven state changes such as @password and
    @changeip.
    """

    with session.lock:
        process_received_packet_locked(session, pkt)


def process_received_packet_locked(session: ChatSession, pkt) -> None:
    """
    Parse one inbound Scapy packet and update session state.

    This function expects session.lock to already be held. It filters unrelated
    packets first, then dispatches by reserved ICMP sequence number.
    """

    # Ignore non-IPv4/non-ICMP packets captured by the sniffer.
    if IP not in pkt or ICMP not in pkt:
        return

    ip = pkt[IP]
    icmp = pkt[ICMP]

    # Only accept packets from the configured peer to this local endpoint.
    if ip.src != session.peer_ip:
        return

    if ip.dst != session.local_ip:
        return

    if icmp.type != 8:
        return

    # ICMP identifier acts as a session ID so unrelated Echo traffic is ignored.
    if icmp.id != session.session_id:
        return

    seq = int(icmp.seq)
    ip_id = int(ip.id)

    if seq == ICMP_ACK_SEQ:
        # ACK packets must authenticate successfully and must name the same
        # message ID in both IP.id and the HMAC-protected payload.
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
        # NACK requests a single missing chunk. The sender retransmits only that
        # chunk if it is still available in sent_chunks.
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
        # START begins a new inbound message frame. If an older inbound message
        # is incomplete, it is discarded because this implementation tracks one
        # active receive stream at a time.
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
        # END provides the exact encrypted byte length. From this, the receiver
        # calculates expected chunk count and can detect missing chunks.
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
        # DATA packet: seq is the chunk number, IP.id is the 2-byte encrypted
        # chunk value. If END already arrived earlier, this packet might be a
        # retransmitted missing chunk, so attempt completion immediately.
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
    """
    Background packet sniffer.

    The sniffer receives ICMP packets and sends each packet to
    process_received_packet. stop_filter is checked when packets arrive, so
    shutdown becomes effective after the sniffer sees another packet.
    """

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
    """
    Change the peer IP and regenerate the cryptographic key.

    The key depends on the local/peer IP pair, so changing peer IP invalidates
    all in-flight messages and cached retransmission state.
    """

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

        # Re-derive key using the same password and new peer IP.
        session.key = derive_key(
            session.password,
            session.local_ip,
            session.peer_ip,
        )

        # Clear state tied to the previous peer/key. Old chunks and ACKs are no
        # longer valid after the peer identity changes.
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
    """
    Change shared password and regenerate the session key.

    Both peers must switch to the same password before encrypted traffic will
    decode successfully again.
    """

    new_password = getpass.getpass("Enter new shared password: ").strip()

    if not new_password:
        print("Password not changed.")
        return

    with session.lock:
        session.password = new_password

        # Re-derive key using the new password and the same IP pair.
        session.key = derive_key(
            session.password,
            session.local_ip,
            session.peer_ip,
        )

        # Clear state tied to the old key. Any buffered encrypted data was
        # created under the previous key and should not be decoded now.
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
    """Print interactive command help."""

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
    """Print a snapshot of current session state."""

    # Copy values while holding the lock, then print after releasing it so the
    # receiver thread is not blocked by terminal output.
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
    """
    Dispatch one user command from the chat prompt.

    Commands start with "@". Any non-command text is handled by main() as a chat
    message instead of being passed here.
    """

    if command == "@help":
        show_help()

    elif command == "@finish":
        # Main loop checks this flag and exits cleanly.
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
        # @changedstip is kept as a compatibility alias for older usage.
        change_destination_ip(session)

    elif command == "@password":
        change_password(session)

    elif command.startswith("@resend "):
        # Manual full-message retransmission for recent outbound messages.
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
    """
    Send an authenticated control packet in the ICMP Raw payload.

    Unlike data packets, ACK/NACK information is not hidden in IP.id. The IP.id
    still repeats message_id for fast filtering, but the trusted values are in
    the HMAC-protected payload.
    """

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
    """
    Retransmit one previously sent data chunk after receiving a NACK.

    The function looks up the original 16-bit chunk value and sends a single
    DATA packet with the same chunk number. It does not resend START or END.
    """

    # Snapshot chunk value and addressing while holding the lock. Actual packet
    # sending happens after the lock is released.
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
    """
    Program entry point and interactive chat loop.

    Startup sequence:
    1. Ask user for local IP, peer IP, password, and session ID.
    2. Derive the shared encryption/authentication key.
    3. Start the background ICMP receiver thread.
    4. Run an ICMP connectivity check.
    5. Enter the terminal chat loop.
    """

    print("=" * 70)
    print(" Network Steganography Messenger v2")
    print(" ICMP Echo / IPv4 Identification / ChaCha20-Poly1305 / ACK-NACK")
    print("=" * 70)

    try:
        # Both IP addresses are part of the key derivation salt, so validate
        # them before deriving the key or starting packet capture.
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
        # Session ID is carried in the ICMP identifier field. The peer must use
        # the same value so both sides ignore unrelated Echo traffic.
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

        # Daemon mode prevents a stuck sniffer from keeping Python alive after
        # the main thread exits.
        daemon=True,
    )
    thread.start()

    print("\nReceiver thread started.")
    check_connectivity(peer_ip, local_ip=local_ip)

    print("Type @help for commands.")
    print("Start chatting.\n")

    while True:
        # Check shutdown flag before blocking on user input.
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

            # Non-command input is treated as chat text and sent over the
            # steganographic ICMP protocol.
            send_stego_message(session, text)

        except KeyboardInterrupt:
            with session.lock:
                session.running = False
            break

        except Exception as exc:
            print(f"[ERROR] {exc}")

    print("\nClosing messenger.")

# Main ##############################################################################################

if __name__ == "__main__":
    main()

# End ###############################################################################################
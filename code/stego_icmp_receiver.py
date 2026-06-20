#####################################################################################################
#                             Network Steganography Messenger                                       #
#####################################################################################################
 
import time
import struct
import hashlib
from typing import Dict
from scapy.all import sniff, IP, ICMP
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"NS"
VERSION = 1
MSG_TYPE_CHAT = 1
ICMP_START_SEQ = 0
ICMP_END_SEQ = 65534

class MessageBuffer:
    def __init__(self, message_id: int):
        self.message_id = message_id
        self.chunks: Dict[int, int] = {}
        self.total_chunks = None
        self.created_at = time.time()

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

def decrypt_message(key: bytes, encrypted_blob: bytes) -> Dict:
    if len(encrypted_blob) < 12 + 16:
        raise ValueError("Encrypted blob too short")

    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]

    cipher = ChaCha20Poly1305(key)

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        b"network-stego-v2"
    )

    return parse_plaintext(plaintext)

def reassemble_chunks(chunks: Dict[int, int], total_chunks: int) -> bytes:
    result = bytearray()

    for chunk_number in range(1, total_chunks + 1):
        if chunk_number not in chunks:
            raise ValueError(f"Missing chunk {chunk_number}")

        result.extend(chunks[chunk_number].to_bytes(2, "big"))

    return bytes(result)

def main() -> None:
    print("=" * 60)
    print(" Network Steganography Messenger v2 - ICMP Receiver")
    print("=" * 60)

    local_ip = input("Enter local IP: ").strip()
    peer_ip = input("Enter expected peer IP: ").strip()
    password = input("Enter shared password: ").strip()
    session_id_input = input("Enter expected session ID: ").strip()

    expected_session_id = int(session_id_input)
    key = derive_key(password, local_ip, peer_ip)

    active_messages: Dict[int, MessageBuffer] = {}

    print("\nReceiver is listening...")
    print("Press CTRL+C to stop.\n")

    def process_packet(pkt) -> None:
        if IP not in pkt or ICMP not in pkt:
            return

        ip = pkt[IP]
        icmp = pkt[ICMP]

        if ip.src != peer_ip:
            return

        if icmp.type != 8:
            return

        if icmp.id != expected_session_id:
            return

        seq = icmp.seq
        ip_id = ip.id

        if seq == ICMP_START_SEQ:
            message_id = ip_id
            active_messages[message_id] = MessageBuffer(message_id)

            print(f"[RX] START received | message_id={message_id}")
            return

        if seq == ICMP_END_SEQ:
            total_chunks = ip_id

            if not active_messages:
                print("[RX] END received but no active message exists")
                return

            message_id = max(active_messages.keys())
            buffer = active_messages[message_id]
            buffer.total_chunks = total_chunks

            print(f"[RX] END received | total_chunks={total_chunks}")

            try:
                encrypted_blob = reassemble_chunks(
                    buffer.chunks,
                    buffer.total_chunks
                )

                decoded = decrypt_message(key, encrypted_blob)

                print("\n" + "-" * 50)
                print(f"peer: {decoded['text']}")
                print("-" * 50 + "\n")

                del active_messages[message_id]

            except Exception as exc:
                print(f"[RX] Decode failed: {exc}")

            return

        if seq > 0 and seq < ICMP_END_SEQ:
            if not active_messages:
                print("[RX] DATA received but no START exists")
                return

            message_id = max(active_messages.keys())
            buffer = active_messages[message_id]

            buffer.chunks[seq] = ip_id

            print(f"[RX] DATA chunk={seq:03d}, IPv4-ID=0x{ip_id:04X}")
            return

    try:
        sniff(
            filter="icmp",
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\nReceiver stopped.")

# Main ##############################################################################################

if __name__ == "__main__":
    main()

# End ###############################################################################################
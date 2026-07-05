from pwn import log, remote, process


def generate_space_packet(apid: int, packet_count: int, payload: bytes) -> bytes:
    # --- CCSDS 133.0-B-2 Space Packet Primary Header (6 bytes) ---
    version = 0            # Packet Version Number (3 bits) - always 0
    ptype = 1               # Packet Type (1 bit): 1 = Telecommand (uplink)
    sec_hdr_flag = 0        # Secondary Header Flag (1 bit): no secondary header
    apid &= 0x7FF           # Application Process ID (11 bits)

    seq_flags = 0b11        # Sequence Flags (2 bits): unsegmented user data
    seq_count = packet_count & 0x3FFF  # Packet Sequence Count (14 bits)

    data_length = len(payload) - 1     # Packet Data Length: (octets in data field) - 1

    word1 = (version << 13) | (ptype << 12) | (sec_hdr_flag << 11) | apid
    word2 = (seq_flags << 14) | seq_count
    word3 = data_length & 0xFFFF

    header = word1.to_bytes(2, 'big') + word2.to_bytes(2, 'big') + word3.to_bytes(2, 'big')
    packet = header + payload
    return packet


def generate_tc_frame(spacecraft_id: int, virtual_channel_id: int, tc_packet_count: int, payload: bytes) -> bytes:
    # --- CCSDS 232.0-B-4 TC Transfer Frame Primary Header (5 bytes) ---
    tfvn = 0                    # Transfer Frame Version Number (2 bits): 00 for TC
    bypass_flag = 0              # Bypass Flag (1 bit): 0 = sequence-controlled (Type-A)
    control_command_flag = 0     # Control Command Flag (1 bit): 0 = Type-D (data)
    reserved = 0                 # Reserved/spare (2 bits)

    spacecraft_id &= 0x3FF        # 10 bits
    virtual_channel_id &= 0x3F    # 6 bits

    header_len = 5
    frame_length = header_len + len(payload) - 1  # Frame Length field = total octets - 1

    octet1 = (tfvn << 6) | (bypass_flag << 5) | (control_command_flag << 4) | (reserved << 2) | ((spacecraft_id >> 8) & 0x3)
    octet2 = spacecraft_id & 0xFF
    octet3 = (virtual_channel_id << 2) | ((frame_length >> 8) & 0x3)
    octet4 = frame_length & 0xFF
    octet5 = tc_packet_count & 0xFF

    header = bytes([octet1, octet2, octet3, octet4, octet5])
    frame = header + payload
    return frame


def main():
    HOST = "154.57.164.61"
    PORT = 30127
    space_packet = generate_space_packet(apid=42, packet_count=0, payload=b"HEALTHCHECK")
    frame = generate_tc_frame(spacecraft_id=12, virtual_channel_id=3, tc_packet_count=0, payload=space_packet)

    payload = frame

    r = remote(HOST, PORT)
    r.send(payload)
    response = r.recvall(timeout=5)
    log.info(f'Server response: {response}')


if __name__ == "__main__":
    main()

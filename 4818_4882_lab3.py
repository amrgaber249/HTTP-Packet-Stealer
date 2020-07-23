import socket
import binascii

class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """
    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """
    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    ip_addr = [str(byte) for byte in raw_ip_addr]
    return ".".join(ip_addr)


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    tcp_header = {}
    tcp_header["Source Port"] = int(binascii.hexlify(ip_packet_payload[:2]),16)
    tcp_header["Destination Port"] = int(binascii.hexlify(ip_packet_payload[2:4]),16)
    tcp_header["Data Offset"] = int(chr(binascii.hexlify(ip_packet_payload[12:13])[0]),16)
    tcp_header["Payload"] = ip_packet_payload[tcp_header["Data Offset"]*4:]
    return TcpPacket(tcp_header["Source Port"], tcp_header["Destination Port"], tcp_header["Data Offset"], tcp_header["Payload"])


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    ip_header = {}
    ip_header['IHL'] = int(chr(binascii.hexlify(ip_packet[0:1])[1]),16)
    ip_header['Protocol'] = binascii.hexlify(ip_packet[9:10])
    ip_header['Source Address'] = parse_raw_ip_addr(ip_packet[12:16])
    ip_header['Destination Address'] = parse_raw_ip_addr(ip_packet[16:20])
    ip_header['Payload'] = ip_packet[ip_header['IHL']*4:]

    return IpPacket(ip_header['Protocol'], ip_header['IHL'], \
        ip_header['Source Address'], ip_header['Destination Address'], \
            ip_header['Payload'])

def hex_to_decimal(hex_bytes):
    return int(hex_bytes, 16)

def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)
    TCP = 0x0006
    stealer = socket.socket(socket.AF_INET,socket.SOCK_RAW,TCP)
    iface_name = "lo"
    stealer.setsockopt(socket.SOL_SOCKET,
                       socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))

    while True:
        # Receive packets and do processing here
        packet, addr = stealer.recvfrom(4096)
        ip_packet = parse_network_layer_packet(packet)
        tcp_packet = parse_application_layer_packet(ip_packet.payload)
        print(tcp_packet.payload)
    pass


if __name__ == "__main__":
    main()

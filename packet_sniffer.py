from scapy.all import sniff, IP, TCP, UDP

# Specify the log file where packet information will be saved
log_file = "packet_log.txt"


def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        payload = b''  # Initialize an empty bytes object for payload

        # Check for TCP packets
        if TCP in packet:
            tcp_layer = packet[TCP]
            payload = bytes(tcp_layer.payload)  # Get the TCP payload
            protocol = "TCP"

        # Check for UDP packets
        elif UDP in packet:
            udp_layer = packet[UDP]
            payload = bytes(udp_layer.payload)  # Get the UDP payload
            protocol = "UDP"

        # Log to file
        with open(log_file, "a") as log:
            log.write(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {payload}\n")

        # Print to console
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {payload}")


# Start sniffing with filtering for IP packets
print("Starting packet sniffer...")
sniff(prn=process_packet, filter="ip", store=0)

import dpkt
import struct
import socket
import datetime

def extract_arp_packet(buf):
    hardware_types = {
            "0001" : "Ethernet",
            "0006" : "IEEE 802 Networks",
            "0007" : "ARCNET",
            "000F" : "Frame Relay",
            "0010" : "Asynchronous Transfer Mode (ATM)",
            "0011" : "HDLC",
            "0012" : "Fibre Channel",
            "0013" : "Asynchronous Transfer Mode (ATM)",
            "0014" : "Serial Line",
    }

    operation_types = {
        "0001" : "Request",
        "0002" : "Response"
    }

    return {
            "hardware_type": hardware_types[buf[14:16].hex()],
            "protocol_type": "ipv4",
            "hardware_length": str(int(buf[18:19].hex())),
            "protocol_length": str(int(buf[19:20].hex())),
            "operation": operation_types[buf[20:22].hex()] + "({})".format(buf[20:22].hex()),
            "source_hardware_addr": hex_string_to_mac_address(buf[22:28].hex()),
            "source_protocol_addr": hex_string_to_ip(buf[28:32].hex()),
            "target_hardware_addr": hex_string_to_mac_address(buf[32:38].hex()),
            "target_protocol_addr": hex_string_to_ip(buf[38:42].hex())
    }

def print_arp_exchange(exchange):
    request = exchange["request"]
    response = exchange["response"]

    if request == None or response == None:
        print("Couldnt print ARP exchange because of missing info")

    print("                      +------------------------+------------------------+")
    print("                      |      ARP REQUEST       |      ARP RESPONSE      |")
    print("                      +------------------------+------------------------+")
    print("Hardware Type         |{:^24s}|{:^24s}|".format(request["hardware_type"], response["hardware_type"]))
    print("                      +------------------------+------------------------+")
    print("Protocol Type         |{:^24s}|{:^24s}|".format(request["protocol_type"], response["protocol_type"]))
    print("                      +------------------------+------------------------+")
    print("Hardware Length       |{:^24s}|{:^24s}|".format(request["hardware_length"], response["hardware_length"]))
    print("                      +------------------------+------------------------+")
    print("Protocol Length       |{:^24s}|{:^24s}|".format(request["protocol_length"], response["protocol_length"]))
    print("                      +------------------------+------------------------+")
    print("Operation             |{:^24s}|{:^24s}|".format(request["operation"], response["operation"]))
    print("                      +------------------------+------------------------+")
    print("Source Hardware Addr  |{:^24s}|{:^24s}|".format(request["source_hardware_addr"], response["source_hardware_addr"]))
    print("                      +------------------------+------------------------+")
    print("Target Hardware Addr  |{:^24s}|{:^24s}|".format(request["target_hardware_addr"], response["target_hardware_addr"]))
    print("                      +------------------------+------------------------+")
    print("Source Protocol Addr  |{:^24s}|{:^24s}|".format(request["source_protocol_addr"], response["source_protocol_addr"]))
    print("                      +------------------------+------------------------+")
    print("Target Protocol Addr  |{:^24s}|{:^24s}|".format(request["target_protocol_addr"], response["target_protocol_addr"]))
    print("                      +------------------------+------------------------+\n")

def hex_string_to_mac_address(hex_string):
    return "{}:{}:{}:{}:{}:{}".format(
        hex_string[0:2],
        hex_string[2:4],
        hex_string[4:6],
        hex_string[6:8],
        hex_string[8:10],
        hex_string[10:12],
    )

def hex_string_to_ip(hex_string):
    return "{}.{}.{}.{}".format(
        int(hex_string[0:2], 16),
        int(hex_string[2:4], 16),
        int(hex_string[4:6], 16),
        int(hex_string[6:8], 16)
    )

def main():
    file_name = str(input("Enter your pcap file name: "))

    f = None
    pcap = None
    
    try:
        f = open(file_name, "rb")
        pcap = dpkt.pcap.Reader(f)
    except FileNotFoundError:
        print("File not found")
        return
    except ValueError:
        print("The file must be a .pcap file")
        return
    
    exchanges = []
    
    for ts, buf in pcap:
        # check if its arp
        if buf[12:14].hex() != "0806":
            continue
        
        # check if the arp packet is a broadcast
        if buf[0:6].hex() == "ffffffffffff":
            continue

        arp_packet = extract_arp_packet(buf)

        # arp request
        if buf[20:22].hex() == "0001":
            exchanges.append({
                "request": arp_packet,
                "response": None
            })
        # arp response
        elif buf[20:22].hex() == "0002":
            for exchange in exchanges:
                arp_request = exchange["request"]
                if (arp_request["target_protocol_addr"] == arp_packet["source_protocol_addr"] and
                arp_request["source_protocol_addr"] == arp_packet["target_protocol_addr"]):
                    exchange["response"] = arp_packet
                    break
        
    # print exchange info
    for exchange in exchanges:
        print_arp_exchange(exchange)

if __name__ == "__main__":
    main()
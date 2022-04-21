import dpkt
import struct
import socket
import datetime

def extract_arp_packet(buf):
    hardware_types = {
            "0001" : "ethernet",
            "0006" : "IEEE 802 Networks",
            "0007" : "ARCNET",
            "000F" : "Frame Relay",
            "0010" : "Asynchronous Transfer Mode (ATM)",
            "0011" : "HDLC",
            "0012" : "Fibre Channel",
            "0013" : "Asynchronous Transfer Mode (ATM)",
            "0014" : "Serial Line",
    }

    return {
            "hardware_type": hardware_types[buf[14:16].hex()],
            "protocol_type": buf[16:18].hex(),
            "hardware_length": buf[18:19].hex(),
            "protocol_length": buf[19:20].hex(),
            "operation": buf[20:22].hex(),
            "source_hardware_addr": buf[22:28].hex(),
            "source_protocol_addr": buf[28:32].hex(),
            "target_hardware_addr": buf[32:38].hex(),# (UNKNOWN)
            "target_protocol_addr": buf[38:42].hex()
    }

def print_arp_exchange(exchange):
    print(exchange)
    request = exchange["request"]
    reply = exchange["reply"]

    print("                      +------------------------+------------------------+")
    print("                      |      ARP REQUEST       |       ARP REPLY        |")
    print("                      +------------------------+------------------------+")
    print("Hardware Type         |{:^24s}|{:^24s}|".format(request["hardware_type"], reply["hardware_type"]))
    print("                      +------------------------+------------------------+")
    print("Protocol Type         |{:^24s}|{:^24s}|".format(request["protocol_type"], reply["protocol_type"]))
    print("                      +------------------------+------------------------+")
    print("Hardware Length       |{:^24s}|{:^24s}|".format(request["hardware_length"], reply["hardware_length"]))
    print("                      +------------------------+------------------------+")
    print("Protocol Length       |{:^24s}|{:^24s}|".format(request["protocol_length"], reply["protocol_length"]))
    print("                      +------------------------+------------------------+")
    print("Operation             |{:^24s}|{:^24s}|".format(request["operation"], reply["operation"]))
    print("                      +------------------------+------------------------+")
    print("Source Hardware Addr  |{:^24s}|{:^24s}|".format(request["source_hardware_addr"], reply["source_hardware_addr"]))
    print("                      +------------------------+------------------------+")
    print("Source Protocol Addr  |{:^24s}|{:^24s}|".format(request["source_protocol_addr"], reply["source_protocol_addr"]))
    print("                      +------------------------+------------------------+")
    print("Target Hardware Addr  |{:^24s}|{:^24s}|".format(request["target_hardware_addr"], reply["target_hardware_addr"]))
    print("                      +------------------------+------------------------+")
    print("Target Protocol Addr  |{:^24s}|{:^24s}|".format(request["target_protocol_addr"], reply["target_protocol_addr"]))
    print("                      +------------------------+------------------------+")

def main():
    # file_name = str(input("Enter your pcap file name: "))

    file_name = "arp.pcap"

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
                "reply": None
            })
        # arp reply
        elif buf[20:22].hex() == "0002":
            print(arp_packet)
            for exchange in exchanges:
                arp_request = exchange["request"]
                if (arp_request["target_protocol_addr"] == arp_packet["source_hardware_addr"] and
                arp_request["source_protocol_addr"] == arp_packet["target_protocol_addr"]):
                    exchange["reply"] = arp_packet
        
    # print exchange info
    # for exchange in exchanges:
        # print_arp_exchange(exchange)

if __name__ == "__main__":
    main()
import dpkt
import socket
import datetime

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
    
    for ts, buf in pcap:
        x += 1
        eth = dpkt.ethernet.Ethernet(buf)

        if eth.type != dpkt.ethernet.ETH_TYPE_ARP:
            continue

        arp = eth.data
        print(arp)

if __name__ == "__main__":
    main()
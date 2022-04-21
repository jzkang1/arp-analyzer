How to run program:
Open terminal in this directory
Run command "py analysis_pcap_arp"
Enter pcap file name as input

Program logic:
First I made a list to store each ARP exchange.
I looped through each packet captured in the pcap file and parsed the bytes in the headers to check if it was an ARP packet.
After that, I parsed all of the packet's bytes to gather header information such as source ip address, destination ip address, etc.
After that, we checked the "operation" header in the packet to see if it was an ARP request or an ARP response.
If it was an request then we'll make a new "exchange" object and append it to the exchanges list.
If it was an response then we'll loop through the exchanges list and try to match it with the corresponding request.
After parsing the pcap file, I printed the details of each ARP exchange in a table format.
## After owning any network this can be used to spy on it

<h3>This script it only for educational purposes<h3>
<ul>
<li>def in_sudo_mode - Function to check if the script is being runwith sudo priviledges. If not it will stop</li>
<li>def clients - This function returns a list with only the clients. the gateway is removed from the list.</li>
<li>arp_res -> The response from the ARP scan</li>
<li>gateway_res -> The response from the gateway_info function</li>
<ol>def allow_ip_forwarding - Running this function allows ip forwarding. The packets will flow through your machine, and you'll be able to capture them Otherwise user will lose connection</li>
<li>def arp_spoofer - This function needs to be ran twice to update the ARP tables. One time with the gateway IP and MAC, and one time with the target's IP and MAC.</li>
<li>def packet_sniffer - This function will be a packet sniffer to capture all the packets sent to the computer whilst the computer is the MITM</li>
<li>def process_sniffed_pkt - A callback function that works with the packet sniffer. It reads and stores the packets in pcap file</li>
<li>ARP is a layer 3 protocol. So we use scapy.send(). We choose it to be verbose so we don't see the output.</li>
<li>Tested time.sleep() with different values. 3s seems adequate.</li>
<li>The process_sniffed_pkt is a callback function that will run on each packet.</li>
</ul>
<h4>To run this script: sudo python3 mitm.py -ip_range (ex. 192.168.1.0/24)</h4>

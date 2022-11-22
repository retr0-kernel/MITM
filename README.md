## After owning any network you can use this to spy on it
(Still building)

<ul>ARP is a layer 3 protocol. So we use scapy.send(). We choose it to be verbose so we don't see the output.</ul>
<ul>Tested time.sleep() with different values. 3s seems adequate.</ul>
<ul>The process_sniffed_pkt is a callback function that will run on each packet.</ul>

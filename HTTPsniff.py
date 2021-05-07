from scapy.all import *
from scapy.layers.http import HTTPRequest #j'import la librairy HTTPRequest 
import argparse 


#je vais crée un fonction qui va s'occuper du sniffing HTTP


def sniff_packet(iface=None):

	if iface: 
		sniff(filter="port 80", prn=HTTP_info, iface=iface, store=False ) #filter permet de filtrer ce que nous allons sniffer, ici le port 80 http, prn est la fuctnion qui sera executé a chaque fois qu'un packet serais sniffer, iface coreespond a l'interface utiliser, Store peremt de savoir si l'on garde ou pas les paquet sniffer 
	else :
		sniff(filter="port 80", prn=HTTP_info, store=False)


def HTTP_info(packet):

	


	if packet.haslayer(HTTPRequest): #si le paquet est un paquet HTTP
		url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode() #on recupere l'url de la requette HTTP
		ip = packet[IP].src

		method = packet[HTTPRequest].Method.decode()
		print("[{}]-{}-[methode]{}".format(ip,url,method))

		fichier = open("http.txt","a")
		fichier.write(url+","+method+"\n")
		fichier.close()

		
		if packet.haslayer(Raw) and method == "POST":
			print("Information importante {}".format(packet[Raw].load))
			
			

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--iface", help="interface réseau a utiliser, par default celle de scapy sera utilisé")

args=parser.parse_args()
iface=args.iface
sniff_packet(iface)










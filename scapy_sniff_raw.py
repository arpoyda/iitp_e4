import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon = 'wlan0mon'    ### Just monitor VAP interface (mon0)
#mac2search = "46:6f:4b:75:6d:61"   ### BSSID of ap to search or client MAC
mac2search = "18:56:80:e6:27:89"

def insert_ap(pkt):
	pkt.show()
	try:
		mac = pkt[Dot11].addr2
		dest = pkt[Dot11].addr3
		#print(pkt.load)
		if mac.upper() == mac2search.upper() and dest == "00:00:00:00:00:00":
			#pkt.show()
			#ls(pkt)
			print(pkt.subtype, pkt.type)
			print(pkt.addr3)
			pass
	except AttributeError:
		#print("Incorrect format")
		pass

sniff(iface=intfmon, prn=insert_ap, store=False,)
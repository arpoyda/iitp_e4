import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

intfmon = 'wlp2s0mon'    ### Just monitor VAP interface (mon0)
mac2search = "18:56:80:e6:27:89"   ### BSSID of ap to search or client MAC

def insert_ap(pkt):
	print(pkt[Dot11].addr2)
	if pkt.haslayer(Dot11):
		print(1)
		mac = pkt[Dot11].addr2
		if mac.upper() == mac2search.upper():
			essid = pkt[Dot11].info
			powervalues=[0,0,0]
			# power = (256 - ord(pkt.notdecoded[-4:-3]))  # Some radiotap headers
			power = (256 - ord(pkt.notdecoded[-2:-1]))  # other radiotap headers like Atheros
			if power > 0 <= 99:
				power = 100 - power
			elif power == 256:
				return  ## corrupt value

			print("ESSID: %s BSSID: %s PWR: %s" %(essid,mac,power))

sniff(iface=intfmon, prn=insert_ap, store=False,)
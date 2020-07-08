from scapy.all import *

for _ in range(1):
	packet = Dot11(
	    addr1="00:a0:57:98:76:54",
	    addr2="00:a0:57:12:34:56",
	    addr3="00:a0:57:98:76:54") / Dot11AssoReq(
	        cap=0x1100, listen_interval=0x00a) / Dot11Elt(
	            ID=0, info="MY_BSSIDsHI!")
	packet /= Dot11EltRates()

	sendp(packet, iface="wlp2s0")
packet.show()


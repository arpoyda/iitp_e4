import sys
from scapy.all import *

def get_packet():
	packet = Dot11(
	    	 	addr1="00:00:" + get_if_hwaddr("wlan0")[:-6],
	    	 	addr2=get_if_hwaddr("wlan0")[12:] + ":57:12:34:56",
	    	 	addr3="00:00:00:00:00:00"
	    	 ) / Dot11AssoReq(
	        		cap=0x1100, listen_interval=0x00a
	        	) / Dot11Elt(
	            	ID=0, info="MY_BSSID!"
	            )
	packet /= Dot11EltRates()
	return packet

def get_frame():
	dot11=Dot11(type=2, subtype=8, addr1='11:11:11:11:11:11', addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
	frame = RadioTap()/dot11/Dot11QoS()/"abcd"
	return frame

def main():
	if sys.argv[2] == "packet":
		packet = get_packet()
	elif sys.argv[2] == "frame":
		packet = get_frame()
	else:
		sys.exit("arg2 can be only: [\"packet\", \"frame\"]")

	packet.show()
	try:
		for _ in range(int(sys.argv[1])):
			sendp(packet, iface="wlan0")
	except ValueError:
		sys.exit("arg1 can be only: <int>")
	

if __name__ == '__main__':
	main()
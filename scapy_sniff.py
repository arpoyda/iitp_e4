from scapy.all import *

ap_list = []
def ssid(pkt):
    print(pkt.show())
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2)
                print("AP: %s SSID: %s" % (pkt.addr2, pkt.info))

sniff(iface='en0', prn=ssid)
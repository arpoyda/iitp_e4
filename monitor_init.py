#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import os, time, socket, fcntl, struct
from subprocess import call
from platform import system
from scapy.all import *


def OScheck():
    osversion = system()
    print("Operating System: %s" %osversion)
    if osversion != 'Linux':
        print("This script only works on Linux OS! Exitting!")
        exit(1)

def InitMon(params=('', '1')):
	if not os.path.isdir("/sys/class/net/" + params[0]+"mon") or (params[0] != "-a"):
		if not os.path.isdir("/sys/class/net/" + params[0]) and (params[0] != "-a"):
			print("WiFi interface %s does not exist! Cannot continue!" %(params[0]))
			exit(1)
		else:
			try:
				#os.system("sudo airmon-ng check kill")
				if params[0] == "-a":
					os.system("sudo airmon-ng start %s" % max(get_if_list()))
					time.sleep(5)
					os.system("sudo iwconfig %s channel %s" % (max(get_if_list()), int(params[1])))
					print("Monitor %s created" % (max(get_if_list())))
				else:
					os.system("sudo airmon-ng start %s" % params[0])
					time.sleep(0.5)
					os.system("sudo iwconfig %s channel %s" % (params[0]+"mon", int(params[1])))
					time.sleep(0.1)
					print("Monitor %s created" % (params[0]+"mon"))
			except OSError as e:
				print("Could not create monitor")
				os.kill(os.getpid(),SIGINT)
				sys.exit(1)
	else:
		print("Monitor %s exists! Nothing to do, just continuing..." %(intfmon))

def GetMAC(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    macaddr = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return macaddr


if __name__ == "__main__":
	# Check if OS is linux:
	OScheck()

	# Check for root privileges
	if os.geteuid() != 0:
		exit("You need to be root to run this script!")
	else:
		print("You are running this script as root!")

	# Check if monitor device exists
	InitMon(('-a', '2'))

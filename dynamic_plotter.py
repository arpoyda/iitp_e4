import matplotlib.pyplot as plt
import matplotlib.animation as animation
import datetime as dt
import sys
from threading import Thread
from scapy.all import *

from monitor_init import OScheck, InitMon


class Data:
    def __init__(self):
        self.time = []
        self.sig = []


 
class Plotter: 
    def __init__(self, data):
        plt.style.use('dark_background')
        self.data = data
        self.fig = plt.figure()
        self.ax1 = self.fig.add_subplot(1, 1, 1)

    def animate(self, i):    
        self.ax1.clear()
        self.ax1.plot(self.data.time[-30:], self.data.sig[-30:])
        #self.ax1.plot(self.data.time, self.data.sig)

        plt.xticks(rotation=45, ha='right')
        plt.subplots_adjust(bottom=0.30)
        plt.ylabel('Signal, dBm')
        plt.title('Signal over Time')

    def run(self):
        self.ani = animation.FuncAnimation(self.fig, self.animate, interval=500)
        plt.show()



class Signal:
    def __init__(self, data, intfmon='wlan0', m2s="18:56:80:e6:27:89", d2s="00:00:00:00:00:00"):
        self.mac2search = m2s
        self.intfmon = intfmon
        self.data = data
        self.dest2search = d2s  

    def packet_handler(self, pkt):
        try:
            mac = pkt[Dot11].addr2
            dest = pkt[Dot11].addr3
            #print(mac + ' -> ' dest)
            if mac.upper() == self.mac2search.upper() and dest == self.dest2search:
                #print(pkt.dBm_AntSignal)
                self.data.time.append(dt.datetime.now().strftime('%H:%M:%S.%f'))
                self.data.sig.append(int(pkt.dBm_AntSignal))
        except (AttributeError, NameError, IndexError):
            pass

    def run(self):
        sniff(iface=self.intfmon, prn=self.packet_handler, store=False,)


def wonna_quit(iface):
    while True:
        if input("exit?: ") in "exit_ok_yes_y_1":
            os.system("sudo airmon-ng stop %s" % iface+"mon")
            sys.exit()

def main():
    OScheck()
    InitMon((sys.argv[1], sys.argv[2]))
    time.sleep(5)


    data = Data()

    plott = Plotter(data)
    sign = Signal(data, intfmon=sys.argv[1]+"mon", m2s=sys.argv[3], d2s=sys.argv[4])

    t1 = Thread(target=sign.run, daemon=True)
    t2 = Thread(target=plott.run, daemon=True)
    t_c = Thread(target=wonna_quit, args=(sys.argv[1],))

    t_c.start()
    t1.start()
    t2.start()
    
    t_c.join()


if __name__ == "__main__":
    main()

# lfilter=lambda p: p[Dot11].addr2 == self.mac2search.upper() and p[Dot11].addr3 == "00:00:00:00:00:00"

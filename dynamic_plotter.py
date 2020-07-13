import matplotlib.pyplot as plt
import matplotlib.animation as animation
import datetime as dt
import sys
from threading import Thread
from scapy.all import *

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
        #self.ax1.plot(self.data.time[-30:], self.data.sig[-30:])
        self.ax1.plot(self.data.time, self.data.sig)

        plt.xticks(rotation=45, ha='right')
        plt.subplots_adjust(bottom=0.30)
        plt.ylabel('Signal, dBm')
        plt.title('Signal over Time')

    def run(self):
        self.ani = animation.FuncAnimation(self.fig, self.animate, interval=100)
        plt.show()



class Signal:
    def __init__(self, data, m2s, intfmon='wlan0'):
        self.mac2search = m2s
        self.intfmon = intfmon
        self.data = data

    def packet_handler(self, pkt):
        try:
            mac = pkt[Dot11].addr2
            dest = pkt[Dot11].addr3
            print(pkt.dBm_AntSignal)
            if mac.upper() == self.mac2search.upper() and dest == "00:00:00:00:00:00":
                print(pkt.dBm_AntSignal)
                self.data.time.append(dt.datetime.now().strftime('%H:%M:%S.%f'))
                self.data.sig.append(int(pkt.dBm_AntSignal))
        except (AttributeError, NameError):
            pass

    def run(self):
        sniff(iface=self.intfmon, prn=self.packet_handler, store=False,)



def main():

    data = Data()

    plott = Plotter(data)
    sign = Signal(data, sys.argv[1], sys.argv[2])

    t1 = Thread(target=sign.run)
    t2 = Thread(target=plott.run)

    t1.start()
    t2.start()

    t1.join()
    t2.join()


if __name__ == "__main__":
    main()

# lfilter=lambda p: p[Dot11].addr2 == self.mac2search.upper() and p[Dot11].addr3 == "00:00:00:00:00:00"

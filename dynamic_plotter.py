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

class Controller:
    def __init__(self):
        self.m2s = ""
        self.d2s = ""
        self.time_delta = 0.5
        self.iface = ""
        self.channel = ""
        self.plot = True


 
class Plotter: 
    def __init__(self, data, controller=None):
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
    def __init__(self, data, ctrl):
        self.ctrl = ctrl
        self.data = data
        self.prev_time = 0 
        open("sig_log.txt", "w").close()

    def packet_handler(self, pkt):
        try:
            mac = pkt[Dot11].addr2
            dest = pkt[Dot11].addr3
            delta = time.time() - self.prev_time
            if (mac.upper() == self.mac2search.upper())          and\
               (dest == self.ctrl.d2s or self.ctrl.d2s == "any") and\
               (delta > self.ctrl.time_delta):
                with open("sig_log.txt", "a") as f:
                    f.write("%s -> %s: %s: %s\n" % (mac, dest, int(pkt.dBm_AntSignal), delta))
                self.prev_time = time.time()    
                self.data.time.append(delta)
                self.data.sig.append(int(pkt.dBm_AntSignal))
        except (AttributeError, NameError, IndexError):
            pass

    def run(self):
        sniff(iface=self.intfmon, prn=self.packet_handler, store=False,)


def wonna_quit(iface):

    while True:
        command = input("exit?: ").split()
        if command[0] in "exit_ok_yes_y_1":
            if iface == "-a":
                os.system("sudo airmon-ng stop %s" % max(get_if_list()))
            else:    
                os.system("sudo airmon-ng stop %s" % iface+"mon")
            sys.exit()
        elif command[0] == "clear":
            open("sig_log.txt", "w").close()


def control(ctrl):
    pn = ""
    difs = ""
    send_to_sniff = ""
    strength = "None"
    while True:
        command = input("Enter cmd: ")
        if command in ("exit", "quit", "exit()", "quit()")
            if iface == "-a":
                    os.system("sudo airmon-ng stop %s" % max(get_if_list()))
                else:    
                    os.system("sudo airmon-ng stop %s" % iface+"mon")
                sys.exit()
        elif command == "clear":
            open("sig_log.txt", "w").close()
        elif command[0] == "save":
            with open(str(pathlib.Path(__file__).parent.absolute()) + "/experiments/" + command[1], "w") as exp:
                with open("sig_log.txt", "r") as log:
                    results = log.read()
                    _pn = input("pn: ")
                    _difs = input("difs: ")
                    _send_to_sniff = input("_send_to_sniff: ")
                    if _pn != "":
                        pn = _pn
                    if _difs != "":
                        difs = _difs
                    if _pn != "":
                        send_to_sniff = _send_to_sniff
                    fout = strength + "\n" + "pn: " + pn + '\n' + "difs: " + difs + "\n" + "send_to_sniff: " + send_to_sniff + '\n' + results
                    exp.write(fout) 
        elif command[0] == "stop":
            ctrl.plot = False
        elif command[0] == "start":
            ctrl.plot = True
        elif command[0] == "delta"
            ctrl.time_delta = float(command[1])
        elif command[0] == "strength"
            ctrl.strength = int(command[1])


def fill_ctrl(ctrl, arr):
    ctrl.iface = arr[1]
    ctrl.channel = arr[2]
    ctrl.m2s = arr[3]
    ctrl.d2s = arr[4]
    ctrl.time_delta = 0.49


def main():
    OScheck()
    InitMon((sys.argv[1], sys.argv[2]))
    time.sleep(5)

    data = Data()
    ctrl = Controller()
    fill_ctrl(ctrl, sys.argv)

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

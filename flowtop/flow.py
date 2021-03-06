import curses
import logging
import socket
import struct
import threading
import time

from scapy import all as scapy

from flowtop.window import WindowManager

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

RENDER_INTERVAL = 1


class Option:
    def __init__(self, text):
        self.__text = text

    def __len__(self):
        return len(self.text)

    @property
    def text(self):
        return self.__text

    @text.setter
    def text(self, value):
        self.__text = value


class ToggableOption(Option):
    def __init__(self, text1, text2):
        super(ToggableOption, self).__init__(text1)
        self.__text1 = text1
        self.__text2 = text2
        self.__flag = True

    @property
    def text(self):
        return self.__text1 if self.__flag else self.__text2

    @text.setter
    def text(self, value):
        return

    def toggle(self):
        self.__flag = not self.__flag


class Action:
    def __init__(self, callback, *args, **kwargs):
        self.__callback = callback
        self.__args = args
        self.__kwargs = kwargs

    def __call__(self):
        self.__callback(*self.__args, **self.__kwargs)


class FlowTop:
    def __init__(self, interface):
        self.__running = True
        self.__wm = WindowManager()
        self.__ft = FlowTracker(interface)
        self.__render_expired = False

        self.__options = [
            Option(''),
            ToggableOption('Sort by Packets', 'Sort by Bytes'),
            ToggableOption('Show Expired', 'Hide Expired'),
            Option(''),
            Option('Reset'),
            Option(''),
            Option(''),
            Option(''),
            Option(''),
            Option('Exit'),
            Option(''),
            Option('')
        ]

        self.__actions = {
            curses.KEY_UP: [Action(self.__wm.change_selection, True)],
            curses.KEY_DOWN: [Action(self.__wm.change_selection, False)],
            curses.KEY_F2: [Action(self.__wm.toggle_sort), Action(self.__options[1].toggle)],
            curses.KEY_F3: [Action(self.__toggle_render_expired), Action(self.__options[2].toggle)],
            curses.KEY_F5: [Action(self.__ft.clear)],
            curses.KEY_F10: [Action(self.shutdown)],
            curses.KEY_RESIZE: [Action(self.__wm.resize)]
        }

        self.__wm.set_options(self.__options)

    def __toggle_render_expired(self):
        self.__render_expired = not self.__render_expired

    def run(self):
        last_render_ts = time.time()
        force_render = True  # force rendering for the first tick to draw interface
        self.__ft.start()

        while self.__running:
            key = self.__wm.get_pressed_key()
            if key in self.__actions:
                for action in self.__actions[key]:
                    action()

                force_render = True  # force rendering after action

            self.__ft.expire_flows()

            if force_render or (time.time() - last_render_ts) > RENDER_INTERVAL:
                self.render()
                last_render_ts = time.time()
                force_render = False

            time.sleep(0.1)

    def render(self):
        self.__wm.set_flows(
            self.__ft.flows if self.__render_expired else self.__ft.active_flows
        )
        self.__wm.set_global_stats(*self.__ft.stats)
        self.__wm.update()

    def shutdown(self):
        self.__running = False


class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, ip_proto):
        self.__src_ip = src_ip
        self.__dst_ip = dst_ip
        self.__l3_src = Flow.__resolve_ip_address(src_ip)
        self.__l3_dst = Flow.__resolve_ip_address(dst_ip)
        self.__src_port = src_port
        self.__dst_port = dst_port
        self.__ip_proto = ip_proto
        self.__first_packet_ts = None
        self.__last_activity = time.time()
        self.__packets_n = 0
        self.__bytes_n = 0
        self.__expired = False

    @staticmethod
    def __resolve_ip_address(ip_address):
        try:
            result, _, _ = socket.gethostbyaddr(ip_address)
        except socket.herror:
            result = None
        return result

    @property
    def src_ip(self):
        return self.__src_ip

    @property
    def dst_ip(self):
        return self.__dst_ip

    @property
    def l3_src(self):
        return self.__l3_src or self.__src_ip

    @property
    def l3_dst(self):
        return self.__l3_dst or self.__dst_ip

    @property
    def src_port(self):
        return self.__src_port

    @property
    def dst_port(self):
        return self.__dst_port

    @property
    def ip_proto(self):
        return self.__ip_proto

    @property
    def packets_n(self):
        return self.__packets_n

    @property
    def bytes_n(self):
        return self.__bytes_n

    @property
    def last_activity(self):
        return self.__last_activity

    @property
    def expired(self):
        return self.__expired

    def account_packet(self, packet: scapy.Packet):
        if self.__first_packet_ts is None:
            self.__first_packet_ts = packet.time
        self.__last_activity = time.time()
        self.__packets_n += 1
        self.__bytes_n += len(packet)

    def expire(self):
        self.__expired = True

    def __str__(self):
        return '{} <-> {} {} <-> {}: {}/{}'.format(self.__src_ip, self.__dst_ip, self.__src_port,
                                                   self.__dst_port, self.__packets_n, self.__bytes_n)


class FlowTracker:
    FLOW_TIMEOUT = 30
    NO_EXPIRATION = 0

    def __init__(self, interface):
        self.__interface = interface
        self.__flow_table = None
        self.__start_ts = None
        self.clear()
        self.__receiving_thread = None

    def __del__(self):
        if self.__receiving_thread is not None:
            self.__receiving_thread.join()

    @property
    def flows(self):
        return self.__flow_table

    @property
    def flows_n(self):
        return len(list(self.__flow_table))

    @property
    def active_flows(self):
        return {hashsum: flow for hashsum, flow in self.__flow_table.items() if not flow.expired}

    @property
    def avg_flows_per_s(self):
        try:
            return self.flows_n / self.timeframe
        except ZeroDivisionError:
            return 0

    @property
    def packets_n(self):
        return sum([flow.packets_n for flow in self.__flow_table.values()])

    @property
    def avg_packets_per_s(self):
        try:
            return self.packets_n / self.timeframe
        except ZeroDivisionError:
            return 0

    @property
    def bytes_n(self):
        return sum([flow.bytes_n for flow in self.__flow_table.values()])

    @property
    def avg_bytes_per_s(self):
        try:
            return self.bytes_n / self.timeframe
        except ZeroDivisionError:
            return 0

    @property
    def stats(self):
        return self.packets_n, self.avg_packets_per_s, self.bytes_n, self.avg_bytes_per_s, self.flows_n, self.avg_flows_per_s

    @property
    def timeframe(self):
        return int(time.time()) - int(self.__start_ts)

    @staticmethod
    def ip2int(ip):
        packed_ip = socket.inet_aton(ip)
        return struct.unpack("!L", packed_ip)[0]

    @staticmethod
    def calc_five_tuple_hash(five_tuple):
        return (FlowTracker.ip2int(five_tuple[0]) * 59) ^ (FlowTracker.ip2int(five_tuple[1]) * 59) ^ (five_tuple[2] * 13) ^ (five_tuple[3] * 13) ^ five_tuple[4]

    def clear(self):
        self.__flow_table = {}
        self.__start_ts = time.time()

    def account_packet(self, packet):
        if packet.haslayer(scapy.IP):
            l3 = scapy.IP
        else:
            return

        if packet.haslayer(scapy.TCP):
            l4 = scapy.TCP
        elif packet.haslayer(scapy.UDP):
            l4 = scapy.UDP
        else:
            return

        five_tuple = (packet[l3].src, packet[l3].dst, packet[l4].sport,
                      packet[l4].dport, packet[l3].proto)

        hashsum = FlowTracker.calc_five_tuple_hash(five_tuple)

        if hashsum in self.__flow_table:
            flow = self.__flow_table[hashsum]
        else:
            flow = Flow(*five_tuple)
            self.__flow_table[hashsum] = flow

        flow.account_packet(packet)

    def expire_flows(self):
        if FlowTracker.FLOW_TIMEOUT == FlowTracker.NO_EXPIRATION:
            return

        for key, flow in self.__flow_table.items():
            if (int(time.time()) - int(flow.last_activity)) > FlowTracker.FLOW_TIMEOUT:
                flow.expire()

    def capture(self):
        scapy.sniff(iface=self.__interface, filter='tcp or udp or sctp', store=1, prn=self.account_packet)

    def start(self):
        self.__receiving_thread = threading.Thread(target=self.capture)
        self.__receiving_thread.setDaemon(True)
        self.__receiving_thread.start()

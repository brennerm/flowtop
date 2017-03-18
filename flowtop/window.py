import curses

from flowtop.constants import *


class WindowManager:
    def __init__(self):
        self.__main_win = curses.initscr()
        curses.start_color()
        if curses.can_change_color():
            curses.init_color(0, 0, 0, 0)
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        curses.mousemask(1)
        self.__main_win.nodelay(1)
        self.__main_win.keypad(1)
        self.__main_win.refresh()

        curses.init_pair(WHITE_ON_BLUE, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(BLUE_ON_BLACK, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(RED_ON_BLACK, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(GREEN_ON_BLACK, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(YELLOW_ON_BLACK, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(CYAN_ON_BLACK, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(MAGENTA_ON_BLACK, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(WHITE_ON_CYAN, curses.COLOR_WHITE, curses.COLOR_CYAN)
        curses.init_pair(MAGENTA_ON_CYAN, curses.COLOR_MAGENTA, curses.COLOR_CYAN)

        self.__flow_table_window = FlowTableWindow(0, 0, 0, 0)
        self.__global_stat_window = GlobalStatWindow(0, 0, 0, 0)
        self.__option_pane = OptionPane(0, 0, 0, 0)

        self.__windows = [self.__flow_table_window, self.__global_stat_window, self.__option_pane]

        self.resize()

    def __del__(self):
        self.__deinitialize_curses()

    def __deinitialize_curses(self):
        curses.nocbreak()
        self.__main_win.keypad(0)
        curses.echo()
        curses.endwin()

    def resize(self):
        max_height, max_width = self.__main_win.getmaxyx()

        self.__flow_table_window.resize(max_height - 3, max_width, 0, 0)
        self.__global_stat_window.resize(1, max_width, max_height - 2, 0)
        self.__option_pane.resize(1, max_width, max_height - 1, 0)

    def get_pressed_key(self):
        return self.__main_win.getch()

    def set_flows(self, flows):
        self.__flow_table_window.set_flows(flows)

    def set_options(self, options):
        self.__option_pane.set_options(options)

    def set_global_stats(self, *args, **kwargs):
        self.__global_stat_window.set_stats(*args, **kwargs)

    def toggle_sort(self):
        self.__flow_table_window.toggle_sort()

    def update(self):
        for window in self.__windows:
            window.update()

        curses.doupdate()


class Window:
    def __init__(self, height, width, pos_y, pos_x):
        self._curses_window = curses.newwin(height, width, pos_y, pos_x)

    @staticmethod
    def _shorten_string(string, width):
        return (string[:width - 4] + '...') if len(string) > width else string

    def resize(self, height, width, y, x):
        self._curses_window.resize(height, width)
        self._curses_window.mvwin(y, x)

    def update(self):
        self._curses_window.clear()
        self._update()
        self._curses_window.noutrefresh()

    def _update(self):
        raise NotImplementedError


class FlowTableWindow(Window):
    def __init__(self, height, width, pos_y, pos_x):
        super(FlowTableWindow, self).__init__(height, width, pos_y, pos_x)
        self.__flows = []
        self.__sort_by_packets = True

    def set_flows(self, flows):
        self.__flows = flows

    def toggle_sort(self):
        self.__sort_by_packets = not self.__sort_by_packets

    def _update(self):
        headers = ['Ingress IP', 'Egress IP', 'Ingress Port', 'Egress Port', 'L4 Protocol', '#Packets', '#Bytes']

        col_width = int((self._curses_window.getmaxyx()[1] - max([len(header) for header in headers])) / len(headers)) + 1

        row_format = ("{:>" + str(col_width) + "}") * (len(headers))

        self._curses_window.addstr(0, 0, row_format.format(*headers), curses.A_BOLD)

        if self.__sort_by_packets:
            self.__flows.sort(key=lambda x: x.bytes_n, reverse=True)
        else:
            self.__flows.sort(key=lambda x: x.packets_n, reverse=True)

        min_index = 0
        max_index = min(self._curses_window.getmaxyx()[0] - 1, len(self.__flows)) or 0

        visible_flows = self.__flows[min_index:max_index]

        for i, flow in enumerate(visible_flows, 1):
            src = FlowTableWindow._shorten_string(flow.l3_src, col_width)
            dst = FlowTableWindow._shorten_string(flow.l3_dst, col_width)

            row = row_format.format(src, dst, flow.src_port, flow.dst_port, PROTOCOL_NUMBERS.get(flow.ip_proto, flow.ip_proto), flow.packets_n, flow.bytes_n)
            self._curses_window.addstr(i, 0, row)


class GlobalStatWindow(Window):
    def __init__(self, height, width, pos_y, pos_x):
        super(GlobalStatWindow, self).__init__(height, width, pos_y, pos_x)

        self.__packets = 0
        self.__avg_packets_per_s = 0
        self.__bytes = 0
        self.__avg_bytes_per_s = 0
        self.__flows = 0
        self.__avg_flows_per_s = 0

    def set_stats(self, packets_n, avg_packets_per_s, bytes_n, avg_bytes_per_s, flows_n, avg_flows_per_s):
        self.__packets = packets_n
        self.__avg_packets_per_s = avg_packets_per_s
        self.__bytes = bytes_n
        self.__avg_bytes_per_s = avg_bytes_per_s
        self.__flows = flows_n
        self.__avg_flows_per_s = avg_flows_per_s

    def _update(self):
        stat_format = "Total Packets: {} | Total avg Packets/s: {:.2f} | Total Bytes: {} | Total avg Bytes/s: {:.2f} | Total Flows: {} | Total avg New Flows/s: {:.2f}"

        self._curses_window.addstr(0, 0, stat_format.format(self.__packets, self.__avg_packets_per_s, self.__bytes, self.__avg_bytes_per_s, self.__flows, self.__avg_flows_per_s), curses.A_BOLD)


class OptionPane(Window):
    def __init__(self, height, width, pos_y, pos_x):
        super(OptionPane, self).__init__(height, width, pos_y, pos_x)

        self.__options = []

    def _update(self):
        sum_len_options = sum(len(option) + 2 for option in self.__options)
        free_space = int((self._curses_window.getmaxyx()[1] - sum_len_options) / len(self.__options))
        free_space = min(free_space, 20)
        option_texts = [option.text.center(free_space) for option in self.__options]

        offset = 0
        for i, option_text in enumerate(option_texts, start=1):
            try:
                self._curses_window.addstr(0, offset, "F" + str(i), curses.A_BOLD)
                offset += 1 + len(str(i))

                self._curses_window.addstr(0, offset, option_text, curses.color_pair(1))
                offset += 1 + len(option_text) + 1
            except:
                raise Exception("given width is not sufficient for displaying all options")

    def set_options(self, options):
        if len(options) > 12:
            raise ValueError('Number of options exceeds 12')

        self.__options = options

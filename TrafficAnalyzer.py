"""
Author: Samir Nuri
Date: 2024-06-22
"""

import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, Text, Scrollbar, VERTICAL, HORIZONTAL, RIGHT, Y, X, BOTH, END
from scapy.all import sniff, conf, IFACES, IP, TCP, UDP, ICMP, ARP
import threading
import time
import logging
import socket
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

logging.basicConfig(level=logging.INFO)

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")

        self.stop_sniffing_event = threading.Event()
        self.captured_packets = []
        self.protocol_counts = defaultdict(int)

        self.setup_gui()

    def setup_gui(self):
        """Setup the graphical user interface components."""
        control_frame = tk.Frame(self.root)
        control_frame.pack(side=tk.TOP, fill=tk.X)

        self.setup_controls(control_frame)
        self.setup_treeview()
        self.setup_plot()

    def setup_controls(self, frame):
        """Setup the control panel."""
        tk.Label(frame, text="Select Network Adapter:").pack(side=tk.LEFT)
        self.adapter_var = tk.StringVar()
        self.adapter_menu = ttk.Combobox(frame, textvariable=self.adapter_var)
        self.adapter_menu.pack(side=tk.LEFT)
        self.adapter_menu['values'] = [iface.name for iface in IFACES.data.values()]
        if self.adapter_menu['values']:
            self.adapter_menu.current(0)

        tk.Button(frame, text="Start Monitoring", command=self.start_monitoring).pack(side=tk.LEFT)
        self.stop_button = tk.Button(frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)

        tk.Button(frame, text="Export", command=self.export_data).pack(side=tk.RIGHT)

        self.filter_entry = tk.Entry(frame)
        self.filter_entry.pack(side=tk.RIGHT)
        self.filter_entry.insert(0, "Enter filter expression")
        tk.Button(frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.RIGHT)

    def setup_treeview(self):
        """Setup the Treeview widget for displaying packet details."""
        columns = ('Time', 'Source', 'Source Name', 'Destination', 'Destination Name', 'Protocol', 'Length', 'Application')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind('<Double-1>', self.show_packet_details)

    def setup_plot(self):
        """Setup the Matplotlib plot."""
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

    def start_monitoring(self):
        """Start monitoring network traffic."""
        self.toggle_buttons(starting=True)
        selected_adapter = self.adapter_var.get()
        if not selected_adapter:
            messagebox.showerror("Error", "Please select a network adapter.")
            self.toggle_buttons(starting=False)
            return
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(selected_adapter,))
        self.sniff_thread.start()

    def stop_monitoring(self):
        """Stop monitoring network traffic."""
        self.stop_sniffing_event.set()
        self.toggle_buttons(starting=False)

    def toggle_buttons(self, starting):
        """Enable/disable start and stop buttons."""
        self.stop_button.config(state=tk.NORMAL if starting else tk.DISABLED)
        for child in self.root.winfo_children():
            if isinstance(child, tk.Button) and child != self.stop_button:
                child.config(state=tk.DISABLED if starting else tk.NORMAL)

    def sniff_packets(self, iface):
        """Sniff network packets on the selected interface."""
        try:
            sniff(iface=iface, prn=self.process_packet, stop_filter=lambda x: self.stop_sniffing_event.is_set())
        except Exception as e:
            logging.error(f"Error while sniffing packets: {e}")

    def process_packet(self, packet):
        """Process each captured packet."""
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
            src_ip = packet[IP].src if IP in packet else 'N/A'
            dst_ip = packet[IP].dst if IP in packet else 'N/A'
            src_name = self.resolve_hostname(src_ip)
            dst_name = self.resolve_hostname(dst_ip)
            length = len(packet)
            proto = self.get_protocol(packet)
            application = self.get_application(proto)

            packet_details = (timestamp, src_ip, src_name, dst_ip, dst_name, proto, length, application)
            self.captured_packets.append((packet_details, packet))
            self.protocol_counts[proto] += 1
            self.tree.insert('', 'end', values=packet_details)
            self.update_plot()
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def resolve_hostname(self, ip):
        """Resolve the hostname for a given IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ip

    def get_protocol(self, packet):
        """Determine the protocol of the packet."""
        if IP in packet:
            if TCP in packet:
                return 'TCP'
            elif UDP in packet:
                return 'UDP'
            elif ICMP in packet:
                return 'ICMP'
            else:
                return str(packet[IP].proto)
        elif ARP in packet:
            return 'ARP'
        else:
            return 'Other'

    def get_application(self, proto):
        """Determine the application layer protocol (placeholder)."""
        return {
            'TCP': 'TCP Application',
            'UDP': 'UDP Application',
        }.get(proto, 'N/A')

    def update_plot(self):
        """Update the Matplotlib plot with the current protocol counts."""
        self.ax.clear()
        protocols, counts = zip(*self.protocol_counts.items())
        self.ax.bar(protocols, counts)
        self.ax.set_xlabel('Protocol')
        self.ax.set_ylabel('Count')
        self.ax.set_title('Protocol Distribution')
        self.canvas.draw()

    def export_data(self):
        """Export captured packets to a file."""
        try:
            with open("captured_packets.txt", "w") as file:
                for packet_details, packet in self.captured_packets:
                    file.write(f"{packet_details}\n")
            logging.info("Data exported successfully")
        except Exception as e:
            logging.error(f"Error exporting data: {e}")

    def apply_filter(self):
        """Apply filter to display only certain packets (placeholder)."""
        filter_expression = self.filter_entry.get()
        logging.info(f"Applying filter: {filter_expression}")

    def show_packet_details(self, event):
        """Show the details of the selected packet."""
        selected_item = self.tree.selection()
        if not selected_item:
            return

        packet_index = self.tree.index(selected_item)
        _, packet = self.captured_packets[packet_index]

        detail_window = Toplevel(self.root)
        detail_window.title("Packet Details")
        
        text_area = Text(detail_window, wrap='none')
        text_area.insert(END, packet.show(dump=True))
        text_area.pack(fill=BOTH, expand=True)
        
        # Adding scrollbars
        y_scrollbar = Scrollbar(detail_window, orient=VERTICAL, command=text_area.yview)
        y_scrollbar.pack(side=RIGHT, fill=Y)
        text_area.config(yscrollcommand=y_scrollbar.set)
        
        x_scrollbar = Scrollbar(detail_window, orient=HORIZONTAL, command=text_area.xview)
        x_scrollbar.pack(side=tk.BOTTOM, fill=X)
        text_area.config(xscrollcommand=x_scrollbar.set)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    root.mainloop()

import tkinter as tk
from tkinter import ttk
from threading import Thread
import sniffer_demo
import subprocess  # Allows running external processes and managing their input/output ( LocateIPs.py)


class PacketSnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Packet Sniffer")
        self.geometry("1200x600")

        self.sniffing = False

        # Frame for controls
        self.control_frame = ttk.Frame(self)
        self.control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        # Start and Stop buttons 
        self.start_button = ttk.Button(self.control_frame, text="▶️ Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)
        self.stop_button = ttk.Button(self.control_frame, text="⏹️ Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        # Search bar
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.control_frame, textvariable=self.search_var)
        self.search_entry.pack(pady=5)
        self.search_entry.bind("<KeyRelease>", self.dynamic_search)

        # Label for KML message
        self.kml_message = ttk.Label(self.control_frame, text="")
        self.kml_message.pack(pady=5)

        # Treeview for displaying packets
        columns = ("Source", "Destination", "Protocol", "Packet Type", "Segment", "Info")
        self.tree = ttk.Treeview(self, columns=columns, show='headings')

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200)

        self.tree.pack(fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side='right', fill='y')

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.tree.delete(*self.tree.get_children())
        self.sniffing_thread = Thread(target=self.sniff_packets)
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.write_unique_ips_to_file()
        self.show_kml_added_message()
        self.run_locate_ips_script()

    def sniff_packets(self):
        sniffer_demo.main(self.display_packet, self.is_sniffing)

    def is_sniffing(self):
        return self.sniffing

    def display_packet(self, packet_info):
        if not self.sniffing:
            return

        tags = ()
        if packet_info["Segment"] == "TCP":
            tags = ("tcp",)
        elif packet_info["Segment"] == "UDP":
            tags = ("udp",)
        elif packet_info["Segment"] == "ICMP":
            tags = ("icmp",)
        elif packet_info["Segment"] == "HTTP":
            tags = ("http",)
        elif packet_info["Packet Type"] == "Ethernet":
            tags = ("ethernet",)

        # Format the TCP segment info for better display
        info = packet_info["Info"]
        if packet_info["Segment"] == "TCP":
            parts = info.split(", Flags: ")
            flag_info = parts[1] if len(parts) > 1 else ""
            main_info = parts[0]
            info = f"{main_info}, Flags: {flag_info}"

        self.tree.insert("", tk.END, values=(
            packet_info["Source"], packet_info["Destination"], packet_info["Protocol"], packet_info["Packet Type"],
            packet_info["Segment"], info), tags=tags)

        self.tree.tag_configure("tcp", background="lightgreen")
        self.tree.tag_configure("udp", background="lightblue")
        self.tree.tag_configure("icmp", background="lightyellow")
        self.tree.tag_configure("http", background="lightcoral")
        self.tree.tag_configure("ethernet", background="lightpink")  # Ensure this tag configuration

    def dynamic_search(self, event):
        search_term = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())

        for packet_info in sniffer_demo.packet_history:
            match = True

            if "src==" in search_term:
                src_filter = search_term.split("src==")[1].split()[0]
                match = src_filter in packet_info["Source"].lower()
            elif "dst==" in search_term:
                dst_filter = search_term.split("dst==")[1].split()[0]
                match = dst_filter in packet_info["Destination"].lower()
            elif "tcp" in search_term:
                match = packet_info["Segment"].lower() == "tcp"
            elif "udp" in search_term:
                match = packet_info["Segment"].lower() == "udp"
            elif "icmp" in search_term:
                match = packet_info["Segment"].lower() == "icmp"
            elif "http" in search_term:
                match = packet_info["Segment"].lower() == "http"
            elif "ethernet" in search_term:
                match = packet_info["Packet Type"].lower() == "ethernet"
            else:
                match = (search_term in packet_info["Source"].lower() or 
                         search_term in packet_info["Destination"].lower() or 
                         search_term in packet_info["Protocol"].lower() or 
                         search_term in packet_info["Packet Type"].lower() or 
                         search_term in packet_info["Segment"].lower() or 
                         search_term in packet_info["Info"].lower())

            if match:
                tags = ()
                if packet_info["Segment"] == "TCP":
                    tags = ("tcp",)
                elif packet_info["Segment"] == "UDP":
                    tags = ("udp",)
                elif packet_info["Segment"] == "ICMP":
                    tags = ("icmp",)
                elif packet_info["Segment"] == "HTTP":
                    tags = ("http",)
                elif packet_info["Segment"] == "Ethernet":
                    tags = ("ethernet",)

                # Format the TCP segment info for better display
                info = packet_info["Info"]
                if packet_info["Segment"] == "TCP":
                    parts = info.split(", Flags: ")
                    flag_info = parts[1] if len(parts) > 1 else ""
                    main_info = parts[0]
                    info = f"{main_info}, Flags: {flag_info}"

                self.tree.insert("", tk.END, values=(
                    packet_info["Source"], packet_info["Destination"], packet_info["Protocol"], packet_info["Packet Type"],
                    packet_info["Segment"], info), tags=tags)

                # Colors of each protocol
                self.tree.tag_configure("tcp", background="lightgreen")
                self.tree.tag_configure("udp", background="lightblue")
                self.tree.tag_configure("icmp", background="lightyellow")
                self.tree.tag_configure("http", background="lightcoral")
                self.tree.tag_configure("ethernet", background="lightpink")
    # Create a file ipFile.txt contains all unique IP sources
    def write_unique_ips_to_file(self):
        unique_ips = set(packet["Source"] for packet in sniffer_demo.packet_history if packet["Packet Type"] == "IPv4")
        with open("ipFile.txt", "w") as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")

    def show_kml_added_message(self):
        self.kml_message.config(text="KML added 📍")

    def run_locate_ips_script(self):
        subprocess.run(["python", "locateIPs.py"])

if __name__ == "__main__":
    app = PacketSnifferApp()
    app.mainloop()

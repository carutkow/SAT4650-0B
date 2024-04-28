import threading
from tkinter import *
from tkinter import scrolledtext
from scapy.all import sniff, TCP, IP
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib import rcParams

# Counter for packets from different source IPs
src_ip_counter = Counter()

# Global variable to control the sniffing loop
stop_sniffing = False

# Function to handle packets, display them in the GUI, and count source IPs
def packet_callback(packet, text_widget):
    global src_ip_counter
    if IP in packet and TCP in packet:
        packet_info = packet.summary()
        text_widget.insert(END, packet_info + '\n')
        src_ip = packet[IP].src
        src_ip_counter[src_ip] += 1

# The function that starts sniffing (to be run in a separate thread)
def start_sniffing(interface_name, text_widget):
    global stop_sniffing
    stop_sniffing = False
    sniff(iface=interface_name, prn=lambda packet: packet_callback(packet, text_widget), 
          store=False, stop_filter=lambda x: stop_sniffing)

# Function to start the IDS thread
def start_ids(interface_name, text_widget):
    ids_thread = threading.Thread(target=start_sniffing, args=(interface_name, text_widget), daemon=True)
    ids_thread.start()

# Function to stop the IDS
def stop_ids():
    global stop_sniffing
    stop_sniffing = True

# Function to create and display a bar chart
def create_bar_chart():
    global src_ip_counter
    plt.figure(figsize=(10, 6))
    top_src_ips = src_ip_counter.most_common(10)
    ips = [ip[0] for ip in top_src_ips]
    counts = [count[1] for count in top_src_ips]
    plt.bar(ips, counts, color='skyblue')
    plt.xlabel('Source IP', fontsize=9)
    plt.ylabel('Packet Count', fontsize=9)
    plt.xticks(rotation=45, fontsize=8)
    plt.yticks(fontsize=8)
    plt.title('Top 10 Source IPs by Packet Count', fontsize=14, fontweight='bold', fontstyle='italic')
    plt.tight_layout()  
    plt.show()

# Setting up the GUI
def setup_gui(interface_name):
    window = Tk()
    window.title("Graphical IDS")
    
    # Configure the main window
    window.config(bg="#add8e6")  
    window.geometry('800x600')  

    # Title Label with fancy font
    title_label = Label(window, text="Graphical IDS", font=("Lucida Handwriting", 30, "italic"), bg="#add8e6")
    title_label.pack(pady=20)  

    # Frame for buttons
    frame = Frame(window, bg="#add8e6")
    frame.pack(pady=20)

    # Start Button
    start_btn = Button(frame, text="Start IDS", command=lambda: start_ids(interface_name, output_text))
    start_btn.pack(side=LEFT, expand=True, padx=10) 

    # Stop Button
    stop_btn = Button(frame, text="Stop IDS", command=stop_ids)
    stop_btn.pack(side=LEFT, expand=True, padx=10)

    # Chart Button
    chart_btn = Button(frame, text="Show Chart", command=create_bar_chart)
    chart_btn.pack(side=LEFT, expand=True, padx=10)

    # ScrolledText widget for displaying packet information
    output_text = scrolledtext.ScrolledText(window, width=70, height=10)
    output_text.pack(pady=10)

    window.mainloop()

# Use the name of the network interface
interface_name = "Killer(R) Wi-Fi 6 AX1650x 160MHz Wireless Network Adapter (200NGW)"

# Initialize the GUI
setup_gui(interface_name)

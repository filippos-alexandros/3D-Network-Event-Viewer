from ursina import *
from ursina import Ursina, window, Button
from ursina.prefabs.file_browser_save import FileBrowser
from ursina import Vec3
from ursina.prefabs.dropdown_menu import DropdownMenu, DropdownMenuButton
import time
import math
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
import threading
from packetClass import packetClass
from nodeClass import nodeClass
from CubeWithLabels import CubeWithLabels

#Handle closing
def on_closing():
    application.quit()

#Start threading and analysis
def process_pcap(file_name):
    analysing_label.enabled=True
    buttonFile.enabled=False
    path = str(file_name)[14:-3]
    threading.Thread(target=analyse, args=(path,)).start()

#Variables for analysis
packets = []
packets_by_protocol = {}
protocol_counts={}
tcp_flood={}
sorted_tcp_flood={}
protocol_names = {
    2054: 'ARP',
    2184: 'Unknown Data Packet',
    34958: 'EAPOL',
    0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IPv4', 5: 'ST', 6: 'TCP', 7: 'CBT', 8: 'EGP', 9: 'IGP',
    10: 'BBN-RCC-MON', 11: 'NVP-II', 12: 'PUP', 13: 'ARGUS (deprecated)', 14: 'EMCON', 15: 'XNET', 16: 'CHAOS',
    17: 'UDP', 18: 'MUX', 19: 'DCN-MEAS', 20: 'HMP', 21: 'PRM', 22: 'XNS-IDP', 23: 'TRUNK-1', 24: 'TRUNK-2',
    25: 'LEAF-1', 26: 'LEAF-2', 27: 'RDP', 28: 'IRTP', 29: 'ISO-TP4', 30: 'NETBLT', 31: 'MFE-NSP', 32: 'MERIT-INP',
    33: 'DCCP', 34: '3PC', 35: 'IDPR', 36: 'XTP', 37: 'DDP', 38: 'IDPR-CMTP', 39: 'TP++', 40: 'IL', 41: 'IPv6',
    42: 'SDRP', 43: 'IPv6-Route', 44: 'IPv6-Frag', 45: 'IDRP', 46: 'RSVP', 47: 'GRE', 48: 'DSR', 49: 'BNA',
    50: 'ESP', 51: 'AH', 52: 'I-NLSP', 53: 'SWIPE (deprecated)', 54: 'NARP', 55: 'Min-IPv4', 56: 'TLSP', 57: 'SKIP',
    58: 'IPv6-ICMP', 59: 'IPv6-NoNxt', 60: 'IPv6-Opts', 61: '', 62: 'CFTP', 63: '', 64: 'SAT-EXPAK', 65: 'KRYPTOLAN',
    66: 'RVD', 67: 'IPPC', 68: '', 69: 'SAT-MON', 70: 'VISA', 71: 'IPCV', 72: 'CPNX', 73: 'CPHB', 74: 'WSN',
    75: 'PVP', 76: 'BR-SAT-MON', 77: 'SUN-ND', 78: 'WB-MON', 79: 'WB-EXPAK', 80: 'ISO-IP', 81: 'VMTP',
    82: 'SECURE-VMTP', 83: 'VINES', 84: 'IPTM', 85: 'NSFNET-IGP', 86: 'DGP', 87: 'TCF', 88: 'EIGRP', 89: 'OSPFIGP',
    90: 'Sprite-RPC', 91: 'LARP', 92: 'MTP', 93: 'AX.25', 94: 'IPIP', 95: 'MICP (deprecated)', 96: 'SCC-SP',
    97: 'ETHERIP', 98: 'ENCAP', 99: '', 100: 'GMTP', 101: 'IFMP', 102: 'PNNI', 103: 'PIM', 104: 'ARIS', 105: 'SCPS',
    106: 'QNX', 107: 'A/N', 108: 'IPComp', 109: 'SNP', 110: 'Compaq-Peer', 111: 'IPX-in-IP', 112: 'VRRP', 113: 'PGM',
    114: '', 115: 'L2TP', 116: 'DDX', 117: 'IATP', 118: 'STP', 119: 'SRP', 120: 'UTI', 121: 'SMP',
    122: 'SM (deprecated)', 123: 'PTP', 124: 'ISIS over IPv4', 125: 'FIRE', 126: 'CRTP', 127: 'CRUDP', 128: 'SSCOPMCE',
    129: 'IPLT', 130: 'SPS', 131: 'PIPE', 132: 'SCTP', 133: 'FC', 134: 'RSVP-E2E-IGNORE', 135: 'Mobility Header',
    136: 'UDPLite', 137: 'MPLS-in-IP', 138: 'manet', 139: 'HIP', 140: 'Shim6', 141: 'WESP', 142: 'ROHC',
    143: 'Ethernet',
    144: 'AGGFRAG', 145: 'NSH', 255: 'Reserved'

}
count_text=""

#Analysis
def analyse(file_name):
    packet_count = 0
    #Loop through packets
    for (pkt_data, pkt_metadata) in RawPcapReader(file_name):

        #Add packet to list
        packet_count += 1
        ether_pkt = Ether(pkt_data)
        packets.append([packet_count, ether_pkt.src, ether_pkt.dst, pkt_metadata.caplen])

        if 'type' not in ether_pkt.fields:
            #Disregard LLC frames as they have no type
            continue

        #Check non-IP packets and organise
        if ether_pkt.type != 0x0800 and ether_pkt.type != 0x86DD:
            if ether_pkt.type not in protocol_counts:
                protocol_counts[ether_pkt.type] = 1
                packets_by_protocol[ether_pkt.type] = [[ether_pkt.src, ether_pkt.dst, pkt_metadata.caplen]]
            else:
                protocol_counts[ether_pkt.type] += 1
                packets_by_protocol[ether_pkt.type].append([ether_pkt.src, ether_pkt.dst, pkt_metadata.caplen])

        else:
            #Check IPv4 packets
            if ether_pkt.type == 0x0800:
                ip_pkt = ether_pkt[IP]
                #Extract info for TCP SYN flood
                if ip_pkt.proto == 6:
                    flag = ip_pkt['TCP'].flags
                    if flag == 'S':  # SYN flag
                        if ip_pkt.src in tcp_flood:
                            tcp_flood[ip_pkt.src][0] += 1
                        else:
                            tcp_flood[ip_pkt.src] = [1, 0]
                    elif flag == 'A':  # SYN-ACK flag
                        if ip_pkt.src in tcp_flood:
                            tcp_flood[ip_pkt.src][1] += 1
                        else:
                            tcp_flood[ip_pkt.src] = [0, 1]
                if ip_pkt.proto not in protocol_counts:
                    protocol_counts[ip_pkt.proto] = 1
                    packets_by_protocol[ip_pkt.proto] = [[ip_pkt.src, ip_pkt.dst, pkt_metadata.caplen]]
                else:
                    protocol_counts[ip_pkt.proto] += 1
                    packets_by_protocol[ip_pkt.proto].append([ip_pkt.src, ip_pkt.dst, pkt_metadata.caplen])

            else:
                #Check IPv6 packets
                ip_pkt = ether_pkt[IPv6]
                if ip_pkt.nh not in protocol_counts:
                    protocol_counts[ip_pkt.nh] = 1
                    packets_by_protocol[ip_pkt.nh] = [[ip_pkt.src, ip_pkt.dst, pkt_metadata.caplen]]
                else:
                    protocol_counts[ip_pkt.nh] += 1
                    packets_by_protocol[ip_pkt.nh].append([ip_pkt.src, ip_pkt.dst, pkt_metadata.caplen])

    #Prepare output
    global count_text
    count_text+='{} packets. \n\n'.format(packet_count)
    count_text+='Protocol Counts:\n'
    global sorted_tcp_flood
    sorted_counts = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)
    sorted_tcp_flood = sorted(tcp_flood.items(), key=lambda item: item[1][0] - item[1][1], reverse=True)

    global options
    options=[]
    #Assign name to each protocol code and send to output
    for proto, count in sorted_counts:
        if proto in protocol_names:
            proto_name = protocol_names[proto]
        else:
            proto_name = 'Unknown'
        count_text+=f'{proto_name}: {count}\n'
        options.append(proto_name)
    text.text=count_text

    #Create output panel and adjust interface
    panel.position = (0.8 - (text.width / 2), -0.35 + (text.height / 2))
    panel.scale = (text.width + 0.05, text.height + 0.05)
    panel.enabled=True
    text.position = (0.8 - text.width, -0.35 + text.height)
    text.enabled=True
    analysing_label.enabled=False
    text_entity.enabled=True
    up_arrow.enabled=True
    down_arrow.enabled=True
    attack_button.enabled=True

#Compression
def simplify(nodes, node_count, packetObjs):
    max_nodes=10
    if len(nodes)>max_nodes:
        sorted_node_counts = dict(sorted(node_count.items(), key=lambda item: item[1], reverse=True))
        nodes = list(sorted_node_counts.keys())[:(max_nodes-1)]
        remaining_nodes=len(list(sorted_node_counts.keys()))-(max_nodes-1)
        nodes.append(str(remaining_nodes)+" other nodes")
        for i in packetObjs:
            if (i.startNode not in nodes):
                i.startNode=(str(remaining_nodes)+" other nodes")
            if(i.endNode not in nodes):
                i.endNode=(str(remaining_nodes)+" other nodes")
            if i.startNode==i.endNode:
                packetObjs.remove(i)
    return(nodes, packetObjs)





entities=[]
nodeObjs = []
packetObjs = []
#Visualisation
def visualise(option):
    #Reset variables from previous iterations
    global entities
    global packetObjs
    global nodeObjs
    for obj in entities:
        obj.enabled = False
        destroy(obj)
    for obj in packetObjs:
        del(obj)
    for obj in nodeObjs:
        del(obj)
    entities=[]
    packetObjs=[]
    nodeObjs=[]
    nodes=[]
    positions = []
    protocol = None
    selected_packets=[]

    #Get packets for selected protocol
    for key, val in protocol_names.items():
        if val == option:
            protocol = key
    selected_packets = packets_by_protocol[protocol]


    #Create packet objects and get nodes
    nodes = []
    node_counts = {}
    for i in selected_packets:
        for node in i[:2]:
            if node not in nodes:
                nodes.append(node)
            if node in node_counts:
                node_counts[node] += 1
            else:
                node_counts[node] = 1
        packetObjs.append(packetClass(i[0], i[1]))

    (nodes, packetObjs) = simplify(nodes, node_counts, packetObjs)
    count = len(nodes)

    #Calculations for circle
    offset = 2.0 / count
    increment = math.pi * (3.0 - math.sqrt(5.0))
    radius = 3.5

    #Create list of 3D positions
    for i in range(count):
        y = ((i * offset) - 1) + (offset / 2)
        r = math.sqrt(1 - y ** 2)
        phi = ((i + 1) % count) * increment

        x = math.cos(phi) * r
        z = math.sin(phi) * r

        positions.append((x * radius, y * radius, z * radius))

    #Create node objects
    for i, obj in enumerate(nodes):
        cube_entity = CubeWithLabels(text=str(nodes[i]), position=positions[i])
        entities.append(cube_entity)
        nodeObjs.append(nodeClass(obj, 0, True, positions[i], cube_entity))

    #Get position of nodes per packet
    def process_packets():
        if not packetObjs:
            return

        #Get packet object
        packet_obj = packetObjs[0]
        packetObjs.pop(0)
        start_node = packet_obj.startNode
        end_node = packet_obj.endNode
        start_node_obj = None
        end_node_obj = None

        #Find corresponding node objects
        for node_obj in nodeObjs:
            if node_obj.address == start_node:
                start_node_obj = node_obj
            if node_obj.address == end_node:
                end_node_obj = node_obj
            if start_node_obj is not None and end_node_obj is not None:
                break

        #Shoot packet
        if start_node_obj and end_node_obj:
            shoot_packet(start_node_obj, end_node_obj)


        #Schedule next packet
        if entities!=[]:
            invoke(process_packets, delay=0.1)


    process_packets()

#Packet movement
def shoot_packet(start, end):
    #Create packet sphere
    start_pos=start.pos
    end_pos=end.pos
    packet = Entity(model='sphere', color=color.white, scale=0.1, position=start_pos)
    entities.append(packet)

    #Convert end_pos to Vec3
    start_pos_Vec3=Vec3(*start_pos)
    end_pos_vec3=Vec3(*end_pos)

    #Calculate step size for each dimension (x, y, z)
    step_x = (end_pos_vec3.x - start_pos[0]) / 50
    step_y = (end_pos_vec3.y - start_pos[1]) / 50
    step_z = (end_pos_vec3.z - start_pos[2]) / 50

    #Threshold distance to determine when the packet reaches its destination
    threshold_distance = 0.1

    #Move packet
    def move(start_pos, end_pos, start, end):
        try:
            distance_to_end = (end_pos_vec3 - packet.position).length()
            distance_to_start = (start_pos_Vec3 - packet.position).length()
            #Flash source node and initiate movement
            if distance_to_start <= threshold_distance:
                start.cube.flash_text_white()
                packet.position += Vec3(step_x, step_y, step_z)
                #Schedule next move after a delay
                invoke(move, start_pos, end_pos, start, end, delay=0.02)
            elif distance_to_end >= threshold_distance:
                #Update the position
                packet.position += Vec3(step_x, step_y, step_z)
                #Schedule next move after a delay
                invoke(move, start_pos, end_pos, start, end, delay=0.02)
            else:
                #Destroy the packet once it reaches destination
                destroy(packet)
                #Flash destination node
                end.cube.flash_text_white()
        except Exception as e:
            #Entity no longer exists, do nothing
            pass

    #Start moving the packet
    if entities != []:
        move(start_pos, end_pos, start, end)

#SYN Flood data
def attack_centre():

    tcp_flood = [i for i in sorted_tcp_flood if (i[1][0] - i[1][1]) >= 0]

    if tcp_flood:
        #Formatting of text file
        max_key_length = max(len(key) for key, _ in tcp_flood)
        max_value_length = max(len(str(value[0])) for _, value in tcp_flood)
        title_row = f"{'Address'.ljust(max_key_length)}     {'SYN'.ljust(max_value_length)},     {'ACK'}"

        #Convert dictionary to string with each key-value pair on new line
        text_content = '\n'.join(
            [f"{key.ljust(max_key_length)}     {str(value[0]).ljust(max_value_length)}     {value[1]}" for key, value in
             tcp_flood])
        text_content = title_row + '\n\n' + text_content
    else:
        text_content='No TCP flood indications'
    #Path to the file
    file_path = 'TCP_Flood_Analysis.txt'

    #Open the file in write mode and write the text
    with open(file_path, 'w') as file:
        file.write(text_content)

    #Open file for different OS
    try:
        subprocess.Popen(['xdg-open', file_path])  # For Linux
    except:
        try:
            subprocess.Popen(['open', file_path])  # For macOS
        except:
            subprocess.Popen(['start', file_path], shell=True)  # For Windows




#'Main' function
def update():
    global animation_started, nodes
    if not animation_started:
        buttonFile.enabled = True
    else:
        buttonFile.enabled = False

#File selection browser
p=None
def open_file_dialog():
    global p
    buttonFile.enabled=False

    def on_submit(path):
        global animation_started, p
        process_pcap(path)
        buttonFile.enabled=False
        animation_started=True

    fb = FileBrowser(file_types='.pcap')
    fb.on_submit = on_submit

#Window settings
app = Ursina(on_window_close=on_closing)
animation_started=False
window.borderless=False
window.exit_button.enabled=False
EditorCamera()

#Labels and buttons
title_label = Text(
    text="Network Event Viewer",
    origin=(0, 0),
    y=0.45,
    color=color.white,
    scale=2
)

buttonFile = Button(
    text="Open .pcap File",
    color=color.rgb(100, 120, 140),
    scale=(0.3, 0.05),
    on_click=open_file_dialog
)

analysing_label = Text(
    text="Analysing... Please wait",
    origin=(0, 0),
    color=color.white,
    scale=1.2,
    enabled = False
)

panel = Panel(
    scale=(0.3, 0.4),
    position=(0.7,-0.23),
    color=color.gray,
    enabled=False
)

text = Text(
    text=count_text,
    scale=1,
    color=color.white,
    position=(0.8,0),
    enabled=True
)
options = ["Select a Protocol"]
current_option_index = 0

#Labels, buttons, and text changes for switching protocol
def update_text():
    global nodes, current_option_index, animation_started
    text_entity.text = options[current_option_index]
    visualise(text_entity.text)
    animation_started = True

def prev_option():
    global current_option_index
    current_option_index = (current_option_index - 1) % len(options)
    update_text()

def next_option():
    global current_option_index
    current_option_index = (current_option_index + 1) % len(options)
    update_text()

text_entity = Text(
    text=options[current_option_index],
    position = (-0.8,0.1),
    scale=1,
    enabled=False

)

down_arrow = Button(
    text='Previous',
    text_color = color.white,
    position=(-0.7, 0),  # Set the position of the down arrow
    color=color.rgb(100, 120, 140),
    scale=(0.2, 0.05),  # Adjust the scale of the button as needed
    enabled=False,  # Initially disabled
    on_click=prev_option  # Assign the click event handler
)

up_arrow = Button(
    text="Next",
    text_color=color.white,
    position=(-0.7, 0.2),  # Set the position of the up arrow
    color=color.rgb(100, 120, 140),
    scale=(0.2, 0.05),  # Adjust the scale of the button as needed
    enabled=False,  # Initially disabled
    on_click=next_option  # Assign the click event handler
)

attack_button = Button(
    text="Attack Centre",
    text_color=color.white,
    position=(-0.7, -0.2),  # Set the position of the up arrow
    color=color.rgb(100, 120, 140),
    scale=(0.2, 0.05),  # Adjust the scale of the button as needed
    enabled=False,  # Initially disabled
    on_click=attack_centre  # Assign the click event handler
)


app.run()

#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

import binascii

# list of all interfaces of the switch
interfaces = []

# map associating each interface name with the corresponding interface
interfaces_map = {}

# map associating a mac address with the corresponding interface
cam_table = {}

# map associating each interface with the corresponding vlan_id (if it is an access port)
# or with the letter "T" (if it is a trunck port)
vlan_map = {}

# map associating trunck ports with their state: "BLOCKED" or "LISTENING"
port_states = {}

# switch's priority -> will be used for calculating the bridge id
priority = -1

# global variables for stp
current_bid = 0
root_bid = 0
root_path_cost = 0
root_port = -1
dest_mac_multicast = '01:80:c2:00:00:00'
this_switch_mac = ''


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)


def is_unicast(mac_address):
    broadcast_address = "ff:ff:ff:ff:ff:ff"
    # check if the mac_address is broadcast, otherwise it is unicast so we should return true
    if mac_address != broadcast_address:
        return True
    return False


def handle_frame_redirection_according_to_vlan(vlan_map, destination_interface, arrival_interface, vlan_id, data, length):
    # check if the current frame travels between to trunck ports => the vlan_id is already added to the frame
    # so there is no need to add or remove anything from the frame
    # => the frame remains as it is
    if (vlan_map[arrival_interface] == "T" and vlan_map[destination_interface] == "T" and port_states[destination_interface] != "BLOCKED"):
        send_to_link(destination_interface, length, data)
    elif (vlan_map[arrival_interface] != "T" and vlan_map[destination_interface] == "T" and port_states[destination_interface] != "BLOCKED"):
        # if the frame comes from an access port and needs to travel through a trunck port, we need to add vlan_id header
        vlan_tag = create_vlan_tag(int(vlan_map[arrival_interface]))
        data = data[0 : 12] + vlan_tag + data[12:]
        length = length + 4
        send_to_link(destination_interface, length, data)
    elif (vlan_map[arrival_interface] == "T" and vlan_map[destination_interface] != "T"):
        # if the current frame comes from a trunck port and then travels through an access port, we need to remove the vlan tag
        destination_vlan = int(vlan_map[destination_interface])
        if (destination_vlan == vlan_id):
            data = data[0:12] + data[16:]
            length = length - 4
            send_to_link(destination_interface, length, data)
    elif (vlan_map[arrival_interface] != "T" and vlan_map[destination_interface] != "T"):
        # if both ports are access ports, we do not need to modify the frame, we only need to
        # check if the source and the destination are part of the same vlan
        curent_vlan_id = int(vlan_map[arrival_interface])
        destination_vlan_id = int(vlan_map[destination_interface])
        if (destination_vlan_id == curent_vlan_id):
            send_to_link(destination_interface, length, data)

# functions to populate each field of the bpdu packet header individually

# function that returns the src_mac and the dest_mac converted to byte objects
def build_mac_headers(dest_mac_multicast, switch_mac):
    dest_mac = binascii.unhexlify(dest_mac_multicast.replace(':',''))
    src_mac = binascii.unhexlify(switch_mac.replace(':',''))
    return dest_mac, src_mac

def build_llc_header():
    dsap = 0x42
    ssap = 0x42
    control = 0x03
    return dsap, ssap, control

def build_bpdu_header():
    proto_id = 0x0000
    proto_version_id = 0x00
    bpdu_type = 0x00
    return proto_id, proto_version_id, bpdu_type

def build_bpdu_config(root_bid, root_path_cost, own_bid):
    flags = 0x00
    root_bid_copy = root_bid
    root_path_cost_copy = root_path_cost
    own_bid_copy = own_bid
    port_id = 0
    message_age = 1
    max_age = 20
    hello_time = 2
    forward_delay = 15
    return flags, root_bid_copy, root_path_cost_copy, own_bid_copy, port_id, message_age, max_age, hello_time, forward_delay


def create_bpdu_packet():
    global current_bid, root_bid, root_path_cost, priority, dest_mac_multicast, this_switch_mac

    # set up fields in bpdu packet according to 802.2 Logical Link Control header
    dest_mac, src_mac = build_mac_headers(dest_mac_multicast, this_switch_mac)

    llc_length = 38
    dsap, ssap, control = build_llc_header()

    proto_id, proto_version_id, bpdu_type = build_bpdu_header()

    flags, root_bid_copy, root_path_cost_copy, own_bid_copy, port_id, message_age, max_age, hello_time, forward_delay = build_bpdu_config(root_bid, root_path_cost, current_bid)

    result_bpdu_packet = struct.pack("!6s6sHBBBHBBBQIQHHHHH", dest_mac, src_mac, llc_length, dsap, ssap, control, proto_id, proto_version_id, bpdu_type,
                        flags, root_bid_copy, root_path_cost_copy, own_bid_copy,
                        port_id, message_age, max_age, hello_time, forward_delay)
    
    return result_bpdu_packet


def send_bdpu_every_sec():
    global current_bid, root_bid
    while True:
        bpdu_packet = create_bpdu_packet()
        if current_bid == root_bid:
            for port in port_states:
                if (port != root_port):
                    send_to_link(port, len(bpdu_packet), bpdu_packet)
                        
        time.sleep(1)


def handle_bpdu_packet(data, interface):
    global root_bid, root_path_cost, root_port

    # unpack bpdu packet in order to extract the fields that we will need for the stp algorithm
    bpdu_unpacked = struct.unpack("!6s6sHBBBHBBBQIQHHHHH", data)

    bpdu_root_bridge_ID = bpdu_unpacked[10]
    bpdu_sender_path_cost = bpdu_unpacked[11]
    bpdu_sender_bridge_ID = bpdu_unpacked[12]

    # implement stp algorithm following the pseudocode on ocw
    if root_bid == current_bid:
        we_were_root_bridge = True
    
    if (bpdu_root_bridge_ID < root_bid):
        root_bid = bpdu_root_bridge_ID
        root_path_cost = bpdu_sender_path_cost + 10
        root_port = interface

        if (we_were_root_bridge == True):
            for curr_port in port_states:
                if curr_port!= root_port:
                    port_states[curr_port] = "BLOCKED"
        
        # in case root port is blocked => make it designated
        if port_states[root_port] == "BLOCKED":
            port_states[root_port] = "DESIGNATED"

        # update root bridge and forward a newly created bpdu to all other trunck ports
        for curr_port in port_states:
            if curr_port != root_port:
                bpdu_packet = create_bpdu_packet()
                send_to_link(curr_port, len(bpdu_packet), bpdu_packet)

    elif bpdu_root_bridge_ID == root_bid:
        if interface == root_port and bpdu_sender_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_sender_path_cost + 10
        elif interface != root_port:
            if bpdu_sender_path_cost > root_path_cost:
                if port_states[interface] == "BLOCKED":
                    port_states[interface] = "DESIGNATED"

    elif bpdu_sender_bridge_ID == current_bid:
        port_states[interface] = "BLOCKED"

    else:
        return
    
    if current_bid == root_bid:
        for curr_port in port_states:
            port_states[curr_port] = "DESIGNATED"

# function that makes all initializations for stp as advised on ocw
def init_for_stp():
    # for the beginning of the stp algorithm, each switch considers itself rootbridge,
    # so we need to set all ports on designated
    global priority, current_bid, root_bid, root_path_cost, vlan_map, interfaces
    current_bid = priority
    root_bid = current_bid
    root_path_cost = 0
    if (current_bid == root_bid):
        for curr_port in port_states:
            port_states[curr_port] = "DESIGNATED"

# function that parses the input file and populates the some maps that we are going to use later
def read_input_from_file(switch_id):
    global priority, vlan_map, port_states
    idx = 0 # index incicating the number of the current line of the file

    filename = "configs/switch" + switch_id + ".cfg"
    file = open(filename)
    lines = file.readlines()
    
    for line in lines:
        if (idx == 0):
            # if we are on the first line of the file, we need to read the priority of the switch
            priority = int(line.strip())
            idx = idx + 1
            continue
    
        line = line.strip()
        line = line.split(" ")
        currInterface = interfaces_map[line[0]]
        vlan_map[currInterface] = line[1]
        # for the beginning, set all trunck ports to "blocked"
        if (line[1] == "T"):
            port_states[currInterface] = "BLOCKED"
        idx = idx + 1
    
    file.close()

# function that decides which redirection strategy we should approach (depending if the
# mac destination address is already known by the switch or not or if it is broadcast)
def redirect_frame(dest_mac, interface, vlan_id, data, length):
    global cam_table, vlan_map, interfaces, port_states
    if is_unicast(dest_mac):
        # check if there is already an entry for this mac address in the mac table
        if (dest_mac in cam_table):
            handle_frame_redirection_according_to_vlan(vlan_map, cam_table[dest_mac], interface, vlan_id, data, length)
        else:
            for curr_interface in interfaces:
                if curr_interface != interface:
                    handle_frame_redirection_according_to_vlan(vlan_map, curr_interface, interface, vlan_id, data, length)

    else:
        # if the mac destination is broadcast, we should transmit the frame on all ports except from the one on which it came
        for curr_interface in interfaces:
            if curr_interface != interface:
                handle_frame_redirection_according_to_vlan(vlan_map, curr_interface, interface, vlan_id, data, length)
    

def main():
    global cam_table, vlan_map, interfaces_map, interfaces, port_states, priority, current_bid, root_bid, root_path_cost, root_port, dest_mac_multicast, this_switch_mac
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    this_switch_mac = ':'.join(f'{b:02x}' for b in get_switch_mac())

    for i in interfaces:
        interfaces_map[get_interface_name(i)] = i

    read_input_from_file(switch_id)

    # initializations for stp -> consider this switch as root bridge for the moment
    init_for_stp()

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]
        
        # update cam_table by adding an entry for the current mac source address
        cam_table[src_mac] = interface

        # Check whether we have received a bpdu packet or a frame 
        if dest_mac == dest_mac_multicast:
            # we have received a bpdu packet => we need to extract the useful information from it
            handle_bpdu_packet(data, interface)
        else: 
            redirect_frame(dest_mac, interface, vlan_id, data, length)
        


            
if __name__ == "__main__":
    main()

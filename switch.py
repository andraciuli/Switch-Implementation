#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

dest_mac_bytes = bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00])

own_bridge_ID = -1
root_bridge_ID = -1
root_path_cost = -1
root_port = -1

# List of HashMap for each VLAN
mac_table = []
# HashMap for port informations
# Key: port, Value: [interface_type, port_state]
interface_info = {} 
# List of trunk ports
trunk_ports = []

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

def send_bdpu_every_sec():
    global root_bridge_ID, root_path_cost, own_bridge_ID
    while True:
        if own_bridge_ID == root_bridge_ID and root_bridge_ID != -1 and root_path_cost != -1:
            # Send BPDU packages to all trunk ports if the switch is the root bridge
            for port in trunk_ports:
                root_bridge_ID = own_bridge_ID
                sender_bridge_ID = own_bridge_ID
                root_path_cost = 0
                package = create_BPDU_package(sender_bridge_ID, port, root_path_cost, root_bridge_ID)
                send_to_link(port, len(package), package)
        time.sleep(1)

def read_switch_info(switch_id):
    with open(f'configs/switch{switch_id}.cfg', 'r') as file:
        return file.read()

def is_unicast(mac):
    # Convert the MAC address to an integer
    mac_int = int(mac.replace(":", ""), 16)
    # Check the least significant bit of the first byte
    return (mac_int & 0x010000000000) == 0

def broadcast(interface, interfaces, length, data, vlan_id, cameFromTrunk):
    global interface_info
    for i in interfaces:
        if i != interface:
            # Check if the interface is a trunk port and is not blocked
            dest_is_trunk = interface_info[i][0] == 'T' and interface_info[i][1] != 'BLOCKED'
            if dest_is_trunk:
                # If the frame came from a trunk port, send the frame without adding a VLAN tag
                if cameFromTrunk:
                    send_to_link(i, length, data)
                else:
                    send_to_link(i, length + 4, data[:12] + create_vlan_tag(vlan_id) + data[12:])
            elif interface_info[i][0] == str(vlan_id):
                if cameFromTrunk:
                    send_to_link(i, length - 4, data[:12] + data[16:])
                else:
                    send_to_link(i, length, data)

def create_BPDU_package(sender_bridge_ID, port, root_path_cost, root_bridge_ID):
    global dest_mac_bytes

    stp = b"\x42"
    control = 3

    # Logical Link Control header
    # DSAP = 0x42, SSAP = 0x42, Control = 3
    logical_link = stp * 2 + control.to_bytes(1, byteorder='big')

    zero = 0
    # STP BPDU header
    # Protocol ID = 0, Version = 0 (STP), BPDU Type = 0 (Configuration), BPDU Flags = 0
    bytes_header = zero.to_bytes(4, byteorder='big')

    MESSAGE_AGE = struct.pack('!H', 0)
    MAX_AGE = struct.pack('!H', 20)
    HELLO_TIME = struct.pack('!H', 2)
    FORWARD_DELAY = struct.pack('!H', 15)
    llc_length = struct.pack('!H', 38)

    bytes_configurations = (

        zero.to_bytes(1, byteorder='big') +
        # Root Identifier
        int(root_bridge_ID).to_bytes(8, byteorder='big') +
        # Root Path Cost
        int(root_path_cost).to_bytes(4, byteorder='big') +
        # Bridge Identifier
        int(sender_bridge_ID).to_bytes(8, byteorder='big') +
        # Port Identifier
        port.to_bytes(2, byteorder='big') +
        MESSAGE_AGE +
        MAX_AGE +
        HELLO_TIME +
        FORWARD_DELAY
    )

    # Construct and return the full BPDU package
    return (
        dest_mac_bytes +
        get_switch_mac() +
        llc_length +
        logical_link +
        bytes_header +
        bytes_configurations
    )

def receive_bpdu(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface_from, BPDU_sender_bridge_ID):
    # the stp algorithm is the one from the pseudocode 
    global root_bridge_ID, root_path_cost, root_port, interface_info, own_bridge_ID

    weWereRootBridge = (root_bridge_ID == own_bridge_ID)

    if BPDU_root_bridge_ID < int(root_bridge_ID):
        root_bridge_ID = BPDU_root_bridge_ID
        root_path_cost = BPDU_sender_path_cost + 10
        root_port = interface_from

        if weWereRootBridge:
            for i in trunk_ports:
                if i != root_port:
                    interface_info[i][1] = 'BLOCKED'

        if interface_info[root_port][1] == 'BLOCKED':
            interface_info[root_port][1] = 'DESIGNATED'

        for port in trunk_ports:
            package = create_BPDU_package(own_bridge_ID, port, root_path_cost, root_bridge_ID)
            send_to_link(port, len(package), package)

    elif BPDU_root_bridge_ID == root_bridge_ID:
        if interface_from == root_port and BPDU_sender_path_cost + 10 < root_path_cost:
            root_path_cost = BPDU_sender_path_cost + 10
        elif interface_from != root_port:
            if BPDU_sender_path_cost > root_path_cost:
                if interface_info[interface_from][1] == 'BLOCKED':
                    interface_info[interface_from][1] = 'DESIGNATED'

    elif BPDU_sender_bridge_ID == own_bridge_ID:
        interface_info[interface_from][1] = 'BLOCKED'
    else:
        return
    
    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            interface_info[port][1] = 'DESIGNATED'

def main():
    global root_bridge_ID, own_bridge_ID, root_path_cost
    switch_id = sys.argv[1]
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    for i in interfaces:
        mac_table.append({})

    file_data = read_switch_info(switch_id).split('\n')
    switch_priority = file_data[0]

    for i in interfaces:
        line_split = file_data[i + 1].split(' ')
        if len(line_split) == 2:
            interface_info[i] = [line_split[1], 'BLOCKED']
            if line_split[1] == 'T':
                trunk_ports.append(i)

    own_bridge_ID = switch_priority
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0

    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            interface_info[port][1] = 'DESIGNATED'

    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()
        
    while True:
        interface, data, length = recv_from_any_link()
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Check if the frame is a BPDU package
        if dest_mac == dest_mac_bytes:
            # Extract the BPDU package fields
            BPDU_root_bridge_ID = int.from_bytes(data[22:30], 'big')
            BPDU_sender_path_cost = int.from_bytes(data[30:34], 'big')
            BPDU_sender_bridge_ID = int.from_bytes(data[42:50], 'big')
            # Handle the BPDU package
            receive_bpdu(BPDU_root_bridge_ID, BPDU_sender_path_cost, interface, BPDU_sender_bridge_ID)
            continue

        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)
        # Check if the frame came from a trunk port by checking the interface type
        cameFromTrunk = (interface_info[interface][0] == 'T')
        
        # If the frame came from a trunk port and the interface is blocked, ignore the frame
        if cameFromTrunk and interface_info[interface][1] == 'BLOCKED':
            continue

        vlan_id = int(interface_info[interface][0]) if not cameFromTrunk else vlan_id
        mac_table[vlan_id][src_mac] = interface

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')
        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        if is_unicast(dest_mac):
            # If the destination MAC address is in the MAC table, send the frame to the corresponding interface
            if dest_mac in mac_table[vlan_id]:
                dest_interface = mac_table[vlan_id][dest_mac]
                # Check if the destination interface is a trunk port
                dest_is_trunk = interface_info[dest_interface][0] == 'T' and interface_info[dest_interface][1] != 'BLOCKED'  
                if dest_is_trunk:
                    # If the dest is not a trunk port, add a VLAN tag to the frame
                    if not cameFromTrunk:
                        data = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                        length += 4
                # If the destination interface is an access port and the frame came from a trunk port, remove the VLAN tag
                else:
                    if cameFromTrunk:
                        data = data[:12] + data[16:]
                        length -= 4
                send_to_link(dest_interface, length, data)
            # If the destination MAC address is not in the MAC table, broadcast the frame to all interfaces
            else:
                broadcast(interface, interfaces, length, data, vlan_id, cameFromTrunk)
        # If the destination MAC address is a broadcast address, broadcast the frame to all interfaces
        else:
            broadcast(interface, interfaces, length, data, vlan_id, cameFromTrunk)

if __name__ == "__main__":
    main()

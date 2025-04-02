Cerinte implementate - 1 2 3
#### Ciulinca Andra Stefania - 334CA

## Switch Implementation

For this homework I used a list of HashMaps (mac_table), one for each vlan_id, that keeps a port as a value for every mac address. Interface_info is a HashMap that keeps infromations about the port like its type (trunk or access) and its state (BLOCKES or DESIGNATED). 

First the function read_switch_info reads the switch's configuration file and returns its contents as a string. The main code then splits this data into lines, extracting the switch_priority from the first line. For each interface in interfaces, gets the coresponding information in the file and adds it in the interface_info HashMap. It records the port type ('T' for trunk ports) and sets the initial status of the interface to 'BLOCKED'. It then sets the own_bridge_ID and root_bridge_ID to switch_priority, with an initial root_path_cost of zero. If the port becomes root bridge, it marks all trunk ports as 'DESIGNATED'.

Then, for the third task, we check if we have a BPDU package by verifying if the destination address is the same as the multicast MAC address. If it is then we extract the infromation from the package and handle the BPDU based on the pseudocode provided in the homework description. If the Bridge ID from the BPDU is less than the root bridge the switch that send the package becomes root bridge. The BPDU package is the send to every port. For that we need to rebuild the package using 
802.2 Logical Link Control header encapsulation. The ogical Link Control header 
contains the DSAP(0x42), SSAP(0x42) and control field(0x03). Then the Spanning Tree Protocol fields are added. These two are returned combined with the Ethernet header with mac destination, the source and default length.
If we are the root bridge, a BPDU package is sent every second, by building the package with the same logic as above.

Then we have a couple of cases. For the first task we can have a unicast farme with the mac destination in the CAM table. If the destination mac is in the mac table:
- If the destination port is a trunk port
    * If the package came from a trunk port: we send it as it is without a vlan tag  
    * If the package came from a access port: we add the vlan tag to the frame and increase the length by 4.
- If the destination port is an access portbroadcast
    * If the package came from a trunk port: we remove the vlan tag and decrease the length
    * If the package came from a access port: we send it as it is without a vlan tag 
Otherwise we broadcast it to every port that is trunk and not blocked or if we have a frame that is not unicast is is also broadcasted to very available port. When broadcasting we have the same cases as above but checked for every available port.
We can find if the frame is unicast based off the LSB of the first byte in the destination MAC address. If the bit is not set, then the frame is unicast.

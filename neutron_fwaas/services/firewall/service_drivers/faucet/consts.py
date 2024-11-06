TCP = "tcp"
UDP = "udp"
ICMP = "icmp"


TCP_NUM = 6
UDP_NUM = 17
ICMP_NUM = 1

PROTOCOL_NUM_MAP = {TCP: TCP_NUM, UDP: UDP_NUM, ICMP: ICMP_NUM}

ALLOWED_PROTOCOLS = [TCP, UDP, ICMP]

ARP_ETH_TYPE = "0x0806"
IPV4_ETH_TYPE = "0x0800"

PRIVATE_SUBNETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

UNTRACKED_STATE = "0/0x20"

ESTABLISHED_STATE = "0x22/0x22"

NEW_STATE = "0x21/0x21"

IPV4_ETH_TYPE = "0x0800"

COMMIT_FLAG = 1

# The table to reinject the packet after sending it through the conntrack module
UNTRACKED_TABLE = 0

# The table to pass the packet to after successfully opening a new conntrack
TRACKED_TABLE = 1

# We assume that we'll have 5536 ct zones starting from 60000
# OVN will be modified to only use from 0 -> 59999
# We'll only use atmost 4094 ct zones (this could be even less considering many VLANs are used for different purposes) one for each VLAN
CT_ZONE_OFFSET = 60000

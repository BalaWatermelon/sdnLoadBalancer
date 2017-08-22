from ryu.lib.packet import packet, ethernet, arp
from ryu.ofproto import ether

class arper():
    OPT={ 'REPLY':2 }

    def __init__(self, mac):
        self.mac = mac

    # Reply switch(Router) mac when recieved arp request
    # parameter : arp packet
    def create_reply_packet(self,arp_packet):
        e = ethernet.ethernet(dst=arp_packet.src_mac,
                              src=self.mac,
                              ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=arper.OPT['REPLY'],
                    src_mac=self.mac, src_ip=arp_packet.dst_ip,
                    dst_mac=arp_packet.src_mac, dst_ip=arp_packet.src_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        #print('arper',p)
        return p

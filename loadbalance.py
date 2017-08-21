# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.dpid import str_to_dpid

class PingSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(PingSwitch13, self).__init__(*args, **kwargs)

	@set_ev_cls(ofp_event.EventOFPPacketIn, CONFIG_DISPATCHER)
	def packet_in_handler(self, ev):
	    msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']
	    
            pkt = packet.Packet(msg.data)
	    
	
	def packet_type_sorter(self, packet):
	    eth = packet.get_protocols(ethernet.ethernet)[0]
	    ip = packet.get_protocols(ipv4.ipv4)
	    
	    
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		
		# table-miss default: DROP
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
						  ofproto.OFPCML_NO_BUFFER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		self.add_flow(datapath, 0, match, actions, inst)
		
		if datapath.id == 1: # SWITCH 1

			# Flow direct to http server.
			match = parser.OFPMatch(eth_type = 0x0800, ipv4_dst = "10.0.0.3", ip_proto=6, tcp_dst="80")
			actions = [parser.OFPActionSetField(ipv4_dst=parser.OFPActionOutput(3)]
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
			self.add_flow(datapath, 0, match, actions, inst)
			
			# Flow from server to two hosts. (10.0.0.1-2)
			match = parser.OFPMatch(eth_type = 0x0800, ipv4_dst = "10.0.0.1")
			actions = [parser.OFPActionOutput(1)]
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
			self.add_flow(datapath, 0, match, actions, inst)

			match = parser.OFPMatch(eth_type = 0x0800, ipv4_dst = "10.0.0.2")
			actions = [parser.OFPActionOutput(2)]
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
			self.add_flow(datapath, 0, match, actions, inst)
			print "Flow entry added."

	def add_flow(self, datapath, priority, match, actions, inst, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
		datapath.send_msg(mod)

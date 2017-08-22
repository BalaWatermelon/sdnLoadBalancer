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
import packetparser
import arper
class LBSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	

	def __init__(self, *args, **kwargs):
		super(LBSwitch, self).__init__(*args, **kwargs)
		self.pp = packetparser.packetParser()
		self.WAN_PORTS = [1,2]
		self.LAN_PORTS = [3,4,5]
		self.arper = arper.arper('9e:ac:1c:7e:e1:43')

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg
		in_port = msg.match['in_port']
		datapath = ev.msg.datapath

		print('incomming packet',in_port)
	    # Return list of protocol object in the packet
		if in_port in self.WAN_PORTS+self.LAN_PORTS:
			protocol_list = self.pp.parse(ev)
	    # Take action base on WANPORT and LANPORT
		if in_port in self.WAN_PORTS:
			self.handleWAN(protocol_list, in_port, datapath)

		elif in_port in self.LAN_PORTS:
			self.handleLAN(protocol_list)

	    # Drop all packet from undefined ports.

	def handleWAN(self,protocols, in_port, datapath):
		# Direct every arp to the only switch
		for packet in [packet for packet in protocols if packet.protocol_name=='arp']:
			arp_reply = self.arper.create_reply_packet(packet)
			self._send_packet_to_port(datapath,in_port,arp_reply.data)

		print('WAN traffic',protocols)

	def handleLAN(self,protocols):
		# Direct every arp to the only switch
		for packet in [packet for packet in protocols if packet.protocol_name=='arp']:
			arp_reply = self.arper.create_reply_packet(packet)
			self._send_packet_to_port(datapath,in_port,arp_reply.data)

	    print('LAN traffic')
	    
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
		
		# table-miss default: Controller
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
						  ofproto.OFPCML_NO_BUFFER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		self.add_flow(datapath, 0, match, actions, inst)
		'''
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
		'''
	def add_flow(self, datapath, priority, match, actions, inst, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
		datapath.send_msg(mod)

	def _send_packet_to_port(self, dp, port, data):
		if data is None:
			# Do NOT sent when data is None
			return
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		actions = [parser.OFPActionOutput(port=port)]
		# self.logger.info("packet-out %s" % (data,))
		out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
		dp.send_msg(out)
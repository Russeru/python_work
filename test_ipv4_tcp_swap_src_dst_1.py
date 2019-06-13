#! /usr/bin/env python3
#
# (C) LookingGlass Cyber Solutions Inc. 2017
#
# Author: rwalker@lookingglasscyber.com
#

import os
import sys
import unittest
import configparser
from ctypes import *
from multiprocessing import Process, Queue, current_process, Manager, Value
from scapy.all import *
from unitTestDefs import *
import adp_test_framework
from lg_def_chassis.dujson import json_utils, dusocket


class TestIpv4TcpSwapSrcDst1(unittest.TestCase):
    # These are initialized during test setup from environment parameters.
    TEST_CONFIG_INI = os.environ.get('TEST_CONFIG_INI')

    # The config that was prepared before this test was launched.
    config = configparser.ConfigParser()
    config.read(TEST_CONFIG_INI)
    log_dir = config.get('general', 'log_dir')

    # Get current date/time stamp string.
    dtstr = adp_test_framework.generate_host_specific_info.get_time_date_stamp()
    test_run_name = config.get('general', 'project_name') + '__test_run__' + dtstr

    test_run_dir = os.path.join(log_dir, test_run_name)
    if not os.path.isdir(test_run_dir):
        os.makedirs(test_run_dir)

    print('Test run output directory created : ' + test_run_dir)

    if not config.getboolean('general', 'skip_packet_sending_tests'):
        # An instance of the AdpTestFramework.
        ATF = adp_test_framework.AdpTestFramework(left_iface=config.get('left_side', 'iface'),
                                                  right_iface=config.get('right_side', 'iface'),
                                                  output_dir=test_run_dir,
                                                  test_run_name=test_run_name)

    L2_src_mac = config.get('left_side', 'eth_adr')
    L2_dst_mac = config.get('right_side', 'eth_adr')
    L2_type = 'IPv4'
    L2 = Ether(src=L2_src_mac,
               dst=L2_dst_mac,
               type=L2_type)

    L3_IPv4_frag_size = 500
    L3_IPv4_version = 4
    L3_IPv4_ihl = 5
    L3_IPv4_tos = 0
    L3_IPv4_id = 2
    L3_IPv4_flags = 0
    L3_IPv4_frag = 0
    L3_IPv4_ttl = 64
    L3_IPv4_proto = 'tcp'
    L3_IPv4_chksum = 0x6294
    L3_IPv4_src = config.get('left_side', 'ipv4_adr')
    L3_IPv4_dst = config.get('right_side', 'ipv4_adr')
    L3_IPv4_options = None
    L3_IPv4_options_len = 0
    L3_IPv4_hdr_len = 20 + L3_IPv4_options_len
    L3_IPv4_len = L3_IPv4_hdr_len
    L3 = IP(
        version=L3_IPv4_version,
        ihl=L3_IPv4_ihl,
        tos=L3_IPv4_tos,
        len=L3_IPv4_len,
        id=L3_IPv4_id,
        flags=L3_IPv4_flags,
        frag=L3_IPv4_frag,
        # ttl=(L3_IPv4_ttl, 1),
        ttl=L3_IPv4_ttl,
        proto=L3_IPv4_proto,
        chksum=L3_IPv4_chksum,
        src=L3_IPv4_src,
        dst=L3_IPv4_dst  # ,
        # options=L3_IPv4_options
    )

    L4_TCP_sport = 61895
    L4_TCP_dport = 22
    L4_TCP_seq = 1
    L4_TCP_ack = 0
    L4_TCP_reserved = 0
    L4_TCP_flags = 'PA'
    L4_TCP_window = 1444
    L4_TCP_chksum = 0x1058
    L4_TCP_urgptr = 0
    L4_TCP_opt_MSS = 1460
    L4_TCP_opt_SAckOK = b''
    L4_TCP_opt_Timestamp = (4340667, 0)
    L4_TCP_opt_NOP = 0
    L4_TCP_opt_WScale = 7
    L4_TCP_options_len = 20  # 20 bytes of options
    L4_TCP_hdr_len = 20
    L4_TCP_hdr_and_opt_len = L4_TCP_hdr_len + L4_TCP_options_len
    L4_TCP_dataofs = L4_TCP_hdr_and_opt_len / 4
    L4_TCP_options = [('MSS', L4_TCP_opt_MSS),  # 4  bytes
                      ('SAckOK', L4_TCP_opt_SAckOK),  # 2  bytes
                      ('Timestamp', L4_TCP_opt_Timestamp),  # 10 bytes
                      ('NOP', L4_TCP_opt_NOP),  # 1  byte
                      ('WScale', L4_TCP_opt_WScale)]  # 3  bytes
    L4_TCP_payload = 'A' * 496 + 'B' * 500
    L4 = TCP(
        sport=L4_TCP_sport,
        dport=L4_TCP_dport,
        seq=L4_TCP_seq,
        ack=L4_TCP_ack,
        dataofs=L4_TCP_dataofs,
        reserved=L4_TCP_reserved,
        flags=L4_TCP_flags,
        window=L4_TCP_window,
        chksum=L4_TCP_chksum,
        urgptr=L4_TCP_urgptr,
        options=L4_TCP_options
    )

    def setUp(self):
        # Use init_test() for individual test initialization (must be called at the start of each unit test).
        pass

    def tearDown(self):
        if not self.config.getboolean('general', 'skip_packet_sending_tests'):
            self.ATF.tear_down()

    @unittest.skipIf(True, 'Need to refactor test to work with new unit test libs.')
    @unittest.skipIf(config.getboolean('general', 'skip_packet_sending_tests'), 'Skipping packet passing tests.')
    def test_ipv4_swap_src_dst_1(self):
        # Init the test harness with the name of this function.
        self.ATF.init_test(sys._getframe().f_code.co_name)

        # Update TCP header length (add in the length of the TCP options).
        self.L4.dataofs = int((self.L4_TCP_hdr_len + self.L4_TCP_options_len) / 4)

        # Set IP total length with the TCP header length and the payload length.
        self.L3.len = self.L3_IPv4_hdr_len + (self.L4.dataofs * 4) + len(self.L4_TCP_payload)

        # Assemble the packet layers.
        pkt = self.L2 / self.L3 / self.L4 / self.L4_TCP_payload

        # Send packet as a single packet (not fragmented).
        self.ATF.send(pkt, self.ATF.rx_if_left)

        # FIXME: Packets are not getting captured anymore even though they are actually being sent.  - bcampbell
        # Get the packets captured from the left and right sides.
        pkt_list_left_side, pkt_list_right_side = self.ATF.get_packet_lists(pkts_expected_left_side=True,
                                                                            pkts_expected_right_side=False)

        # Should get two packets on the left side since after src and dest are swapped
        # it should come back out the way it came in.
        self.assertEqual(len(pkt_list_left_side), 2)
        self.assertEqual(len(pkt_list_right_side), 0)

        # Make sure that src and dst addresses on second packet were swapped
        self.assertEqual(pkt_list_left_side[1][Ether].src, self.L2_dst_mac)
        self.assertEqual(pkt_list_left_side[1][Ether].dst, self.L2_src_mac)
        self.assertEqual(pkt_list_left_side[1][IP].src, self.L3_IPv4_dst)
        self.assertEqual(pkt_list_left_side[1][IP].dst, self.L3_IPv4_src)


if __name__ == '__main__':
    unittest.main()

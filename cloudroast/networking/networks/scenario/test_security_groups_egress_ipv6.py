"""
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re
import time

from cafe.drivers.unittest.decorators import tags
from cloudcafe.networking.networks.personas import ServerPersona
from cloudroast.networking.networks.fixtures import NetworkingComputeFixture


# For remote clients set up
SSH_USERNAME = 'root'
AUTH_STRATEGY = 'key'

# For TCP testing
TCP_PORT1 = '993'
TCP_PORT2 = '994'
TCP_PORT_RANGE = '992-995'

# UDP ports for sending a file: port 750 within UDP egress rule, 749 not
UDP_PORT_750 = '750'
UDP_PORT_749 = '749'

# Operation now in progress if a reply from a port outside the rule
TCP_RULE_EXPECTED_DATA = ['992 (tcp) timed out: Operation now in progress',
                          '993 port [tcp/*] succeeded!',
                          '994 port [tcp/*] succeeded!',
                          '995 (tcp) failed: Connection refused']

TCP_EXPECTED_DATA = ['992 (tcp) failed: Connection refused',
                     '993 port [tcp/*] succeeded!',
                     '994 port [tcp/*] succeeded!',
                     '995 (tcp) failed: Connection refused']


class SecurityGroupsEgressIPv6Test(NetworkingComputeFixture):
    @classmethod
    def setUpClass(cls):
        super(SecurityGroupsEgressIPv6Test, cls).setUpClass()
        """
        
        cls.fixture_log.debug('Creating the isolated network with IPv6 subnet')
        net_req = cls.networks.behaviors.create_network(name='sg_egress_net6')
        network = net_req.response.entity
        sub6_req = cls.subnets.behaviors.create_subnet(network_id=network.id,
                                                       ip_version=6)
        subnet6 = sub6_req.response.entity
     
        cls.fixture_log.debug('Creating test server keypair')
        cls.keypair = cls.create_keypair(name='sg_test_key6')
        cls.delete_keypairs.append(cls.keypair.name)
     
        cls.fixture_log.debug('Creating the test servers')
        cls.network_ids = [cls.public_network_id, cls.service_network_id,
                           network.id]

        cls.listener = cls.create_test_server(name='sg_egress_listenerv6',
                                              key_name=cls.keypair.name,
                                              network_ids=cls.network_ids,
                                              active_server=False)
        
        # Used for sending TCP and UDP packets with egress rules
        cls.sender = cls.create_test_server(name='sg_egress_senderv6',
                                            key_name=cls.keypair.name,
                                            network_ids=cls.network_ids,
                                            active_server=False)
        
        # Used for sending ICMP packets with egress rules
        cls.icmp_sender = cls.create_test_server(name='sg_egress_icmp_senderv6',
                                                 key_name=cls.keypair.name,
                                                 network_ids=cls.network_ids,
                                                 active_server=False)

        # Used for sending TCP, UDP and ICMP packets without any rules
        cls.other_sender = cls.create_test_server(name='sg_egress_otherv6',
                                                  key_name=cls.keypair.name,
                                                  network_ids=cls.network_ids,
                                                  active_server=False)

        # Waiting for the servers to be active
        server_ids = [cls.listener.id, cls.sender.id, cls.icmp_sender.id,
                      cls.other_sender.id]
        
        print cls.keypair
        print network
        print subnet6
        print server_ids
        print cls.listener.admin_pass
        print cls.sender.admin_pass
        print cls.icmp_sender.admin_pass
        print cls.other_sender.admin_pass
        
        cls.net.behaviors.wait_for_servers_to_be_active(
            server_id_list=server_ids)        
        print 'active!!'

        cls.delete_servers = []
        cls.delete_keypairs = []
        """
        
        #############for development w static servers#########
        #"""
        network = cls.networks.behaviors.get_network(
            'b0655b95-d4d4-4dec-b882-844a3f2be917').response.entity
        subnet6 = cls.subnets.behaviors.get_subnet(
            'fc7eb91f-487b-4230-885e-4c6210f848a2').response.entity
        cls.keypair = cls.keypairs.client.get_keypair(
            'sg_test_key668ebec53').entity
        cls.keypair.private_key = (u"""-----BEGIN RSA PRIVATE KEY-----
MIIEqgIBAAKCAQEAsYptdcb6JSOW6fg19M3BJNfTQ999K/OvouNmdtftPwnVBRBj
BLa0TAU9TLyFVM0SgWm0Q/mTPl+9IcDGEmlu07p77aOtQF+dtZRkx1iZQk1hE9x3
1VnKluI819mtZ5/El2JjXkOHjqip9xq+HWUd3DhTgRsdXyBHskUA4L8RDf8OsbdH
VYCkoWp+FRoEA1vaGsZu3pY3WzttHhiW+1tVvNQCp2oJ8ZvLrNd5y+TABIPIr1Lf
8QMEN6/pExKW6OFa/9E8laHFETc1dA9pGJxGGRda7uupoP1mUGG8vAm52DMjVOoo
o69sOHqg9x0X2JSBtDguEvXsqpBqQN4/YrT/7QIDAQABAoIBAQCYy+0mxwez/Ow+
EuvE82u93K2rJWXh9Mj9JD6kG3PIpBqcUB0YCnIjVwMJztnlQNUjYajOM7ZAoT7y
FKmjYPAL8twDirFpzKC7jKorUpocEOJyqHTNvoh30N/SWTo/C6azLu8cSnwZEBmv
XGmwfLz1MdjULVTa8Lojt/Vod6gi5SYqtZmVPg/TUJ37pawvpg+1ykIoJjkKmVPN
MHaC5f8TJIPXtt34A6aIcvPVpsfvfwa9w6anvHsu6ySC9JJ2rDuZSVH/IWEY/Ayg
tkmvp6jqCjBvOn/airiA1MiLr7mEc6V/1kH/hsXvzGdsDPdv8IeidQZQ/wWndNsN
7xsGrIyVAoIAgQC+oR2zv78Gzf0wmMDJkbWqn97VWrWVatNOewQ9gckZg+sLlZ18
9928AlW5SEYZuI/INvUNvdS332R9YkRCDaPEJ0jqGT54wfF3A46wQ/XGMV1D/QhM
OGK8el4NQtQcaMTDvn7u0BQXMQWUbXhKQYsbnZ3YmNZNpCqC/le5WTY5AwKCAIEA
7mxLCU/sqpiktehtXO68hg2dqv8ij9NgBnYSZ1t6FtFVLIRZhrQZ8QUUiyGHmDPb
ZD4F/nufm98QDTmRVBxmhexGySLhuEaysuAym6fejirXVv55dPptc9vF1X9DTrkj
1DRVKxFH0kBGx6DJAIdrQaothu+V0kGj57XM4jrAeE8CggCBAKRmAF6PI6gzp4Hs
in6LaddvLlZjdywXx4nsL1j3/71Adkk0S3CFtrU4ckNq4AG4mE87jhS+vJ+iSWCU
iXdJmg1FL+2rvaOY5qwT5k9/HItC8UL8Cdbp3cTb5xaapqClfeOt+nvr+ReTEFPU
IKQxaE11nbY5AMBOrtbvkCnplQiPAoIAgQCIXdAdJ2WJvXyXvrSubq3NToRbhUnT
UWaey3GDREL0Qg6hQ6Gg9enQfMNfQHI5j49wKjlrcHG9yTt5FPAWV5gcCSQDbrwD
lgwnWywW81DLp5062JnHWmS323+vuPZaVHI1sSj1VRDrJHBXRZMxhkLGb/tSLj5W
38xLfyQMUOY86QKCAIB1oNw9twkNVf+KmvNHEPEEjgpBhYMOxAQBJQmJqbVwKKnN
wrOSmATnn9DKxMYtvBIKCbDhssgeTaGKySG8FNdRQeq510dNwM/7olSL10X83ZWX
9LiJ/1SRuDssNKLPAO0Oan4mOMMyCAKGAb+VBl24krULZAlm7f+4mr9GyOUFlA==
-----END RSA PRIVATE KEY-----""")
        
        server_ids = [u'5bfefa61-4947-46c9-9f0b-90c48d277c70',
                      u'437af3e1-024a-4d30-bb8d-eada1e8709ca',
                      u'cccb0707-9552-43c5-90e6-201a91eb9598',
                      u'a1e6e0e4-2e93-4dd1-8bec-ab103a325844']
        cls.listener = cls.net.behaviors.get_networking_server(
            server_id=server_ids[0])
        cls.listener.admin_pass = 'GtTAbUXwUn3M'
        cls.sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[1])
        cls.sender.admin_pass = '3hU2WtCm8RDf'
        cls.icmp_sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[2])
        cls.icmp_sender.admin_pass = 'Pd2jWyXyiFCw'
        cls.other_sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[3])
        cls.other_sender.admin_pass = 'a9P7wq4pudSk'
        #"""
        ########################################################
        """
        cls.fixture_log.debug('Creating the security groups and rules')
        
        # Creating the security group and rules for IPv6 TCP testing
        sg_tcp_ipv6_req = cls.sec.behaviors.create_security_group(
            name='sg_tcp_ipv6_egress',
            description='SG for testing IPv6 TCP egress rules')
        cls.sec_group_tcp_ipv6 = sg_tcp_ipv6_req.response.entity
        cls.delete_secgroups.append(cls.sec_group_tcp_ipv6.id)

        egress_tcp_ipv6_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=cls.sec_group_tcp_ipv6.id, direction='egress',
            ethertype='IPv6', protocol='tcp', port_range_min=993,
            port_range_max=995)
        egress_tcp_rule = egress_tcp_ipv6_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_tcp_rule.id)

        # Creating the security group rule for IPv6 UDP testing
        egress_udp_ipv6_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=cls.sec_group_tcp_ipv6.id, direction='egress',
            ethertype='IPv6', protocol='udp', port_range_min=750,
            port_range_max=752)
        egress_udp_rule = egress_udp_ipv6_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_udp_rule.id)

        cls.create_ping_ssh_ingress_rules(
            sec_group_id=cls.sec_group_tcp_ipv6.id)

        # Creating the security group and rules for IPv6 ICMP testing
        sg_icmp_ipv6_req = cls.sec.behaviors.create_security_group(
            name='sg_icmp_ipv6_egress',
            description='SG for testing IPv6 ICMP egress rules')
        cls.sec_group_icmp_ipv6 = sg_icmp_ipv6_req.response.entity
        cls.delete_secgroups.append(cls.sec_group_icmp_ipv6.id)

        egress_icmp_ipv6_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=cls.sec_group_icmp_ipv6.id, direction='egress',
            ethertype='IPv6', protocol='icmp')
        egress_icmp_ipv6_rule = egress_icmp_ipv6_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_icmp_ipv6_rule.id)

        # ICMP ingress rules are also required to see the reply
        egress_icmp_ipv6_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=cls.sec_group_icmp_ipv6.id, direction='ingress',
            ethertype='IPv6', protocol='icmp')
        egress_icmp_ipv6_rule = egress_icmp_ipv6_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_icmp_ipv6_rule.id)

        cls.create_ping_ssh_ingress_rules(
            sec_group_id=cls.sec_group_icmp_ipv6.id)
        
        cls.delete_secgroups = []
        cls.delete_secgroups_rules = []  
      
        cls.security_group_ids = [cls.sec_group_tcp_ipv6.id,
                                  cls.sec_group_icmp_ipv6.id]        
        """
        #############for development w static SGs#########
        #"""
        cls.security_group_ids = [u'fccf67da-4f3f-474a-9431-68ff01b81436',
                                  u'fb4864c7-e371-43bf-ad3a-804741478e67']
        #"""
        cls.sec_group_tcp_ipv6 = cls.sec.behaviors.get_security_group(
            cls.security_group_ids[0]).response.entity
        cls.sec_group_icmp_ipv6 = cls.sec.behaviors.get_security_group(
            cls.security_group_ids[1]).response.entity

        print cls.security_group_ids
        print cls.sec_group_tcp_ipv6
        print cls.sec_group_icmp_ipv6

        ####################################################

        cls.fixture_log.debug('Defining the server personas for quick port '
                              'and IP address access')
        cls.lp = ServerPersona(server=cls.listener, inet=True, network=network,
                               inet_port_count=1, inet_fix_ipv6_count=1)
        cls.op = ServerPersona(server=cls.other_sender, inet=True,
                               network=network, inet_port_count=1,
                               inet_fix_ipv6_count=1)
        cls.sp = ServerPersona(server=cls.sender, inet=True, network=network,
                               inet_port_count=1, inet_fix_ipv6_count=1)        
        cls.spi = ServerPersona(server=cls.icmp_sender, inet=True,
                                network=network, inet_port_count=1,
                                inet_fix_ipv6_count=1) 
                   
        """
        cls.fixture_log.debug('Updating the TCP and ICMP sender servers ports '
                              'with security groups')
        sp_pnet_req = cls.ports.behaviors.update_port(
            port_id=cls.sp.pnet_port_ids[0],
            security_groups=[cls.security_group_ids[0]],
            raise_exception=True)
        sp_snet_req = cls.ports.behaviors.update_port(
            port_id=cls.sp.snet_port_ids[0],
            security_groups=[cls.security_group_ids[0]],
            raise_exception=True)
        sp_inet_req = cls.ports.behaviors.update_port(
            port_id=cls.sp.inet_port_ids[0],
            security_groups=[cls.security_group_ids[0]],
            raise_exception=True)

        spi_pnet_req = cls.ports.behaviors.update_port(
            port_id=cls.spi.pnet_port_ids[0],
            security_groups=[cls.security_group_ids[1]],
            raise_exception=True)
        spi_snet_req = cls.ports.behaviors.update_port(
            port_id=cls.spi.snet_port_ids[0],
            security_groups=[cls.security_group_ids[1]],
            raise_exception=True)
        spi_inet_req = cls.ports.behaviors.update_port(
            port_id=cls.spi.inet_port_ids[0],
            security_groups=[cls.security_group_ids[1]],
            raise_exception=True)

        print cls.sp.pnet_ports
        print cls.sp.snet_ports
        print cls.sp.inet_ports
        print cls.spi.pnet_ports
        print cls.spi.snet_ports
        print cls.spi.inet_ports    

        """

        print 'data plane delay {0}'.format(cls.sec.config.data_plane_delay)
        #time.sleep(cls.sec.config.data_plane_delay)
   

    def setUp(self):        
        """ Creating the remote clients """

        self.fixture_log.debug('Creating the Remote Clients')
        self.lp_rc = self.servers.behaviors.get_remote_instance_client(
            server=self.listener, ip_address=self.lp.pnet_fix_ipv4[0],
            username=SSH_USERNAME, key=self.keypair.private_key,
            auth_strategy=AUTH_STRATEGY)
        self.op_rc = self.servers.behaviors.get_remote_instance_client(
            server=self.other_sender, ip_address=self.op.pnet_fix_ipv4[0],
            username=SSH_USERNAME, key=self.keypair.private_key,
            auth_strategy=AUTH_STRATEGY)
        
        self.fixture_log.debug('Sender Remote Clients require ingress and '
                              'egress rules working for ICMP and ingress '
                              'rules for TCP')
        self.sp_rc = self.servers.behaviors.get_remote_instance_client(
            server=self.sender, ip_address=self.sp.pnet_fix_ipv4[0],
            username=SSH_USERNAME, key=self.keypair.private_key,
            auth_strategy=AUTH_STRATEGY)
        self.spi_rc = self.servers.behaviors.get_remote_instance_client(
            server=self.icmp_sender, ip_address=self.spi.pnet_fix_ipv4[0],
            username=SSH_USERNAME, key=self.keypair.private_key,
            auth_strategy=AUTH_STRATEGY)
        
        print self.lp_rc.can_authenticate()   
        print self.op_rc.can_authenticate()
        print self.sp_rc.can_authenticate()
        print self.spi_rc.can_authenticate()

    def test_remote_client_connectivity(self):
        """
        @summary: Testing the remote clients
        """
        self.verify_remote_client_auth(server=self.listener,
                                       remote_client=self.lp_rc)
        self.verify_remote_client_auth(server=self.other_sender,
                                       remote_client=self.op_rc)
        self.verify_remote_client_auth(server=self.sender,
                                       remote_client=self.sp_rc,
                                       sec_group=self.sec_group_tcp_ipv6) 
        self.verify_remote_client_auth(server=self.icmp_sender,
                                       remote_client=self.spi_rc,
                                       sec_group=self.sec_group_icmp_ipv6)        

    @tags('dev5')
    def test_publicnet_ping(self):
        """
        @summary: Testing ping from other sender without security rules
        """
        ip_address = self.lp.pnet_fix_ipv6[0]
        print ip_address
        self.verify_ping(remote_client=self.op_rc, ip_address=ip_address,
                         ip_version=6)
    
    @tags('dev5')
    def test_isolatednet_ping(self):
        """
        @summary: Testing ping from other sender without security rules
        """
        ip_address = self.lp.inet_fix_ipv6[0]
        self.verify_ping(remote_client=self.op_rc, ip_address=ip_address,
                         ip_version=6)
    
    @tags('dev5')
    def test_publicnet_ping_w_icmp_egress(self):
        """
        @summary: Testing ICMP egress rule on publicnet
        """
        ip_address = self.lp.pnet_fix_ipv6[0]
        self.verify_ping(remote_client=self.spi_rc, ip_address=ip_address,
                         ip_version=6)

    @tags('dev5')
    def test_isolatednet_ping_w_icmp_egress(self):
        """
        @summary: Testing ICMP egress rule on isolatednet
        """
        ip_address = self.lp.inet_fix_ipv6[0]
        self.verify_ping(remote_client=self.spi_rc, ip_address=ip_address,
                         ip_version=6)

    @tags('dev7')
    def test_publicnet_ports_w_tcp(self):
        """
        @summary: Testing TCP ports on publicnet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.op_rc,
                                     listener_ip=self.lp.pnet_fix_ipv6[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_EXPECTED_DATA,
                                     ip_version=6)       

    @tags('dev7')
    def test_isolatednet_ports_w_tcp(self):
        """
        @summary: Testing TCP ports on isolatednet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.op_rc,
                                     listener_ip=self.lp.inet_fix_ipv6[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_EXPECTED_DATA,
                                     ip_version=6)

    @tags('dev8')
    def test_publicnet_ports_w_tcp_egress(self):
        """
        @summary: Testing TCP egress rule on publicnet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.sp_rc,
                                     listener_ip=self.lp.pnet_fix_ipv6[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_RULE_EXPECTED_DATA,
                                     ip_version=6)       

    @tags('dev8')
    def test_isolatednet_ports_w_tcp_egress(self):
        """
        @summary: Testing TCP egress rule on isolatednet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.sp_rc,
                                     listener_ip=self.lp.inet_fix_ipv6[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_RULE_EXPECTED_DATA,
                                     ip_version=6)

    @tags('dev9')
    def test_isolatednet_udp_port_750(self):
        """
        @summary: Testing UDP from other sender without security rules
                  over isolatednet on port 750
        """
        
        file_content = 'Security Groups UDP 750 testing from other sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        # UDP rule NOT applied to sender so the port is not limited here
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.op_rc,
            listener_ip=self.lp.inet_fix_ipv6[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data,
            ip_version=6)

    @tags('dev9')
    def test_isolatednet_udp_port_749(self):
        """
        @summary: Testing UDP from other sender without security rules
                  over isolatednet on port 749
        """

        file_content = 'Security Groups UDP 749 testing from other sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        # Other sender server has no rules applied, both ports should work
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.op_rc,
            listener_ip=self.lp.inet_fix_ipv6[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data,
            ip_version=6)

    @tags('dev10')
    def test_isolatednet_udp_port_750_w_udp_egress(self):
        """
        @summary: Testing UDP from sender with security egress rules on
                  port 750 that is part of the egress rule
        """
        
        file_content = 'Security Groups UDP 750 testing from sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.sp_rc,
            listener_ip=self.lp.inet_fix_ipv6[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data,
            ip_version=6)

    @tags('dev10')
    def test_isolatednet_udp_port_749_w_udp_egress(self):
        """
        @summary: Testing UDP from sender with security egress rules on
                  port 749 that is NOT part of the egress rule
        """

        file_content = 'Security Groups UDP 749 testing from other sender'
        expected_data = ''

        # Port 749 NOT within rule, data should not be transmitted
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.sp_rc,
            listener_ip=self.lp.inet_fix_ipv6[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data,
            ip_version=6)

    @tags('dev11')
    def test_publicnet_udp_port_750(self):
        """
        @summary: Testing UDP from other sender without security rules
                  over publicnet on port 750
        """
        
        file_content = 'Security Groups UDP 750 testing from other sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        # UDP rule NOT applied to sender so the port is not limited here
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.op_rc,
            listener_ip=self.lp.pnet_fix_ipv6[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data,
            ip_version=6)

    @tags('dev11')
    def test_publicnet_udp_port_749(self):
        """
        @summary: Testing UDP from other sender without security rules
                  over publicnet on port 749
        """

        file_content = 'Security Groups UDP 749 testing from other sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        # Other sender server has no rules applied, both ports should work
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.op_rc,
            listener_ip=self.lp.pnet_fix_ipv6[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data,
            ip_version=6)

    @tags('dev11')
    def test_publicnet_udp_port_750_w_udp_egress(self):
        """
        @summary: Testing UDP from sender with security egress rules on
                  port 750 that is part of the egress rule
        """
        
        file_content = 'Security Groups UDP 750 testing from sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.sp_rc,
            listener_ip=self.lp.pnet_fix_ipv6[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data,
            ip_version=6)

    @tags('dev11')
    def test_publicnet_udp_port_749_w_udp_egress(self):
        """
        @summary: Testing UDP from sender with security egress rules on
                  port 749 that is NOT part of the egress rule
        """

        file_content = 'Security Groups UDP 749 testing from other sender'
        expected_data = ''

        # Port 749 NOT within rule, data should not be transmitted
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.sp_rc,
            listener_ip=self.lp.pnet_fix_ipv6[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data,
            ip_version=6)

    @tags('dev5')
    def test_sgigs(self):
        print 'testin....'
    
    def test_tcp_w_ports(self):
        # Create TCP port rule with port range min and max
        # Update sender port with rule
        # Check communication between sender-listener
        # Check communication between other-listener
        pass
    
    def test_tcp_w_remote_ip_prefix(self):
        # Create TCP port rule with remopte_ip_prefix (listener IP prefix)
        # Update sender port with rule
        # Check communication between sender-listener (ports/ping)
        # Check communication between other-listener
        pass
    
    def test_icmp(self):
        # Create ICMP rule
        # Update icmp sender with rule
        # Check communication between sender-listener (ping)
        # Check communication between other-listener        
        pass
        
        

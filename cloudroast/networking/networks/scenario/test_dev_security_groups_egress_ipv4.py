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

# TCP ports to open on listener
TCP_PORT1 = '443'
TCP_PORT2 = '444'

# TCP port range to check from sender (SG rule port range 443-445)
TCP_PORT_RANGE = '442-445'

# UDP ports for sending a file: port 750 within UDP egress rule, 749 not
UDP_PORT_750 = '750'
UDP_PORT_749 = '749'



# Operation now in progress if a reply from a port outside the rule
TCP_RULE_EXPECTED_DATA = ['442 (tcp) timed out: Operation now in progress',
                          '443 port [tcp/*] succeeded!',
                          '444 port [tcp/*] succeeded!',
                          '445 (tcp) failed: Connection refused']

TCP_EXPECTED_DATA = ['442 (tcp) failed: Connection refused',
                     '443 port [tcp/*] succeeded!',
                     '444 port [tcp/*] succeeded!',
                     '445 (tcp) failed: Connection refused']


class SecurityGroupsEgressIPv4Test(NetworkingComputeFixture):
    @classmethod
    def setUpClass(cls):
        super(SecurityGroupsEgressIPv4Test, cls).setUpClass()
        """
        
        cls.fixture_log.debug('Creating the isolated network with IPv4 subnet')
        net_req = cls.networks.behaviors.create_network(name='sg_egress_net')
        network = net_req.response.entity
        sub4_req = cls.subnets.behaviors.create_subnet(network_id=network.id,
                                                       ip_version=4)
        subnet4 = sub4_req.response.entity
     
        cls.fixture_log.debug('Creating test server keypair')
        cls.keypair = cls.create_keypair(name='sg_test_key')
        cls.delete_keypairs.append(cls.keypair.name)
     
        cls.fixture_log.debug('Creating the test servers')
        cls.network_ids = [cls.public_network_id, cls.service_network_id,
                           network.id]

        cls.listener = cls.create_test_server(name='sg_egress_listenerv4',
                                              key_name=cls.keypair.name,
                                              network_ids=cls.network_ids,
                                              active_server=False)
        
        # Used for sending TCP and UDP packets with egress rules
        cls.sender = cls.create_test_server(name='sg_egress_senderv4',
                                            key_name=cls.keypair.name,
                                            network_ids=cls.network_ids,
                                            active_server=False)
        
        # Used for sending ICMP packets with egress rules
        cls.icmp_sender = cls.create_test_server(name='sg_egress_icmp_senderv4',
                                                 key_name=cls.keypair.name,
                                                 network_ids=cls.network_ids,
                                                 active_server=False)

        # Used for sending TCP, UDP and ICMP packets without any rules
        cls.other_sender = cls.create_test_server(name='sg_egress_otherv4',
                                                  key_name=cls.keypair.name,
                                                  network_ids=cls.network_ids,
                                                  active_server=False)

        # Waiting for the servers to be active
        server_ids = [cls.listener.id, cls.sender.id, cls.icmp_sender.id,
                      cls.other_sender.id]
        
        print cls.keypair
        print network
        print subnet4
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
            '46e1bbfe-7040-43fa-b8d5-838af505af10').response.entity
        subnet4 = cls.subnets.behaviors.get_subnet(
            '209b9f37-e248-4aaa-ab20-fdcd4078e655').response.entity
        cls.keypair = cls.keypairs.client.get_keypair(
            'sg_test_keyc210945a').entity
        cls.keypair.private_key = (u"""-----BEGIN RSA PRIVATE KEY-----
MIIEqQIBAAKCAQEAxSLPgGyI5nKr0ab1PfTGcvVp2Dm5zJszHB44WINqFXj7QoeW
c2B2ZpRX5++jKBMUIDIkqcwk19wHj6tlDV8SJrN5qFQPLPwSofSQUEsxivKvjS9V
kx8wTogtY1xbbpCROnV/Yrz9FPrc4wc2uUYndTV5gsrsIDenrp2vq1Mcvv6w1G+u
yyce6AdLa9rEqaxkWA2cTYAhXo+rIehoDqo2lrgUm1TLeU8sPKsGErPGa7PsN6No
omFBx2twwoSJ0W9CNkWtHXH9u31VMYQOsZyVD+IFBAVUgtU7IHnhyeqqY9XpEX8B
rZfdahjWV6RTfZnGW8D3ukhnaZeFo2/KcfwjyQIDAQABAoIBACBsYEqUD1Qvyhi6
aB2fk8A2owkAPZHseNSIF+Ze/uS3OEQx/snNNMwcW/T20hP2R1ogRS10OR8Tvl6f
5wfy+g5JeJn58WEJuJrQmafLJkPfNIZ5IY8IEy7ncOeluhgOSQSfbKs1wD5iIFBq
0FJauoSpnemoLHwEC11J7Cm2isTS3yI7zvQNgnIwPCWlaMKU+3BMqcEXjVRcBveI
934gVRzK3STUNZSTNShkirJf50Wrwti0DuqkhSKFhQrPjppBMkZ6MU7TA+zMQAaf
asBGVfwC1XKkqlPp5QFaecCrYG6CYRguUDwZdjWaDrwehMdKFgYzl5A/PHXbPD2Z
+qwQIoECggCBANvEpguV7ziqagHV9ycSxUkmG/TSEGMfDp6wAmzPhlsi5PthQXBI
Rvh32RiQcLXIN9oHS/2rf0utR336e+/xWhU+yxp90oNvJiNplSPF7mS2in2Kechs
tuzjSI1aJMatVlY3js/xGlsbAlHH8IqVgupPrJb0DsIXFEyKo3YsEUORAoIAgQDl
oveQu9hvzqOGk/nV+M5PlKVkXu3qkUQ3qAajCZCB3WrKYnEole00d5GcZ6vt2uqE
/BgP6hhIWNMXInV8BrRuBoBZXLY8byddyuQ4qUwkp+MYq5VbSlbO+zQ/oNZScANf
BAmAdRTiKXY4y4WwTmgyCedalFTYqth7mbUSUZVQuQKCAIEApj34ORVfE2ddryvS
vNznHfFU/noU6VYp8gJEo1jMUo5v1nR4Ut5pyTSnpXxFtkzRav1QD4C2V2GpjfN3
40aYFTAd5Vk+cCwZFnqc1aW5MrgexN6GRwVtzn4TeNGythOTFr8KKeRBQp+IvqJX
JA37LRG+BaZyr4FT2p6ZDiBBovECggCBAMj+2rgpYymB8enyjaQ28cYAMr/mw1Ik
MlSQ0rZTwdOZjUZ14dwHVqcs3RvMNlWr3sflq94KJZT1glZmh/S2HamMMT2Gg8/j
7s4Or7HUpVwUQxct4D4WlGL4x2PGELH5b0n0S6jPUice6WaO5YZLKrJZrtG+sYEw
EOomwLG3DP2pAoIAgDA7GkNMcdNO96evsYVFQK7E6dsbeDXgCOLNmca3Wngj36/8
BO31OiFNvW8e2ZkazpV5mhRFOg1iBBZThGX+R6V1Mv48FZoTLTqnl9PoTVgoPeik
bICe2aVXky6coAGS4lBvG3vzCN7Wyan/1QRzjsx4FNrqBK8Uewq8Jz49WiZM
-----END RSA PRIVATE KEY-----""")
        
        server_ids = [u'6fa16841-ecf4-45b7-b7c1-3597f419f75b',
                      u'4c029222-901d-42ce-99fc-62e80be8cc4a',
                      u'76ccfe1e-c6cc-4c7c-ae05-51be9845908b',
                      u'5e27d1db-7d72-4eaa-ab40-ecacdbea9b72']
        cls.listener = cls.net.behaviors.get_networking_server(
            server_id=server_ids[0])
        cls.listener.admin_pass = 'fECzqh4KUaMm'
        cls.sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[1])
        cls.sender.admin_pass = 'oC5y6L7sCbVw'
        cls.icmp_sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[2])
        cls.icmp_sender.admin_pass = 'iVbrLS6GGEKu'
        cls.other_sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[3])
        cls.other_sender.admin_pass = 'rEbfD3fajBFC'
        #"""
        ########################################################
        """
        cls.fixture_log.debug('Creating the security groups and rules')
        
        # Creating the security group and rules for IPv4 TCP testing
        sg_tcp_ipv4_req = cls.sec.behaviors.create_security_group(
            name='sg_tcp_ipv4_egress',
            description='SG for testing IPv4 TCP egress rules')
        cls.sec_group_tcp_ipv4 = sg_tcp_ipv4_req.response.entity
        cls.delete_secgroups.append(cls.sec_group_tcp_ipv4.id)

        egress_tcp_ipv4_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=cls.sec_group_tcp_ipv4.id, direction='egress',
            ethertype='IPv4', protocol='tcp', port_range_min=443,
            port_range_max=445)
        egress_tcp_rule = egress_tcp_ipv4_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_tcp_rule.id)

        # Creating the security group rule for IPv4 UDP testing
        egress_udp_ipv4_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=cls.sec_group_tcp_ipv4.id, direction='egress',
            ethertype='IPv4', protocol='udp', port_range_min=750,
            port_range_max=752)
        egress_udp_rule = egress_udp_ipv4_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_udp_rule.id)

        # Adding rules for remote client connectivity
        cls.create_ping_ssh_ingress_rules(
            sec_group_id=cls.sec_group_tcp_ipv4.id)

        # Creating the security group and rules for IPv4 ICMP testing
        sg_icmp_ipv4_req = cls.sec.behaviors.create_security_group(
            name='sg_icmp_ipv4_egress',
            description='SG for testing IPv4 ICMP egress rules')
        cls.sec_group_icmp_ipv4 = sg_icmp_ipv4_req.response.entity
        cls.delete_secgroups.append(cls.sec_group_icmp_ipv4.id)

        egress_icmp_ipv4_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=cls.sec_group_icmp_ipv4.id, direction='egress',
            ethertype='IPv4', protocol='icmp')
        egress_icmp_ipv4_rule = egress_icmp_ipv4_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_icmp_ipv4_rule.id)

        # Adding rules for remote client connectivity
        cls.create_ping_ssh_ingress_rules(
            sec_group_id=cls.sec_group_icmp_ipv4.id)
        
        cls.delete_secgroups = []
        cls.delete_secgroups_rules = []  
      
        cls.security_group_ids = [cls.sec_group_tcp_ipv4.id,
                                  cls.sec_group_icmp_ipv4.id]        
        """
        #############for development w static SGs#########
        #"""
        cls.security_group_ids = [u'66e9aa52-027d-4e7b-9fb3-e6d24fce7a3c',
                                  u'7b6d821b-ac73-49cd-80ed-1e367c252099']
        #"""
        cls.sec_group_tcp_ipv4 = cls.sec.behaviors.get_security_group(
            cls.security_group_ids[0]).response.entity
        cls.sec_group_icmp_ipv4 = cls.sec.behaviors.get_security_group(
            cls.security_group_ids[1]).response.entity

        print cls.security_group_ids
        print cls.sec_group_tcp_ipv4
        print cls.sec_group_icmp_ipv4

        ####################################################

        cls.fixture_log.debug('Defining the server personas for quick port '
                              'and IP address access')
        cls.lp = ServerPersona(server=cls.listener, inet=True, network=network,
                               inet_port_count=1, inet_fix_ipv4_count=1)
        cls.op = ServerPersona(server=cls.other_sender, inet=True,
                               network=network, inet_port_count=1,
                               inet_fix_ipv4_count=1)
        cls.sp = ServerPersona(server=cls.sender, inet=True, network=network,
                               inet_port_count=1, inet_fix_ipv4_count=1)        
        cls.spi = ServerPersona(server=cls.icmp_sender, inet=True,
                                network=network, inet_port_count=1,
                                inet_fix_ipv4_count=1) 
        
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

        #print 'data plane delay {0}'.format(cls.sec.config.data_plane_delay)
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
                                       sec_group=self.sec_group_tcp_ipv4) 
        self.verify_remote_client_auth(server=self.icmp_sender,
                                       remote_client=self.spi_rc,
                                       sec_group=self.sec_group_icmp_ipv4)        

    def test_publicnet_ping(self):
        """
        @summary: Testing ping from other sender without security rules
        """
        ip_address = self.lp.pnet_fix_ipv4[0]
        self.verify_ping(remote_client=self.op_rc, ip_address=ip_address)        

    def test_servicenet_ping(self):
        """
        @summary: Testing ping from other sender without security rules
        """
        ip_address = self.lp.snet_fix_ipv4[0]
        self.verify_ping(remote_client=self.op_rc, ip_address=ip_address)

    def test_isolatednet_ping(self):
        """
        @summary: Testing ping from other sender without security rules
        """
        ip_address = self.lp.inet_fix_ipv4[0]
        self.verify_ping(remote_client=self.op_rc, ip_address=ip_address)

    def test_publicnet_ping_w_icmp_egress(self):
        """
        @summary: Testing ICMP egress rule on publicnet
        """
        ip_address = self.lp.pnet_fix_ipv4[0]
        self.verify_ping(remote_client=self.spi_rc, ip_address=ip_address)

    def test_servicenet_ping_w_icmp_egress(self):
        """
        @summary: Testing ICMP egress rule on servicenet
        """
        ip_address = self.lp.snet_fix_ipv4[0]
        self.verify_ping(remote_client=self.spi_rc, ip_address=ip_address)

    def test_isolatednet_ping_w_icmp_egress(self):
        """
        @summary: Testing ICMP egress rule on isolatednet
        """
        ip_address = self.lp.inet_fix_ipv4[0]
        self.verify_ping(remote_client=self.spi_rc, ip_address=ip_address)

    @tags('dev4')
    def test_publicnet_ports_w_tcp(self):
        """
        @summary: Testing TCP ports on publicnet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.op_rc,
                                     listener_ip=self.lp.pnet_fix_ipv4[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_EXPECTED_DATA)       

    @tags('dev4')
    def test_servicenet_ports_w_tcp(self):
        """
        @summary: Testing TCP ports on servicenet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.op_rc,
                                     listener_ip=self.lp.snet_fix_ipv4[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_EXPECTED_DATA)

    @tags('dev4')
    def test_isolatednet_ports_w_tcp(self):
        """
        @summary: Testing TCP ports on isolatednet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.op_rc,
                                     listener_ip=self.lp.inet_fix_ipv4[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_EXPECTED_DATA)

    @tags('dev4')
    def test_publicnet_ports_w_tcp_egress(self):
        """
        @summary: Testing TCP egress rule on publicnet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.sp_rc,
                                     listener_ip=self.lp.pnet_fix_ipv4[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_RULE_EXPECTED_DATA)       

    @tags('dev4')
    def test_servicenet_ports_w_tcp_egress(self):
        """
        @summary: Testing TCP egress rule on servicenet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.sp_rc,
                                     listener_ip=self.lp.snet_fix_ipv4[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_RULE_EXPECTED_DATA)

    @tags('dev4')
    def test_isolatednet_ports_w_tcp_egress(self):
        """
        @summary: Testing TCP egress rule on isolatednet
        """
        self.verify_tcp_connectivity(listener_client=self.lp_rc,
                                     sender_client=self.sp_rc,
                                     listener_ip=self.lp.inet_fix_ipv4[0],
                                     port1=TCP_PORT1, port2=TCP_PORT2,
                                     port_range=TCP_PORT_RANGE,
                                     expected_data=TCP_RULE_EXPECTED_DATA)
 
    @tags('dev99')
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
            listener_ip=self.lp.inet_fix_ipv4[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
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
            listener_ip=self.lp.inet_fix_ipv4[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
    def test_isolatednet_udp_port_750_w_udp_egress(self):
        """
        @summary: Testing UDP from sender with security egress rules on
                  port 750 that is part of the egress rule
        """
        
        file_content = 'Security Groups UDP 750 testing from sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.sp_rc,
            listener_ip=self.lp.inet_fix_ipv4[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
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
            listener_ip=self.lp.inet_fix_ipv4[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
    def test_servicenet_udp_port_750(self):
        """
        @summary: Testing UDP from other sender without security rules
                  over servicenet on port 750
        """
        
        file_content = 'Security Groups UDP 750 testing from other sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        # UDP rule NOT applied to sender so the port is not limited here
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.op_rc,
            listener_ip=self.lp.snet_fix_ipv4[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
    def test_servicenet_udp_port_749(self):
        """
        @summary: Testing UDP from other sender without security rules
                  over servicenet on port 749
        """

        file_content = 'Security Groups UDP 749 testing from other sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        # Other sender server has no rules applied, both ports should work
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.op_rc,
            listener_ip=self.lp.snet_fix_ipv4[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
    def test_servicenet_udp_port_750_w_udp_egress(self):
        """
        @summary: Testing UDP from sender with security egress rules on
                  port 750 that is part of the egress rule
        """
        
        file_content = 'Security Groups UDP 750 testing from sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.sp_rc,
            listener_ip=self.lp.snet_fix_ipv4[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
    def test_servicenet_udp_port_749_w_udp_egress(self):
        """
        @summary: Testing UDP from sender with security egress rules on
                  port 749 that is NOT part of the egress rule
        """

        file_content = 'Security Groups UDP 749 testing from other sender'
        expected_data = ''

        # Port 749 NOT within rule, data should not be transmitted
        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.sp_rc,
            listener_ip=self.lp.snet_fix_ipv4[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
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
            listener_ip=self.lp.pnet_fix_ipv4[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
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
            listener_ip=self.lp.pnet_fix_ipv4[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
    def test_publicnet_udp_port_750_w_udp_egress(self):
        """
        @summary: Testing UDP from sender with security egress rules on
                  port 750 that is part of the egress rule
        """
        
        file_content = 'Security Groups UDP 750 testing from sender'
        expected_data = 'XXXXX{0}'.format(file_content)

        self.verify_upd_connectivity(
            listener_client=self.lp_rc, sender_client=self.sp_rc,
            listener_ip=self.lp.pnet_fix_ipv4[0], port=UDP_PORT_750,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
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
            listener_ip=self.lp.pnet_fix_ipv4[0], port=UDP_PORT_749,
            file_content=file_content, expected_data=expected_data)

    @tags('dev99')
    def test_sgigs(self):
        print 'testin....'

    def test_tcp_w_remote_ip_prefix(self):
        # Create TCP port rule with remopte_ip_prefix (listener IP prefix)
        # Update sender port with rule
        # Check communication between sender-listener (ports/ping)
        # Check communication between other-listener
        pass
        

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

from cafe.drivers.unittest.decorators import tags
from cloudcafe.networking.networks.personas import ServerPersona
from cloudroast.networking.networks.fixtures import NetworkingComputeFixture


class SecurityGroupsEgressIPv4Test(NetworkingComputeFixture):
    @classmethod
    def setUpClass(cls):
        super(SecurityGroupsEgressIPv4Test, cls).setUpClass()

        # Creating the Isolated IPv4 network
        network, subnet, port = cls.net.behaviors.create_network_subnet_port(
            name='ipv4_sg_net', ip_version=4, raise_exception=True)
        cls.delete_networks.append(network.id)
        cls.delete_subnets.append(subnet.id)
        cls.delete_ports.append(port.id)
        
        cls.network_ids = [cls.public_network_id, cls.service_network_id,
                           network.id]

        cls.listener = cls.create_test_server(name='sg_egress_listenerv4',
                                              network_ids=cls.network_ids,
                                              active_server=False)
        
        # Used for sending TCP and UDP packets with egress rules
        cls.sender = cls.create_test_server(name='sg_egress_senderv4',
                                            network_ids=cls.network_ids,
                                            active_server=False)
        
        # Used for sending ICMP packets with egress rules
        cls.icmp_sender = cls.create_test_server(name='sg_egress_icmp_senderv4',
                                                 network_ids=cls.network_ids,
                                                 active_server=False)

        # Used for sending TCP, UDP and ICMP packets without any rules
        cls.other_sender = cls.create_test_server(name='sg_egress_otherv4',
                                                  network_ids=cls.network_ids,
                                                  active_server=False)

        # Waiting for the servers to be active
        server_ids = [cls.listener.id, cls.sender.id, cls.icmp_sender.id,
                      cls.other_sender.id]
        print server_ids
        print cls.listener.admin_pass
        print cls.sender.admin_pass
        print cls.icmp_sender.admin_pass
        print cls.other_sender.admin_pass
        
        cls.net.behaviors.wait_for_servers_to_be_active(
            server_id_list=server_ids)        
        print 'active!!'

        cls.delete_servers = []

        
        #############for development w static servers#########
        """
        network = cls.networks.behaviors.get_network(
            'fe9e43d0-1820-4c95-8be9-f62639fdd0ca').response.entity
        
        server_ids = ['c3b2188a-ec8e-4a95-95af-52c16db6bcd3',
                      '5376f3fa-d1ac-48f8-9dfc-1e3ff865d43c',
                      '30a3166c-1cb9-4869-95ba-960992130e4d',
                      '0e68b8c4-76b3-48b2-a773-8e594b10c312']
        cls.listener = cls.net.behaviors.get_networking_server(
            server_id=server_ids[0])
        cls.listener.admin_pass = 'ax5oLUyugPLy'
        cls.sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[1])
        cls.sender.admin_pass = 'tpZuSp2T7tP9'
        cls.icmp_sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[2])
        cls.icmp_sender.admin_pass = 'EBAiV7ho5N7j'
        cls.other_sender = cls.net.behaviors.get_networking_server(
            server_id=server_ids[3])
        cls.other_sender.admin_pass = 'hG8zzsC8uV97'
        """
        ########################################################

        # Creating the security group and rules for TCP testing
        sg_req = cls.sec.behaviors.create_security_group(
            name='sg_egress', description='SG for testing egress rules')
        sec_group = sg_req.response.entity
        cls.delete_secgroups.append(sec_group.id)

        egress_tcp_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=sec_group.id, direction='egress',
            ethertype='IPv4', protocol='tcp', port_range_min=443,
            port_range_max=445)
        egress_tcp_rule = egress_tcp_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_tcp_rule.id)

        ingress_ssh_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=sec_group.id, direction='ingress',
            ethertype='IPv4', protocol='tcp', port_range_min=22,
            port_range_max=22)
        ingress_ssh_rule = ingress_ssh_rule_req.response.entity
        cls.delete_secgroups_rules.append(ingress_ssh_rule.id)

        # Creating the security group and rules for TCP testing
        sg_icmp_req = cls.sec.behaviors.create_security_group(
            name='sg_egress', description='SG for testing egress rules')
        sec_group_icmp = sg_icmp_req.response.entity
        cls.delete_secgroups.append(sec_group_icmp.id)

        egress_icmp_rule_req = cls.sec.behaviors.create_security_group_rule(
            security_group_id=sec_group_icmp.id, direction='egress',
            ethertype='IPv4', protocol='icmp')
        egress_icmp_rule = egress_icmp_rule_req.response.entity
        cls.delete_secgroups_rules.append(egress_icmp_rule.id)

        ingress_ssh_rule_req2 = cls.sec.behaviors.create_security_group_rule(
            security_group_id=sec_group_icmp.id, direction='ingress',
            ethertype='IPv4', protocol='tcp', port_range_min=22,
            port_range_max=22)
        ingress_ssh_rule2 = ingress_ssh_rule_req2.response.entity
        cls.delete_secgroups_rules.append(ingress_ssh_rule2.id)
        
        cls.delete_secgroups = []
        cls.delete_secgroups_rules = []        
        #############for development w static SGs#########
        """
        sec_group = cls.sec.behaviors.get_security_group('ef2d2fec-5dee-4f4e-8bcc-2dc30e601d88').response.entity
        egress_tcp_rule = cls.sec.behaviors.get_security_group_rule('d5d2eb79-0906-4f56-9d53-14bf5c10fc24').response.entity
        ingress_ssh_rule = cls.sec.behaviors.get_security_group_rule('6cabf849-ce02-4f06-b266-576ab6c7345d').response.entity
        sec_group_icmp = cls.sec.behaviors.get_security_group('1ca7ecb6-2bd7-41b6-9f8f-706f11803ae0').response.entity
        egress_icmp_rule = cls.sec.behaviors.get_security_group_rule('076eef4c-480e-4f1c-bfb6-2227bbf30195').response.entity
        ingress_ssh_rule2 = cls.sec.behaviors.get_security_group_rule('e1b41a07-7da2-4b89-89d3-409396c2688c').response.entity
        """
        ####################################################
        print sec_group
        print egress_tcp_rule
        print ingress_ssh_rule
        print sec_group_icmp
        print egress_icmp_rule        
        print ingress_ssh_rule2

        # Getting the server sender ports via the server persona object
        sp = ServerPersona(server=cls.sender, inet=True, network=network,
                           inet_port_count=1, inet_fix_ipv4_count=1)        

        spi = ServerPersona(server=cls.icmp_sender, inet=True, network=network,
                            inet_port_count=1, inet_fix_ipv4_count=1) 
        
        print sp.pnet_ports
        print sp.snet_ports
        print sp.inet_ports
        print spi.pnet_ports
        print spi.snet_ports
        print spi.inet_ports       
        
        # Updating the TCP and ICMP sender servers ports with security groups
        sp_pnet_req = cls.ports.behaviors.update_port(
            port_id=sp.pnet_port_ids[0], security_groups=[sec_group.id])
        sp_snet_req = cls.ports.behaviors.update_port(
            port_id=sp.snet_port_ids[0], security_groups=[sec_group.id])
        sp_inet_req = cls.ports.behaviors.update_port(
            port_id=sp.inet_port_ids[0], security_groups=[sec_group.id])

        spi_pnet_req = cls.ports.behaviors.update_port(
            port_id=spi.pnet_port_ids[0], security_groups=[sec_group_icmp.id])
        spi_snet_req = cls.ports.behaviors.update_port(
            port_id=spi.snet_port_ids[0], security_groups=[sec_group_icmp.id])
        spi_inet_req = cls.ports.behaviors.update_port(
            port_id=spi.inet_port_ids[0], security_groups=[sec_group_icmp.id])

        print sp.pnet_ports
        print sp.snet_ports
        print sp.inet_ports
        print spi.pnet_ports
        print spi.snet_ports
        print spi.inet_ports  

    @tags('dev4')
    def test_sgigs(self):
        print 'testin....'
        

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
from cafe.drivers.unittest.datasets import DatasetList
from cafe.drivers.unittest.decorators import DataDrivenFixture, \
    data_driven_test, tags
from cafe.drivers.unittest.decorators import tags

from cloudcafe.networking.networks.personas import ServerPersona
from cloudcafe.networking.networks.extensions.ip_addresses_api.constants \
    import (IPAddressesErrorTypes, IPAddressesResource,
            IPAddressesResponseCodes)
from cloudroast.networking.networks.fixtures \
    import NetworkingIPAssociationsFixture


class SharedIPTest(NetworkingIPAssociationsFixture):

    @classmethod
    def setUpClass(cls):
        super(SharedIPTest, cls).setUpClass()
        """Setting up isolated network and test servers"""

        cls.server1 = cls.net.behaviors.get_networking_server(
            server_id='457fe2d3-2c0f-4cef-b836-80beccd74537')        
        cls.server2 = cls.net.behaviors.get_networking_server(
            server_id='c0ff951a-1bf3-4177-8d6a-fdd61cd9d9ce')
        cls.server3 = cls.net.behaviors.get_networking_server(
            server_id='631e6f5c-8832-47fa-b6f5-b95bf519476f')        

        cls.servers_list = [cls.server1, cls.server2, cls.server3]
        cls.network = cls.networks.behaviors.get_network(
            'e71a46e9-47f7-40a4-b82c-53056f9a3923').response.entity
        cls.subnet = cls.subnets.behaviors.list_subnets(
            network_id=cls.network.id).response.entity[0]
        cls.port = cls.ports.behaviors.list_ports(
            network_id=cls.network.id).response.entity[0]

        cls.isolated_network_id = cls.network.id
        network_ids = [cls.public_network_id, cls.service_network_id,
                       cls.isolated_network_id]
        
        # Server initial IP address configuration per network: pnet (Public),
        # snet (private or service) and inet (isolated)
        cls.server_persona1 = ServerPersona(
                server=cls.server1, pnet=True, snet=True, inet=True,
                 network=cls.network, subnetv4=cls.subnet, portv4=None,
                 subnetv6=None, portv6=None, inet_port_count=1,
                 snet_port_count=1, pnet_port_count=1, inet_fix_ipv4_count=1,
                 inet_fix_ipv6_count=0, snet_fix_ipv4_count=1, snet_fix_ipv6_count=0,
                 pnet_fix_ipv4_count=1, pnet_fix_ipv6_count=1)

        cls.server_persona2 = ServerPersona(
                server=cls.server2, pnet=True, snet=True, inet=True,
                 network=cls.network, subnetv4=cls.subnet, portv4=None,
                 subnetv6=None, portv6=None, inet_port_count=1,
                 snet_port_count=1, pnet_port_count=0, inet_fix_ipv4_count=1,
                 inet_fix_ipv6_count=0, snet_fix_ipv4_count=1, snet_fix_ipv6_count=0,
                 pnet_fix_ipv4_count=1, pnet_fix_ipv6_count=1)

        cls.server_persona3 = ServerPersona(
                server=cls.server3, pnet=True, snet=True, inet=True,
                 network=cls.network, subnetv4=cls.subnet, portv4=None,
                 subnetv6=None, portv6=None, inet_port_count=1,
                 snet_port_count=1, pnet_port_count=1, inet_fix_ipv4_count=1,
                 inet_fix_ipv6_count=0, snet_fix_ipv4_count=1, snet_fix_ipv6_count=0,
                 pnet_fix_ipv4_count=1, pnet_fix_ipv6_count=1)

        # Updating isolated device port as server persona for assertions
        cls.server_persona1.portv4 = cls.server_persona1.inet_ports[0]
        cls.server_persona2.portv4 = cls.server_persona2.inet_ports[0]
        cls.server_persona3.portv4 = cls.server_persona3.inet_ports[0]

        cls.personas = [cls.server_persona1, cls.server_persona2,
                        cls.server_persona3]

    def setUp(self):
        """Checking test server network, port and fixed IPs"""

        self.assertServersPersonaNetworks(self.personas)
        self.assertServersPersonaPorts(self.personas)
        self.assertServersPersonaFixedIps(self.personas)

        self.pnet_port_ids = self.get_servers_persona_port_ids(
            server_persona_list=self.personas, type_='public')
        self.snet_port_ids = self.get_servers_persona_port_ids(
            server_persona_list=self.personas, type_='private')
        self.inet_port_ids = self.get_servers_persona_port_ids(
            server_persona_list=self.personas, type_='isolated')

        # Getting isolated ports that should have compute as owner
        self.s1_port = self.inet_port_ids[0]
        self.s2_port = self.inet_port_ids[1]
        self.s3_port = self.inet_port_ids[2]
        
        #this is the same as self.server_persona1.inet_port_ids[0]

        #create puclib ipv4 and ipv6 shared ips and isolated ipv4
        #get the IPs and check the response
        #list the IPs and check the response is ok
        #associate (bind) the shared IPs with server 1 and 2
        #negative update shared ip ports with server 2 and 3 (should not be
        #possible
        #negative delete shared ip binded, should not be possible
        #unbind server 1 and update shared ip with 2 and 3 should be ok
        #unbind shared IP and delete should be ok

    def tearDown(self):
        self.ipAddressesCleanUp()

    @tags('dev3')
    def test_sips(self):
        expected_ip = self.get_expected_ip_address_data()
        expected_ip.network_id = self.public_network_id
        expected_ip.version = 6
        expected_ip.port_ids = self.pnet_port_ids
        
        shared_ip = self.create_test_ipaddress(expected_ip)
        
        print expected_ip
        print shared_ip
        # add the check that the fixed IP was added
       
    @tags('positive', 'rbac_creator')
    def test_public_network_shared_ipv4_create_w_port_ids(self):
        """
        @summary: Creating a public network IPv4 shared IP with port IDs
        """
        expected_ip = self.get_expected_ip_address_data()
        expected_ip.network_id = self.public_network_id
        expected_ip.version = 4
        expected_ip.port_ids = self.pnet_port_ids
        self.create_test_ipaddress(expected_ip)

    @tags('positive', 'rbac_creator')
    def test_public_network_shared_ipv6_create_w_port_ids(self):
        """
        @summary: Creating a public network IPv6 shared IP with port IDs
        """
        expected_ip = self.get_expected_ip_address_data()
        expected_ip.network_id = self.public_network_id
        expected_ip.version = 6
        expected_ip.port_ids = self.pnet_port_ids
        self.create_test_ipaddress(expected_ip)
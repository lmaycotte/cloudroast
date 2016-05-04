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

from cloudcafe.networking.networks.common.constants \
    import NetworkTypes, PortTypes
from cloudcafe.networking.networks.personas import ServerPersona
from cloudcafe.networking.networks.extensions.ip_addresses_api.constants \
    import IPAddressesErrorTypes, IPAddressesResource, \
        IPAddressesResponseCodes
from cloudroast.networking.networks.fixtures \
    import NetworkingIPAssociationsFixture


class SharedIPTest(NetworkingIPAssociationsFixture):

    @classmethod
    def setUpClass(cls):
        super(SharedIPTest, cls).setUpClass()
        """Setting up test servers with an IPv4 isolated network"""
        
        """
        cls.fixture_log.debug('Creating the isolated network with IPv4 subnet')
        net_req = cls.networks.behaviors.create_network(name='shared_ip_net')
        cls.network = net_req.response.entity
        sub4_req = cls.subnets.behaviors.create_subnet(
            network_id=cls.network.id, ip_version=4)
        cls.subnet4 = sub4_req.response.entity

        cls.fixture_log.debug('Creating the test servers')
        cls.network_ids = [cls.public_network_id, cls.service_network_id,
                           cls.network.id]
        
        cls.server1 = cls.create_test_server(name='shared_ip_server1',
                                             network_ids=cls.network_ids,
                                             active_server=False)

        cls.server2 = cls.create_test_server(name='shared_ip_server2',
                                             network_ids=cls.network_ids,
                                             active_server=False)

        cls.server3 = cls.create_test_server(name='shared_ip_server3',
                                             network_ids=cls.network_ids,
                                             active_server=False)

        # Waiting for the servers to be active
        server_ids = [cls.server1.id, cls.server2.id, cls.server3.id]

        print cls.network
        print cls.subnet4
        print server_ids
    
        cls.net.behaviors.wait_for_servers_to_be_active(
            server_id_list=server_ids)        
        print 'active!!'

        cls.delete_servers = []

        #############for development w static servers#########
        """
        cls.network = cls.networks.behaviors.get_network(
            '0e147a87-ff0c-4e68-9299-02246aa7d77f').response.entity
        cls.subnet4 = cls.subnets.behaviors.get_subnet(
            '8035518f-ea3b-4822-8dac-969069548b2b').response.entity

        server_ids = [u'67e37b2d-c65e-4349-962f-a311425f7809',
                      u'fe2d01bb-afa2-4006-8b3e-6fa84459f088',
                      u'66499a19-6d14-4288-ab2f-0d23eea9fa3a']
        
        cls.server1 = cls.net.behaviors.get_networking_server(
            server_id=server_ids[0])        
        cls.server2 = cls.net.behaviors.get_networking_server(
            server_id=server_ids[1])
        cls.server3 = cls.net.behaviors.get_networking_server(
            server_id=server_ids[2])        
        #"""

        # Server initial IP address configuration per network: pnet (Public),
        # snet (private or service) and inet (isolated)
        cls.sp1 = ServerPersona(server=cls.server1, inet=True,
                                network=cls.network, subnetv4=cls.subnet4,
                                inet_port_count=1, inet_fix_ipv4_count=1)
        cls.sp1.update_server_persona()

        cls.sp2 = ServerPersona(server=cls.server2, inet=True,
                                network=cls.network, subnetv4=cls.subnet4,
                                inet_port_count=1, inet_fix_ipv4_count=1)
        cls.sp2.update_server_persona()

        cls.sp3 = ServerPersona(server=cls.server3, inet=True,
                                network=cls.network, subnetv4=cls.subnet4,
                                inet_port_count=1, inet_fix_ipv4_count=1)
        cls.sp3.update_server_persona()

        cls.personas = [cls.sp1, cls.sp2, cls.sp3]

    def setUp(self):
        """Checking test server network, port and fixed IPs"""

        #self.assertServersPersonaNetworks(self.personas)
        #self.assertServersPersonaPorts(self.personas)
        #self.assertServersPersonaFixedIps(self.personas)

        self.pnet_port_ids = self.get_servers_persona_port_ids(
            server_persona_list=self.personas, type_='public')
        self.snet_port_ids = self.get_servers_persona_port_ids(
            server_persona_list=self.personas, type_='private')
        self.inet_port_ids = self.get_servers_persona_port_ids(
            server_persona_list=self.personas, type_='isolated')
        
        print self.pnet_port_ids
        print self.snet_port_ids
        print self.inet_port_ids
        
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

        # Defining initial shared IP data object
        expected_ip = self.get_expected_ip_address_data()

        # Defining IPv4 or IPv6 version for shared IP
        version = 6
        expected_ip.version = version

        # Defining network type: public, service or isolated
        # And getting the network ID from any server persona
        network_type = NetworkTypes.PUBLIC
        network_id_label = '{0}_network_id'.format(network_type.lower())
        network_id = getattr(self.sp1, network_id_label)
        expected_ip.network_id = network_id

        # Defining slicing indexes for ports or devices IDs to be used (0-3)
        start_id_index = 0
        end_id_index = 2

        # Defining port type: pnet, snet or inet (for public, service or iso)
        port_type = PortTypes.PUBLIC
        ports_label = '{0}_ports'.format(port_type.lower())
        port_ids_label = '{0}_port_ids'.format(port_type.lower())
        port_ids = getattr(self, port_ids_label)
        expected_ip.port_ids = port_ids[start_id_index:end_id_index]

        # Defining initial server fixed IPs count for specified network type
        initial_server1_fixed_ip_count = 1
        initial_server2_fixed_ip_count = 1
        initial_server3_fixed_ip_count = 1       

        # Defining servers fixed IPs on port after creating the shared IP (+1)
        # Shared IP is added to the server port fixed_ips attribute
        # Which servers get a +1 IP depend on the start and end id used indexes
        server1_fixed_ip_count = 2
        server2_fixed_ip_count = 2
        server3_fixed_ip_count = 1
        fix_ip_label = '{0}_fix_ipv{1}'.format(port_type.lower(), version)
        fix_ip_count_label = '{0}_count'.format(fix_ip_label)
        
        for n, persona in enumerate(self.personas):
            server_n_label = 'server{0}_fixed_ip_count'.format(n + 1)
            server_fixed_ip_count = eval(server_n_label)
            print server_fixed_ip_count
            setattr(persona, fix_ip_count_label, server_fixed_ip_count)
     
        print fix_ip_count_label
        print network_id
        print port_ids
        
        shared_ip = self.create_test_ipaddress(expected_ip)
        
        print expected_ip
        print shared_ip

        # Check the expected shared IP was only added to the expected port
        self.assertServersPersonaFixedIps(self.personas)
        
        print self.sp1.pnet_fix_ipv6
        fixed_ips = getattr(self.sp1, fix_ip_label)
        ports = getattr(self.sp1, ports_label)
        server_id = self.sp1.server.id

        msg = ('Expected shared IP \n{shared_ip}\nMissing in server '
               '{server_id} ports:\n{ports}').format(shared_ip=shared_ip,
                                                     server_id=server_id,
                                                     ports=ports)
        self.assertIn(shared_ip.address, fixed_ips, msg)
        
        # Reseting the server persona fixed IPs counts
        setattr(self.sp1, fix_ip_count_label, initial_server1_fixed_ip_count)
        setattr(self.sp2, fix_ip_count_label, initial_server2_fixed_ip_count)
        setattr(self.sp3, fix_ip_count_label, initial_server3_fixed_ip_count)        
       
    @tags('dev4')
    def test_public_network_shared_ipv4_create_w_port_ids(self):
        """
        @summary: Creating a public network IPv4 shared IP with port IDs
        """
        expected_ip = self.get_expected_ip_address_data()
        expected_ip.network_id = self.public_network_id
        expected_ip.version = 4
        expected_ip.port_ids = self.pnet_port_ids

        shared_ip = self.create_test_ipaddress(expected_ip)
        print expected_ip
        print shared_ip
                

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
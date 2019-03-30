
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import netaddr
import testtools

from tempest.common import custom_matchers
from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from vmware_nsx_tempest_plugin.lib import feature_manager
CONF = config.CONF


class IPv6PortsTest(feature_manager.FeatureManager):
    """Test the following operations for ports:
        port create
        port delete
        port list
        port show
        port update
    """

    @classmethod
    def skip_checks(cls):
        super(IPv6PortsTest, cls).skip_checks()
        if not (CONF.network_feature_enabled.ipv6 and
                CONF.network_feature_enabled.ipv6_subnet_attributes):
            raise cls.skipException('IPv6 or its attributes not supported')
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(IPv6PortsTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(IPv6PortsTest, cls).resource_setup()

    def _delete_port(self, port_id):
        self.ports_client.delete_port(port_id)
        body = self.ports_client.list_ports()
        ports_list = body['ports']
        self.assertFalse(port_id in [n['id'] for n in ports_list])

    def _update_port_with_security_groups(self, security_groups_names):
        name = "ipv6-network"
        security_groups_list = list()
        networks_client = self.cmgr_adm.networks_client
        network = self.create_topology_network(name,
                                               networks_client=networks_client)
        address_cidr = CONF.network.project_network_v6_cidr
        address_prefixlen = CONF.network.project_network_v6_mask_bits
        if ((address_prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address_cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools':
                            [{'start': str(address_cidr).split('/')[0] + '2',
                              'end':str(address_cidr).split('/')[0] + '70'}]}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network['name'] + 'sub'
        subnet_1 = self.create_topology_subnet(subnet_name, network, 
                                               subnets_client=subnet_client,
                                               ip_version=6, enable_dhcp=False,
                                               **allocation_pools)
        fixed_ip_1 = [{'subnet_id': subnet_1['id']}]
        sec_rule_client = self.cmgr_adm.security_group_rules_client
        sec_client = self.cmgr_adm.security_groups_client
        for name in security_groups_names:
            group_create_body = self.create_topology_security_group(
                namestart=name, security_groups_client=sec_client,
                security_group_rules_client=sec_rule_client)
            security_groups_list.append(group_create_body['id'])
        # Create a port
        sec_grp_name = data_utils.rand_name('secgroup')
        security_group = self.create_topology_security_group(
            namestart=sec_grp_name, security_groups_client=sec_client,
            security_group_rules_client=sec_rule_client)
        post_body = {
            "name": data_utils.rand_name('port-'),
            "security_groups": [security_group['id']],
            "admin_state_up": True,
            "fixed_ips": fixed_ip_1}
        port_client = self.cmgr_adm.ports_client
        body = self.create_topology_port(network=network,
                                         ports_client=port_client,
                                         **post_body)
        port = body['port']
        # Update the port with security groups
        update_body = {"name": data_utils.rand_name('port-'),
                       "admin_state_up": False,
                       "security_groups": security_groups_list}
        body = self.update_topology_port(port['id'], ports_client=port_client,
                                         **update_body)
        port_show = body['port']
        # Verify the security groups and other attributes updated to port
        exclude_keys = set(port_show).symmetric_difference(update_body)
        exclude_keys.add('security_groups')
        self.assertThat(port_show, custom_matchers.MatchesDictExceptForKeys(
                        update_body, exclude_keys))

        for security_group in security_groups_list:
            self.assertIn(security_group, port_show['security_groups'])

    def _create_ipv6_topology(self):
        name = "ipv6-network"
        networks_client = self.cmgr_adm.networks_client
        network = self.create_topology_network(name,
                                               networks_client=networks_client)
        address_cidr = CONF.network.project_network_v6_cidr
        address_prefixlen = CONF.network.project_network_v6_mask_bits
        if ((address_prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address_cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools': [{
                            'start': str(address_cidr).split('/')[0] + '2',
                            'end':str(address_cidr).split('/')[0] + '70'}]}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network['name'] + 'sub'
        self.create_topology_subnet(subnet_name, network, 
                                    subnets_client=subnet_client,
                                    ip_version=6, enable_dhcp=False,
                                    **allocation_pools)
        return network

    def _create_ipv6_rtr_topology(self):
        # Create a router
        router = self.create_topology_router(
            "ipv6-rtr", routers_client=self.cmgr_adm.routers_client)
        name = "ipv6-network"
        networks_client = self.cmgr_adm.networks_client
        network = self.create_topology_network(name,
                                               networks_client=networks_client)
        address_cidr = CONF.network.project_network_v6_cidr
        address_prefixlen = CONF.network.project_network_v6_mask_bits
        if ((address_prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address_cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools': [{
                            'start': str(address_cidr).split('/')[0] + '2',
                            'end':str(address_cidr).split('/')[0] + '70' }]}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network['name'] + 'sub'
        self.create_topology_subnet(subnet_name, network,
                                    subnets_client=subnet_client,
                                    routers_client=self.cmgr_adm.routers_client,
                                    router_id=router['id'],
                                    ip_version=6, enable_dhcp=False,
                                    **allocation_pools)
        return network, router

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('030e75c0-c8b5-4f80-912e-d41543c940aa')
    def test_create_ipv6_port_allowed_allocation_pools(self):
        """
        Test create port with IPv6 static address
        Verify the address is within the CIDR block
        """
        network = self._create_ipv6_topology()
        port_client = self.cmgr_adm.ports_client
        body = self.create_topology_port(network=network,
                                         ports_client=port_client)
        port = body['port']
        ip_address = port['fixed_ips'][0]['ip_address']
        address_cidr = CONF.network.project_network_v6_cidr
        allocation_pools = {'allocation_pools': [{
                            'start': str(address_cidr).split('/')[0] + '2',
                            'end':str(address_cidr).split('/')[0] + '70'}]}
        start_ip_address = allocation_pools['allocation_pools'][0]['start']
        end_ip_address = allocation_pools['allocation_pools'][0]['end']
        ip_range = netaddr.IPRange(start_ip_address, end_ip_address)
        self.assertIn(ip_address, ip_range)

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('6ff0f917-ca9d-46d7-a463-56e86b93c540')
    def test_update_port(self):
        """
        Test update an IPv6 port with a different name
        and set admin_state to False
        Verify the update of port options is successful
        """
        network = self._create_ipv6_topology()
        port_client = self.cmgr_adm.ports_client
        body = self.create_topology_port(network=network,
                                         ports_client=port_client)
        port = body['port']
        # Verify port update
        new_name = "New_Port"
        body = self.update_topology_port(port['id'],
                                         ports_client=port_client,
                                         name=new_name,
                                         admin_state_up=False)
        updated_port = body['port']
        self.assertEqual(updated_port['name'], new_name)
        self.assertFalse(updated_port['admin_state_up'])

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('62009271-562a-4263-bd76-b478bbda2928')
    def test_show_port(self):
        # Verify the details of port
        network = self._create_ipv6_topology()
        port_client = self.cmgr_adm.ports_client
        body = self.create_topology_port(network=network, ports_client=port_client)
        create_port = body['port']
        body = self.show_topology_port(create_port['id'], ports_client=port_client)
        show_port = body['port']
        self.assertIn('id', show_port)
        self.assertThat(create_port,
                        custom_matchers.MatchesDictExceptForKeys
                        (show_port, excluded_keys=['extra_dhcp_opts',
                                              'created_at',
                                              'updated_at']))

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('547d2daf-b291-40f0-aa96-873af369847d')
    def test_show_port_fields(self):
        # Verify specific fields of a port
        network = self._create_ipv6_topology()
        port_client = self.cmgr_adm.ports_client
        body = self.create_topology_port(network=network, ports_client=port_client)
        create_port = body['port']
        fields = ['id', 'mac_address']
        body = self.show_topology_port(create_port['id'], ports_client=port_client,
                                       fields=fields)
        show_port = body['port']
        self.assertEqual(sorted(show_port.keys()), sorted(fields))
        for field_name in fields:
            self.assertEqual(show_port[field_name], create_port[field_name])

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('442d05b5-41bf-4d26-8f1a-7426d4c40f95')
    def test_list_ports(self):
        # Verify the port exists in the list of all ports
        network = self._create_ipv6_topology()
        port_client = self.cmgr_adm.ports_client
        body = self.create_topology_port(network=network, ports_client=port_client)
        create_port = body['port']
        body = self._list_ports()
        ports = [port['id'] for port in body
                 if port['id'] == create_port['id']]
        self.assertNotEmpty(ports, "Created port not found in the list")

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('f2c378ed-7385-4007-90bf-dc856e8dd92d')
    def test_port_list_filter_by_ip(self):
        """
        Verify port list filtering with IPv6 address
        """
        # Create network and subnet
        network = self._create_ipv6_topology()
        port_client = self.cmgr_adm.ports_client
        # Create two ports
        body = self.create_topology_port(network=network, ports_client=port_client)
        port_1 = body['port']
        body = self.create_topology_port(network=network, ports_client=port_client)
        # List ports filtered by fixed_ips
        port_1_fixed_ip = port_1['fixed_ips'][0]['ip_address']
        fixed_ips = 'ip_address=' + port_1_fixed_ip
        ports = self._list_ports(fixed_ips=fixed_ips)
        # Check that we got the desired port
        tenant_ids = set([port['tenant_id'] for port in ports])
        self.assertEqual(len(tenant_ids), 1,
                         'Ports from multiple tenants are in the list resp')
        port_ids = [port['id'] for port in ports]
        fixed_ips = [port['fixed_ips'] for port in ports]
        port_ips = []
        for addr in fixed_ips:
            port_ips.extend([port['ip_address'] for port in addr])

        port_net_ids = [port['network_id'] for port in ports]
        self.assertIn(port_1['id'], port_ids)
        self.assertIn(port_1_fixed_ip, port_ips)
        self.assertIn(network['id'], port_net_ids)

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('72492a05-ab4a-4b2f-a142-a92e5b193935')
    def test_port_list_filter_by_router_id(self):
        """
        Verify port list filtering with router ID parameter
        """
        # Create network and subnet and router
        network, router = self._create_ipv6_rtr_topology()
        # List ports filtered by router_id
        ports = self._list_ports(device_id=router['id'])
        self.assertEqual(len(ports), 2)
        for port in ports:
            self.assertEqual(port['device_id'], router['id'])

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('5f3b1f8b-5c80-4191-b1f0-b42515a95c32')
    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_update_port_with_security_group_and_extra_attributes(self):
        self._update_port_with_security_groups(
            [data_utils.rand_name('secgroup')])

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('595ac04f-18aa-4d7a-88a5-a2e3c446a80c')
    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_update_port_with_two_security_groups_and_extra_attributes(self):
        self._update_port_with_security_groups(
            [data_utils.rand_name('secgroup'),
             data_utils.rand_name('secgroup')])

    @decorators.attr(type=['smoke', 'positive'])
    @decorators.idempotent_id('31ab954f-8725-41fe-a6bb-c7271fe94389')
    def test_create_show_delete_port_user_defined_mac(self):
        """
        Verify CRUD operations on a port with user defind mac
        """
        # Create network and subnet
        network = self._create_ipv6_topology()
        port_client = self.cmgr_adm.ports_client
        # Create port
        body = self.create_topology_port(network=network, ports_client=port_client)
        # Create a port for a legal mac
        old_port = body['port']
        free_mac_address = old_port['mac_address']
        self.delete_topology_port(old_port['id'], ports_client=port_client)
        # Create a new port with user defined mac
        body = self.create_topology_port(network=network, ports_client=port_client,
                                         mac_address=free_mac_address)
        port = body['port']
        body = self.show_topology_port(port['id'], ports_client=port_client)
        show_port = body['port']
        self.assertEqual(free_mac_address,
                         show_port['mac_address'])

    @decorators.attr(type=['smoke', 'negative'])
    @decorators.idempotent_id('ae63ad4d-dd30-4728-a2f2-ac027521403b')
    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_create_port_with_no_securitygroups(self):
        # Create network and subnet
        network = self._create_ipv6_topology()
        port_client = self.cmgr_adm.ports_client
        # Create port
        body = self.create_topology_port(network=network, ports_client=port_client,
                                         security_groups=[])
        port = body['port']
        self.assertIsNotNone(port['security_groups'])
        self.assertEmpty(port['security_groups'])

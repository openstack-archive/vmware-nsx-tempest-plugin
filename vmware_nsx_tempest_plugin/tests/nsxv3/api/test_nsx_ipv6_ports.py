
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

import ipaddress

import netaddr
import six
import testtools

from tempest.api.network import base
from tempest.common import custom_matchers
from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as ex

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.services import nsxv3_client

CONF = config.CONF

class IPv6PortsTest(base.BaseAdminNetworkTest):
    """Test the following operations for ports:
        port create
        port delete
        port list
        port show
        port update
    """
    _ip_version = 6
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
    def resource_setup(cls):
        super(IPv6PortsTest, cls).resource_setup()
        cls.network = cls.create_network()
        cls.port = cls.create_port(cls.network)

    def _delete_port(self, port_id):
        self.ports_client.delete_port(port_id)
        body = self.ports_client.list_ports()
        ports_list = body['ports']
        self.assertFalse(port_id in [n['id'] for n in ports_list])

    def _create_subnet(self, network, gateway='',
                       cidr=None, mask_bits=None, enable_dhcp=None,
                       **kwargs):
        subnet = self.create_subnet(network, gateway, cidr, mask_bits, enable_dhcp=enable_dhcp)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])
        return subnet

    def _create_network(self, network_name=None, **kwargs):
        network_name = network_name or data_utils.rand_name(
            self.__class__.__name__)
        network = self.networks_client.create_network(
            name=network_name, **kwargs)['network']
        self.addCleanup(self.networks_client.delete_network,
                        network['id'])
        return network

    def _update_port_with_security_groups(self, security_groups_names):
        subnet_1 = self._create_subnet(self.network, enable_dhcp=False)
        fixed_ip_1 = [{'subnet_id': subnet_1['id']}]

        security_groups_list = list()
        sec_grps_client = self.security_groups_client
        for name in security_groups_names:
            group_create_body = sec_grps_client.create_security_group(
                name=name)
            self.addCleanup(self.security_groups_client.delete_security_group,
                            group_create_body['security_group']['id'])
            security_groups_list.append(group_create_body['security_group']
                                        ['id'])
        # Create a port
        sec_grp_name = data_utils.rand_name('secgroup')
        security_group = sec_grps_client.create_security_group(
            name=sec_grp_name)
        self.addCleanup(self.security_groups_client.delete_security_group,
                        security_group['security_group']['id'])
        post_body = {
            "name": data_utils.rand_name('port-'),
            "security_groups": [security_group['security_group']['id']],
            "network_id": self.network['id'],
            "admin_state_up": True,
            "fixed_ips": fixed_ip_1}
        body = self.ports_client.create_port(**post_body)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])
        port = body['port']

        # Update the port with security groups
        update_body = {"name": data_utils.rand_name('port-'),
                       "admin_state_up": False,
                       "security_groups": security_groups_list}
        body = self.ports_client.update_port(port['id'], **update_body)
        port_show = body['port']
        # Verify the security groups and other attributes updated to port
        exclude_keys = set(port_show).symmetric_difference(update_body)
        exclude_keys.add('security_groups')
        self.assertThat(port_show, custom_matchers.MatchesDictExceptForKeys(
                        update_body, exclude_keys))

        for security_group in security_groups_list:
            self.assertIn(security_group, port_show['security_groups'])

    @decorators.idempotent_id('030e75c0-c8b5-4f80-912e-d41543c940aa')
    def test_create_ipv6_port_allowed_allocation_pools(self):
        """ 
        Test create port with IPv6 static address
        Verify the address is within the CIDR block
        """    
        network = self._create_network()
        net_id = network['id']
        address = self.cidr
        address.prefixlen = self.mask_bits
        if ((address.version == 4 and address.prefixlen >= 30) or
            (address.version == 6 and address.prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address.cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools': [{'start': str(address[2]),
                                                  'end': str(address[-2])}]}
        self._create_subnet(network, cidr=address,
                            mask_bits=address.prefixlen,
                            enable_dhcp=False,
                            **allocation_pools)
        body = self.ports_client.create_port(network_id=net_id)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])
        port = body['port']
        ip_address = port['fixed_ips'][0]['ip_address']
        start_ip_address = allocation_pools['allocation_pools'][0]['start']
        end_ip_address = allocation_pools['allocation_pools'][0]['end']
        ip_range = netaddr.IPRange(start_ip_address, end_ip_address)
        self.assertIn(ip_address, ip_range)

    @decorators.idempotent_id('6ff0f917-ca9d-46d7-a463-56e86b93c540')
    def test_update_port(self):
        """ 
        Test update an IPv6 port with a different name
        and set admin_state to False
        Verify the update of port options is successful
        """
        _ip_version = 6
        network = self._create_network()
        net_id = network['id']
        address = self.cidr
        address.prefixlen = self.mask_bits
        if ((address.version == 4 and address.prefixlen >= 30) or
            (address.version == 6 and address.prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address.cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools': [{'start': str(address[2]),
                                                  'end': str(address[-2])}]}
        self._create_subnet(network, cidr=address,
                            mask_bits=address.prefixlen,
                            enable_dhcp=False,
                            **allocation_pools)
        body = self.ports_client.create_port(network_id=net_id)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])
        port = body['port']
        ip_address = port['fixed_ips'][0]['ip_address']
        start_ip_address = allocation_pools['allocation_pools'][0]['start']
        end_ip_address = allocation_pools['allocation_pools'][0]['end']
        ip_range = netaddr.IPRange(start_ip_address, end_ip_address)
        self.assertIn(ip_address, ip_range)
        self.assertTrue(port['admin_state_up'])
        # Verify port update
        new_name = "New_Port"
        body = self.ports_client.update_port(port['id'],
                                             name=new_name,
                                             admin_state_up=False)
        updated_port = body['port']
        self.assertEqual(updated_port['name'], new_name)
        self.assertFalse(updated_port['admin_state_up'])

    @decorators.idempotent_id('62009271-562a-4263-bd76-b478bbda2928')
    def test_show_port(self):
        # Verify the details of port
        body = self.ports_client.show_port(self.port['id'])
        port = body['port']
        self.assertIn('id', port)
        self.assertThat(self.port,
                        custom_matchers.MatchesDictExceptForKeys
                        (port, excluded_keys=['extra_dhcp_opts',
                                              'created_at',
                                              'updated_at']))

    @decorators.idempotent_id('547d2daf-b291-40f0-aa96-873af369847d')
    def test_show_port_fields(self):
        # Verify specific fields of a port
        fields = ['id', 'mac_address']
        body = self.ports_client.show_port(self.port['id'],
                                           fields=fields)
        port = body['port']
        self.assertEqual(sorted(port.keys()), sorted(fields))
        for field_name in fields:
            self.assertEqual(port[field_name], self.port[field_name])

    @decorators.idempotent_id('442d05b5-41bf-4d26-8f1a-7426d4c40f95')
    def test_list_ports(self):
        # Verify the port exists in the list of all ports
        body = self.ports_client.list_ports()
        ports = [port['id'] for port in body['ports']
                 if port['id'] == self.port['id']]
        self.assertNotEmpty(ports, "Created port not found in the list")

    @decorators.idempotent_id('f2c378ed-7385-4007-90bf-dc856e8dd92d')
    def test_port_list_filter_by_ip(self):
        """
        Verify port list filtering with IPv6 address
        """
        # Create network and subnet
        network = self._create_network()
        self._create_subnet(network, enable_dhcp=False)
        # Create two ports
        port_1 = self.ports_client.create_port(network_id=network['id'])
        self.addCleanup(self.ports_client.delete_port, port_1['port']['id'])
        port_2 = self.ports_client.create_port(network_id=network['id'])
        self.addCleanup(self.ports_client.delete_port, port_2['port']['id'])
        # List ports filtered by fixed_ips
        port_1_fixed_ip = port_1['port']['fixed_ips'][0]['ip_address']
        fixed_ips = 'ip_address=' + port_1_fixed_ip
        port_list = self.ports_client.list_ports(fixed_ips=fixed_ips)
        # Check that we got the desired port
        ports = port_list['ports']
        tenant_ids = set([port['tenant_id'] for port in ports])
        self.assertEqual(len(tenant_ids), 1,
                         'Ports from multiple tenants are in the list resp')
        port_ids = [port['id'] for port in ports]
        fixed_ips = [port['fixed_ips'] for port in ports]
        port_ips = []
        for addr in fixed_ips:
            port_ips.extend([port['ip_address'] for port in addr])

        port_net_ids = [port['network_id'] for port in ports]
        self.assertIn(port_1['port']['id'], port_ids)
        self.assertIn(port_1_fixed_ip, port_ips)
        self.assertIn(network['id'], port_net_ids)

    @decorators.idempotent_id('72492a05-ab4a-4b2f-a142-a92e5b193935')
    def test_port_list_filter_by_router_id(self):
        """
        Verify port list filtering with router ID parameter
        """
        # Create a router
        network = self._create_network()
        self._create_subnet(network, enable_dhcp=False)
        router = self.create_router()
        self.addCleanup(self.routers_client.delete_router, router['id'])
        port = self.ports_client.create_port(network_id=network['id'])
        # Add router interface to port created above
        self.routers_client.add_router_interface(router['id'],
                                                 port_id=port['port']['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], port_id=port['port']['id'])
        # List ports filtered by router_id
        port_list = self.ports_client.list_ports(device_id=router['id'])
        ports = port_list['ports']
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]['id'], port['port']['id'])
        self.assertEqual(ports[0]['device_id'], router['id'])

    @decorators.idempotent_id('5f3b1f8b-5c80-4191-b1f0-b42515a95c32')
    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_update_port_with_security_group_and_extra_attributes(self):
        self._update_port_with_security_groups(
            [data_utils.rand_name('secgroup')])

    @decorators.idempotent_id('595ac04f-18aa-4d7a-88a5-a2e3c446a80c')
    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_update_port_with_two_security_groups_and_extra_attributes(self):
        self._update_port_with_security_groups(
            [data_utils.rand_name('secgroup'),
             data_utils.rand_name('secgroup')])

    @decorators.idempotent_id('31ab954f-8725-41fe-a6bb-c7271fe94389')
    def test_create_show_delete_port_user_defined_mac(self):
        """
        Verify CRUD operations on a port with user defind mac
        """
        # Create a port for a legal mac
        body = self.ports_client.create_port(network_id=self.network['id'])
        old_port = body['port']
        free_mac_address = old_port['mac_address']
        self.ports_client.delete_port(old_port['id'])
        # Create a new port with user defined mac
        body = self.ports_client.create_port(network_id=self.network['id'],
                                             mac_address=free_mac_address)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])
        port = body['port']
        body = self.ports_client.show_port(port['id'])
        show_port = body['port']
        self.assertEqual(free_mac_address,
                         show_port['mac_address'])

    @decorators.idempotent_id('ae63ad4d-dd30-4728-a2f2-ac027521403b')
    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_create_port_with_no_securitygroups(self):
        network = self._create_network()
        self._create_subnet(network, enable_dhcp=False)
        port = self.create_port(network, security_groups=[])
        self.addCleanup(self.ports_client.delete_port, port['id'])
        self.assertIsNotNone(port['security_groups'])
        self.assertEmpty(port['security_groups'])

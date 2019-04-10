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
from tempest.lib import exceptions as lib_exc

from vmware_nsx_tempest_plugin.lib import feature_manager
CONF = config.CONF


class IPv6ExternalNetworksTest(feature_manager.FeatureManager):
    """Test the operations on IPv6 External Network
    """

    @classmethod
    def skip_checks(cls):
        super(IPv6ExternalNetworksTest, cls).skip_checks()
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
        super(IPv6ExternalNetworksTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(IPv6ExternalNetworksTest, cls).resource_setup()

    @decorators.attr(type=['nsxv3', 'positive'])
    @decorators.idempotent_id('b3881f7a-4d7a-464d-9ecd-dc829e346e95')
    def test_create_ipv6_external_gateway_no_snat(self):
        """
        Test create IPv6 external network
        Verify the router can be configured with IPv6 gateway with no-SNAT
        """
        name = "ipv6-ext-network"
        networks_client = self.cmgr_adm.networks_client
        ext_network = self.create_topology_network(name,
                                                   networks_client=networks_client,
                                                   **{'router:external': True})
        self.assertIsNotNone(ext_network['id'])
        self.assertTrue(ext_network['router:external'])
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = ext_network['name'] + 'sub'
        allocation_pools = {'allocation_pools': [{
                            'start': '2000:20:20::2',
                            'end': '2000:20:20::200'}]}
        self.create_topology_subnet(subnet_name, ext_network,
            subnets_client=subnet_client,
            ip_version=6, enable_dhcp=False,
            cidr = "2000:20:20::/64",
            **allocation_pools)
        #Create a router and set gateway to an IPv6 external network
        router = self.create_topology_router(
            "ipv6-rtr", routers_client=self.cmgr_adm.routers_client,
            set_gateway=True, enable_snat=False,
            ext_netid=ext_network['id'])
        show_body = self.show_topology_router(router['id'],
            routers_client=self.cmgr_adm.routers_client)
        self.assertEqual(show_body['router']['id'], router['id'])
        self.assertEqual(show_body['router']['external_gateway_info']['enable_snat'], False)
        self.assertEqual(show_body['router']['external_gateway_info']['network_id'], ext_network['id'])

    @decorators.attr(type=['nsxv3', 'negative'])
    @decorators.idempotent_id('46aa564f-5d97-4540-aed5-660468b5f4a6')
    def test_create_ipv6_external_gateway_snat(self):
        """
        Test create IPv6 external network
        Verify the router can not be configured with IPv6 gateway with SNAT
        """
        name = "ipv6-ext-network"
        networks_client = self.cmgr_adm.networks_client
        ext_network = self.create_topology_network(name,
                                                   networks_client=networks_client,
                                                   **{'router:external': True})
        self.assertIsNotNone(ext_network['id'])
        self.assertTrue(ext_network['router:external'])
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = ext_network['name'] + 'sub'
        allocation_pools = {'allocation_pools': [{
                            'start': '2000:20:20::2',
                            'end': '2000:20:20::200'}]}
        self.create_topology_subnet(subnet_name, ext_network,
            subnets_client=subnet_client,
            ip_version=6, enable_dhcp=False,
            cidr = "2000:20:20::/64",
            **allocation_pools)
        #Create a router and set gateway to an IPv6 external network
        self.assertRaises(lib_exc.BadRequest,
                          self.create_topology_router,
                          router_name="ipv6-rtr",
                          routers_client=self.cmgr_adm.routers_client,
                          set_gateway=True, enable_snat=True,
                          ext_netid=ext_network['id'])

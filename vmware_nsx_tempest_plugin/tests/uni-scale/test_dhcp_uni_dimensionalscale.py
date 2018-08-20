# Copyright 2016 VMware Inc
# All Rights Reserved
#
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

import re

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxv_client

from oslo_log import log as logging

CONF = config.CONF
LOG = logging.getLogger(__name__)


class DHCPUnidimensionalScaleTest(feature_manager.FeatureManager):

    """Test Uni Dimesional Case for
       Logical-switches
       Logical-Dhcp-Servers
       Logical-Static-bindings

    """
    @classmethod
    def setup_clients(cls):
        super(DHCPUnidimensionalScaleTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(DHCPUnidimensionalScaleTest, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _create_scale_logical_dhcp_server(self, scale):
        # Create networks based on scale number
        for i in range(scale):
            name = 'uniscale-%s-net' % i
            network = self.create_topology_network(network_name=name)
            sub_name = 'uniscale-%s-sub' % i
            self.create_topology_subnet(sub_name, network)
        networks = self.networks_client.list_networks()
        scale_nets = [net for net in networks['networks']
                      if net['name'].startswith("uniscale-")]
        error_msg = "Neutron networks created doesn't match the scale number"
        self.assertEqual(len(scale_nets), scale, error_msg)
        nsx_switches = self.nsx.get_logical_switches()
        scale_switches = [ls for ls in nsx_switches
                          if ls['display_name'].startswith('uniscale-')]
        error_msg = ("Logical switches on backend doesn't match the "
                     "number of networks on OpenStack")
        self.assertIsNotNone(len(scale_switches), error_msg)
        dhcp_servers = self.nsx.get_logical_dhcp_servers()
        scale_dhcp_servers = [ds for ds in dhcp_servers
                              if ls['display_name'].startswith('uniscale-')]
        error_msg = ("Logical DHCP servers on backend doesn't match the "
                     "number of networks on OpenStack")
        self.assertIsNotNone(len(scale_dhcp_servers), scale, error_msg)

    def _create_scale_dhcp_bindings(self, scale):
        # Create a network with dhcp enabled subnet
        name = data_utils.rand_name('binding-')
        network = self.create_topology_network(network_name=name)
        sub_name = data_utils.rand_name('binding-sub')
        self.create_topology_subnet(sub_name, network)
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        self.assertIsNotNone(dhcp_server)
        for i in range(scale):
            args = {"device_owner": 'compute:None'}
            self.create_topology_port(network, **args)
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        dhcp_bindings = self.nsx.get_dhcp_server_static_bindings(
            dhcp_server['id'])
        self.assertEqual(len(dhcp_bindings), scale)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c2b264a2-daab-451f-ad3b-f0713a390f47')
    def test_create_500_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(500)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('5ba22b0f-4593-4509-8998-a3002ce63406')
    def test_create_1k_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('ddf3d789-838a-428a-b4fe-8fe214f0e956')
    def test_create_2k_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(2000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('ed5441be-a700-45fa-bec1-b1d100acbb73')
    def test_create_4k_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(4000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('4a5484e3-f9b8-4562-8a4c-d8974a703767')
    def test_create_100_dhcp_bindings(self):
        self._create_scale_dhcp_bindings(100)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('cbb8af8c-db3a-4ad2-8954-c41670956c52')
    def test_create_256_dhcp_bindings(self):
        self._create_scale_dhcp_bindings(256)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('ffa5db0b-5922-494d-bcd3-9d5b0b10b684')
    def test_create_512_dhcp_bindings(self):
        self._create_scale_dhcp_bindings(512)

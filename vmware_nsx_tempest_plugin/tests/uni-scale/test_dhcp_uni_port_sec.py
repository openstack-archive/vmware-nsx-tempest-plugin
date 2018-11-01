# Copyright 2018 VMware Inc
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


class PORTSecUnidimensionalScaleTest(feature_manager.FeatureManager):

    """Test Uni Dimesional Case for
       Logical-switches
       Logical-Dhcp-Servers
       Logical-Static-bindings

    """
    @classmethod
    def setup_clients(cls):
        super(PORTSecUnidimensionalScaleTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(PORTSecUnidimensionalScaleTest, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _create_scale_logical_port_with_disabled_port_sec(self, scale):
        # Create a network with dhcp enabled subnet
        neutron_ports = 0
        name = data_utils.rand_name('port-sec-net')
        network = self.create_topology_network(network_name=name)
        sub_name = data_utils.rand_name('port-sec-sub')
        self.create_topology_subnet(sub_name, network, cidr='20.20.0.0/16')
        port_name = data_utils.rand_name('port-sec')
        for i in range(scale):
            args = {"device_owner": 'compute:None',
                    "port_security_enabled": False,
                    "name": '%s%s' % (port_name, i)}
            self.create_topology_port(network, **args)
        ports = self.ports_client.list_ports()
        for port in ports.get('ports'):
            if "port-sec" in port['name']:
                neutron_ports += 1
        self.assertEqual(neutron_ports, scale)
        backend_ports = self.nsx.get_logical_ports()
        ports_name = [i.get('display_name') for i in backend_ports
                      if "port-sec" in i.get('display_name')]
        self.assertEqual(len(ports_name) - 2, scale)
        ns_group_id = self.nsx.get_neutron_ns_group_id()
        members = self.nsx.get_ns_group_port_members(ns_group_id)
        self.assertEqual(members.get('result_count'), scale)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c2b264a2-daab-4123-ad3b-f0713a390f47')
    def test_create_500_logical_dhcp_server(self):
        self._create_scale_logical_port_with_disabled_port_sec(500)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('5ba22b0f-4593-4345-8998-a3002ce63406')
    def test_create_1k_logical_dhcp_server(self):
        self._create_scale_logical_port_with_disabled_port_sec(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('ddf3d789-838a-4567-b4fe-8fe214f0e956')
    def test_create_2k_logical_dhcp_server(self):
        self._create_scale_logical_port_with_disabled_port_sec(2000)

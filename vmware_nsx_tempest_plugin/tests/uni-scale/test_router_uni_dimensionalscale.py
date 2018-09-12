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
from tempest.lib import decorators

from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxv_client

from oslo_log import log as logging

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RouterUnidimensionalScaleTest(feature_manager.FeatureManager):

    """Test Uni Dimesional Case for
       Logical-router
       Logical-router-ports

    """
    @classmethod
    def setup_clients(cls):
        super(RouterUnidimensionalScaleTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(RouterUnidimensionalScaleTest, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _create_scale_logical_router(self, scale):
        # Create networks based on scale number
        for i in range(scale):
            name = 'uniscale-%s-router' % i
            router = self.create_topology_router(router_name=name)
        routers = self.routers_client.list_routers()
        scale_rtrs = [rtr for rtr in routers['routers']
                      if router['name'].startswith("tempest-vmw_uniscale-")]
        error_msg = "Neutron routers created doesn't match the scale number"
        self.assertEqual(len(scale_rtrs), scale, error_msg)
        nsx_routers = self.nsx.get_logical_routers()
        scale_routers = \
            [lr for lr in nsx_routers
             if lr['display_name'].
             startswith('tempest-RouterUnidimensionalScaleTest')]
        error_msg = ("Logical routers on backend doesn't match the "
                     "number of routers on OpenStack")
        self.assertIsNotNone(len(scale_routers), error_msg)

    def _create_scale_logical_downlink_ports(self, scale):
        # Create a network with dhcp enabled subnet
        name = 'uniscale-router'
        router = self.create_topology_router(router_name=name)
        for i in range(scale):
            name = 'uniscale-%s-net' % i
            network = self.create_topology_network(network_name=name)
            sub_name = 'uniscale-%s-sub' % i
            self.create_topology_subnet(
                sub_name,
                network,
                router_id=router['id'])

        nsx_routers = self.nsx.get_logical_routers()
        lr = [lr for lr in nsx_routers if router.get(
            'name') in lr['display_name']][0]
        logical_router_ports = self.nsx.get_logical_router_ports(lr)
        self.assertIsNotNone(logical_router_ports)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('123264a2-daab-451f-ad3b-f0713a390f47')
    def test_create_500_logical_routers(self):
        self._create_scale_logical_router(5)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('45622b0f-4593-4509-8998-a3002ce63406')
    def test_create_1k_logical_routers(self):
        self._create_scale_logical_router(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('7893d789-838a-428a-b4fe-8fe214f0e956')
    def test_create_2k_logical_routers(self):
        self._create_scale_logical_router(2000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('213441be-a700-45fa-bec1-b1d100acbb73')
    def test_create_4k_logical_routers(self):
        self._create_scale_logical_router(4000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('546484e3-f9b8-4562-8a4c-d8974a703767')
    def test_create_100_router_ports(self):
        self._create_scale_logical_downlink_ports(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('9788af8c-db3a-4ad2-8954-c41670956c52')
    def test_create_256_router_ports(self):
        self._create_scale_logical_downlink_ports(256)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('8795db0b-5922-494d-bcd3-9d5b0b10b684')
    def test_create_512_router_ports(self):
        self._create_scale_logical_downlink_ports(512)

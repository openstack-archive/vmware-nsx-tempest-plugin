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

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxv_client

from oslo_log import log as logging

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ProviderNetworkUnidimensionalScaleTest(feature_manager.FeatureManager):

    """Test Uni Dimesional Case for
       Provider vlan networks
       Provider vlan networks and
       Provider vxlan networks
       Boot vms from scale networks and check does vm booted properly
    """
    @classmethod
    def setup_clients(cls):
        super(ProviderNetworkUnidimensionalScaleTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.routers_client = cls.cmgr_adm.routers_client
        cls.networks_client = cls.cmgr_adm.networks_client
        cls.subnets_client = cls.cmgr_adm.subnets_client
        cls.sec_rule_client = cls.cmgr_adm.security_group_rules_client
        cls.sec_client = cls.cmgr_adm.security_groups_client

    @classmethod
    def resource_setup(cls):
        super(ProviderNetworkUnidimensionalScaleTest, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _create_scale_vlan_provider_networks(self, scale, name):
        """
        Create provider networks as per the scale parameter
        value passed
        """
        for value in range(scale):
            namex = "uniscale-{}-{}-network".format(value, name)
            body = {"provider:network_type": constants.VLAN_TYPE,
                    "admin_state_up": 'True',
                    "provider:segmentation_id": value}
            self.create_topology_network(
                namex, networks_client=self.networks_client, **body)
        ls1 = self.networks_client.list_networks()['networks']
        networks = [i for i in ls1]
        uniscale_networks = [i for i in networks if name in i['name']]
        error_msg = "The count mismatch of neutron networks with scale counts"
        self.assertEqual(len(uniscale_networks), scale, error_msg)
        ls = self.nsx.get_logical_resources("/logical-switches")
        nsx_networks = [val for val in ls
                        if val['resource_type'] == "LogicalSwitch"]
        nsx_scale_networks = [val for val in nsx_networks
                              if name in val['display_name']]
        self.assertEqual(len(nsx_scale_networks), scale, error_msg)

    def _verify_connectivity_vms_different_routers(self, scale, name):
        """
         create vms under vlan networks randomly and check connectiviy
         Each subnet is taken under different router.
        """
        network = [i for i in self.networks_client.list_networks()['networks']
                   if name in i['name']]
        for val in range(scale):
            r_name = "uniscale-{}-{}-router".format(val, name)
            router = self.create_topology_router(
                r_name, routers_client=self.routers_client)
            s_name = "uniscale-{}-{}-subnet".format(val, name)
            self.create_topology_subnet(s_name, network[val],
                                        routers_client=self.routers_client,
                                        subnets_client=self.subnets_client,
                                        router_id=router['id'])
        # Verifying the count of subnets
        subnets = [i for i in self.subnets_client.list_subnets()['subnets']
                   if name in i['name']]
        self.assertEqual(len(subnets), scale,
                         "The provider subnets counte doesnt equal scale")
        nsx_subnets = [i for i in self.nsx.get_logical_dhcp_servers()
                       if i['resource_type'] == "LogicalDhcpServer"]
        scale_nsx_subnets = [j for j in nsx_subnets
                             if name in j['display_name']]
        self.assertEqual(len(scale_nsx_subnets), scale,
                         "The Subnets counts doesnt match the scale value")

        # Verifying the count of routers on backend and on the neutron db
        scale_rtrs = [rtr for rtr in router['routers']
                      if name in rtr['name']]
        error_msg = "Neutron routers created doesn't match the scale number"
        self.assertEqual(len(scale_rtrs), scale, error_msg)
        nsx_routers = self.nsx.get_logical_routers()
        scale_routers = \
            [lr for lr in nsx_routers
             if lr['display_name'].
             startswith('uniscale') and name in lr['display_name']]
        error_msg = ("Logical routers on backend doesn't match the "
                     "number of routers on OpenStack")
        self.assertIsNotNone(len(scale_routers), error_msg)

        # Creating sgs
        kwargs = dict(tenant_id=network[0]['tenant_id'],
                      security_group_rules_client=self.sec_rule_client,
                      security_groups_client=self.sec_client)
        self.sg = self.create_topology_security_group(**kwargs)

        # create vms under random subnets
        for val in range(scale):
            if val % 100:
                self.create_topology_instance(
                    "vm{}".format(val), [network[val]],
                    security_groups=[{'name': self.sg['name']}],
                    clients=self.cmgr_adm)
        # verify connectivity between vms
        self.ping_between_vms_different_router_uniscale()

    def _verify_connectivity_vms_single_routers(self, scale, name):
        """
         create vms under vlan networks randomly and check connectiviy
        """
        network = [i for i in self.networks_client.list_networks()['networks']
                   if name in i['name']]
        r_name = "uniscale-{}-router".format(name)
        router = self.create_topology_router(
            r_name, routers_client=self.routers_client)

        for val in range(scale):
            s_name = "uniscale-{}-{}-subnet".format(val, name)
            self.create_topology_subnet(
                s_name, network[val], routers_client=self.routers_client,
                subnets_client=self.subnets_client, router_id=router['id'])
        # Verifying the count of subnets
        subnets = [i for i in self.subnets_client.list_subnets()['subnets']
                   if name in i['name']]
        self.assertEqual(len(subnets), scale,
                         "The provider subnets counte doesnt equal scale")
        nsx_subnets = [i for i in self.nsx.get_logical_dhcp_servers()
                       if i['resource_type'] == "LogicalDhcpServer"]
        scale_nsx_subnets = [j for j in nsx_subnets
                             if name in j['display_name']]
        self.assertEqual(len(scale_nsx_subnets), scale,
                         "The Subnets counts doesnt match the scale value")
        # Creating sgs
        kwargs = dict(tenant_id=network[0]['tenant_id'],
                      security_group_rules_client=self.sec_rule_client,
                      security_groups_client=self.sec_client)
        self.sg = self.create_topology_security_group(**kwargs)

        for val in range(scale):
            if val % 100:
                self.create_topology_instance(
                    "vm{}".format(val), [network[val]],
                    security_groups=[{'name': self.sg['name']}],
                    clients=self.cmgr_adm)
        # append vm to the list vms
        self.ping_between_vms_different_router_uniscale()

    def _create_scale_vxlan_provider_networks(self, scale, name):
        """
        Create provider networks as per the scale parameter
        value passed
        """
        for value in range(scale):
            namex = "uniscale-{}-{}-network".format(value, name)
            body = {"provider:network_type": constants.VXLAN_TYPE,
                    "admin_state_up": 'True'}
            self.create_topology_network(
                namex, networks_client=self.networks_client, **body)

        networks = [i for i in self.networks_client.list_networks()['networks']
                    if name in i['name']]
        error_msg = "The count mismatch of neutron networks with scale counts"
        self.assertEqual(len(networks), scale, error_msg)
        ls = self.nsx.get_logical_resources("/logical-switches")
        nsx_networks = [val for val in ls
                        if val['resource_type'] == "LogicalSwitch"]
        nsx_scale_networks = [val for val in nsx_networks
                              if name in val['display_name']]
        self.assertEqual(len(nsx_scale_networks), scale, error_msg)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2cbc2a64-daab-451f-ad3b-f0713a390f47')
    def test_create_1k_provider_vlan_networks(self):
        self._create_scale_vlan_provider_networks(1000,
                                                  name="provider-vlan")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2cbc2a64-addb-451f-ad3b-f0713a390f47')
    def test_create_2k_provider_vlan_networks(self):
        self._create_scale_vlan_provider_networks(2000,
                                                  name="provider-vlan")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2cbc2a64-bada-f154-ad3b-f0713a390f47')
    def test_connectivity_between_vms_different_router_vlan_provider(self):
        self._create_scale_vlan_provider_networks(1000,
                                                  name="provider-vlan")
        self._verify_connectivity_vms_different_routers(1000,
                                                        name="provider-vlan")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2cbc2a64-daba-415f-3bda-f0713a390f47')
    def test_connectivity_between_vms_single_router_vlan_provider(self):
        self._create_scale_vlan_provider_networks(1000,
                                                  name="provider-vlan")
        self._verify_connectivity_vms_single_routers(1000,
                                                     name="provider-vlan")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2cbc2a64-daab-451f-ad3b-170f3a390f47')
    def test_create_1k_provider_vxlan_networks(self):
        self._create_scale_vxlan_provider_networks(1000,
                                                   name="provider-vxlan")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2cbc2a64-daab-451f-ad3b-170f393a0f47')
    def test_create_2k_provider_vxlan_networks(self):
        self._create_scale_vxlan_provider_networks(2000,
                                                   name="provider-vxlan")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c2b264a2-daab-451f-ad3b-f0713a39740f')
    def test_connectivity_between_vms_different_router_vxlan_provider(self):
        self._create_scale_vxlan_provider_networks(1000,
                                                   name="provider-vxlan")
        self._verify_connectivity_vms_different_routers(1000,
                                                        name="provider-vxlan")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c2b264a2-daab-451f-ad3b-74f093a3170f')
    def test_connectivity_between_vms_single_router_vxlan_provider(self):
        self._create_scale_vxlan_provider_networks(1000,
                                                   name="provider-vxlan")
        self._verify_connectivity_vms_single_routers(1000,
                                                     name="provider-vxlan")

# Copyright 2017 VMware Inc
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

from tempest import config
from tempest.lib import decorators
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF
LOG = constants.log.getLogger(__name__)


class ProviderNetworkScenario(feature_manager.FeatureManager):
    """Test Provider Physical Networks Scenario

    """

    @classmethod
    def skip_checks(cls):
        super(ProviderNetworkScenario, cls).skip_checks()
        if not test.is_extension_enabled('provider', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(ProviderNetworkScenario, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(ProviderNetworkScenario, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)
        out = cls.nsx.get_transport_zones()
        vlan_flag = 0
        vxlan_flag = 0
        for tz in out:
            if "transport_type" in tz.keys() and (vlan_flag == 0
                                                  or vxlan_flag == 0):
                if vxlan_flag == 0 and tz['transport_type'] == "OVERLAY":
                    cls.overlay_id = tz['id']
                    vxlan_flag = 1
                if vlan_flag == 0 and tz['transport_type'] == "VLAN":
                    cls.vlan_id = tz['id']
                    vlan_flag = 1

    def _create_provider_network(self, tz_id, net_type,
                                 admin_state_up=True):
        networks_client = self.cmgr_adm.networks_client
        if net_type == constants.VXLAN_TYPE:
            name = "network"
            body = {"provider:physical_network": tz_id,
                    "provider:network_type": net_type,
                    "admin_state_up": admin_state_up}
        elif net_type == constants.VLAN_TYPE:
            name = "network"
            body = {"provider:segmentation_id": 1001,
                    "provider:network_type": net_type,
                    "provider:physical_network": tz_id,
                    "admin_state_up": admin_state_up}
        network = self.create_topology_network(name, networks_client, **body)
        return network

    def provider_network_topology1(self):
        sec_rule_client = self.cmgr_adm.security_group_rules_client
        sec_client = self.cmgr_adm.security_groups_client
        network = self._create_provider_network(self.overlay_id,
                                                constants.VXLAN_TYPE)
        kwargs = dict(tenant_id=network['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        routers_client = self.cmgr_adm.routers_client
        router_name = 'router'
        router = self.create_topology_router(router_name,
                                             routers_client=routers_client)
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network['name'] + 'sub'
        self.create_topology_subnet(subnet_name, network,
                                    routers_client=routers_client,
                                    subnets_client=subnet_client,
                                    router_id=router['id'])
        self.create_topology_instance(
            "server1", [network],
            security_groups=[{'name': self.sg['name']}],
            clients=self.cmgr_adm)
        self.create_topology_instance(
            "server2", [network],
            security_groups=[{'name': self.sg['name']}],
            clients=self.cmgr_adm)

    def provider_network_topology2(self):
        sec_rule_client = self.cmgr_adm.security_group_rules_client
        sec_client = self.cmgr_adm.security_groups_client
        network1 = self._create_provider_network(self.overlay_id,
                                                 constants.VXLAN_TYPE)
        kwargs = dict(tenant_id=network1['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        routers_client = self.cmgr_adm.routers_client
        router_name = 'router'
        router = self.create_topology_router(router_name,
                                             routers_client=routers_client)
        subnet_client = self.cmgr_adm.subnets_client
        network2 = self._create_provider_network(self.overlay_id,
                                                 constants.VXLAN_TYPE)
        subnet_name1 = network1['name'] + 'sub1'
        subnet_name2 = network2['name'] + 'sub2'
        self.create_topology_subnet(subnet_name1, network1,
                                    routers_client=routers_client,
                                    subnets_client=subnet_client,
                                    router_id=router['id'],
                                    cidr='23.0.0.0/24')
        self.create_topology_subnet(subnet_name2, network2,
                                    routers_client=routers_client,
                                    subnets_client=subnet_client,
                                    router_id=router['id'],
                                    cidr='24.0.0.0/24')
        self.create_topology_instance(
            "server1", [network1],
            security_groups=[{'name': self.sg['name']}],
            clients=self.cmgr_adm)
        self.create_topology_instance(
            "server2", [network2],
            security_groups=[{'name': self.sg['name']}],
            clients=self.cmgr_adm)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('244b51c0-b758-49bc-bcaa-9de744322665')
    def test_provider_vxlan_same_network_same_cidr_scenario(self):
        self.provider_network_topology1()
        self.check_cross_network_connectivity(
            self.topology_networks["network"],
            self.servers_details["server1"].floating_ips[0],
            self.servers_details["server1"].server, should_connect=True)
        self.check_cross_network_connectivity(
            self.topology_networks["network"],
            self.servers_details["server2"].floating_ips[0],
            self.servers_details["server2"].server, should_connect=True)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('456b51c0-b758-49bc-bcaa-9de744322123')
    def test_provider_vxlan_differnet_network_different_cidr_scenario(self):
        self.provider_network_topology2()
        self.check_cross_network_connectivity(
            self.topology_networks["network"],
            self.servers_details["server1"].floating_ips[0],
            self.servers_details["server1"].server, should_connect=True)
        self.check_cross_network_connectivity(
            self.topology_networks["network"],
            self.servers_details["server2"].floating_ips[0],
            self.servers_details["server2"].server, should_connect=True)

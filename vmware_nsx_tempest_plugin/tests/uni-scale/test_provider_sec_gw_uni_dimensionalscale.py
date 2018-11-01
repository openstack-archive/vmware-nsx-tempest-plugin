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


class ProviderSecGrpUnidimensionalScaleTest(feature_manager.FeatureManager):

    """Test Uni Dimesional Case for
       Logical-security-groups
       Logical-security-group-rules

    """
    @classmethod
    def setup_clients(cls):
        super(ProviderSecGrpUnidimensionalScaleTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(ProviderSecGrpUnidimensionalScaleTest, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _create_topology_tier1_with_vms(self, no_of_entites, no_of_ports):
        name = 'pro-sec-router'
        router = self.create_topology_router(router_name=name)
        for i in range(no_of_entites):
            name = 'uniscale-%s-net' % i
            network = self.create_topology_network(network_name=name)
            sub_name = 'uniscale-%s-sub' % i
            self.create_topology_subnet(
                sub_name,
                network,
                router_id=router['id'])
            self.create_topology_instance(
                "server_pro_%s" % i, [network])

            for j in range(no_of_ports):
                kwargs = {"port_security_enabled": "true",
                          "security_groups": []}
                self.create_topology_port(
                    network, ports_client=self.cmgr_adm.ports_client, **kwargs)

    def _create_scale_logical_security_groups(self, scale):
        i = 100
        for num in range(scale):
            sg = self.create_topology_security_provider_group(self.cmgr_adm,
                                                              provider=True)
            sw_rules = [dict(direction='ingress', protocol='icmp',
                             port_range_min=i + 1,
                             port_range_max=i + 1, )]
            for rule in sw_rules:
                self.add_security_group_rule(sg, rule)
        provider_sec = self.security_group_rules_client.list_security_groups(
        )
        error_msg = "Neutron provider sec group doesn't created"
        self.assertIsNotNone(len(provider_sec), error_msg)
        nsx_firewall = self.nsx.get_firewall_sections()
        sec_group = [dfw for dfw in nsx_firewall
                     if sg['name'] in dfw['display_name']][0]
        self.assertIsNotNone(len(sec_group))
        nsx_firewall = self.nsx.get_firewall_section_rules(sec_group)
        scale_firewall_rule = [dfw for dfw in nsx_firewall
                               if dfw['id'] is not None]
        self.assertIsNotNone(len(scale_firewall_rule))

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('a12264a2-daab-451f-ad3b-f0713a390123')
    def test_create_10_provider_groups_100_ports_1_switch(self):
        self._create_scale_logical_security_groups(10)
        self._create_topology_tier1_with_vms(1, 100)
    # Check vms connectivity from outside world when provider-sec group enabled
        self.ping_between_vms_different_router_uniscale(icmp_succeed=False)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b1222b0f-4593-4509-8998-a3002ce63231')
    def test_create_10_provider_groups_1000_ports_1_switch(self):
        self._create_scale_logical_security_groups(10)
        self._create_topology_tier1_with_vms(1, 1000)
    # Check vms connectivity from outside world when provider-sec group enabled
        self.ping_between_vms_different_router_uniscale(icmp_succeed=False)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b1222b0f-4593-4509-8998-a3002ce63981')
    def test_create_100_provider_groups_100_ports_1_switch(self):
        self._create_scale_logical_security_groups(100)
        self._create_topology_tier1_with_vms(1, 100)
    # Check vms connectivity from outside world when provider-sec group enabled
        self.ping_between_vms_different_router_uniscale(icmp_succeed=False)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b1222b0f-4593-4509-8998-a3002ce63009')
    def test_create_100_provider_groups_1000_ports_1_switch(self):
        self._create_scale_logical_security_groups(100)
        self._create_topology_tier1_with_vms(1, 1000)
    # Check vms connectivity from outside world when provider-sec group enabled
        self.ping_between_vms_different_router_uniscale(icmp_succeed=False)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b1222b0f-4593-4509-8998-a3002ce63341')
    def test_create_10_provider_groups_100_ports_switch_10(self):
        self._create_scale_logical_security_groups(10)
        self._create_topology_tier1_with_vms(10, 100)
    # Check vms connectivity from outside world when provider-sec group enabled
        self.ping_between_vms_different_router_uniscale(icmp_succeed=False)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b1222b0f-4593-4509-8998-a3002c345406')
    def test_create_1000_provider_groups_100_ports_10_switch(self):
        self._create_scale_logical_security_groups(1000)
        self._create_topology_tier1_with_vms(10, 100)
    # Check vms connectivity from outside world when provider-sec group enabled
        self.ping_between_vms_different_router_uniscale(icmp_succeed=False)

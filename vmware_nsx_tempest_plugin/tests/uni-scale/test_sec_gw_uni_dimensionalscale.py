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


class SecGroupUnidimensionalScaleTest(feature_manager.FeatureManager):

    """Test Uni Dimesional Case for
       Logical-security-groups
       Logical-security-group-rules

    """
    @classmethod
    def setup_clients(cls):
        super(SecGroupUnidimensionalScaleTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(SecGroupUnidimensionalScaleTest, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _create_scale_logical_security_groups(self, scale):
        # Create networks based on scale number
        for i in range(scale):
            name = 'uniscale-%s-net' % i
            self.create_topology_empty_security_group(namestart=name)

        sec_groups = self.security_groups_client.list_security_groups()
        error_msg = "Neutron sec group rules doesn't created"
        self.assertIsNotNone(len(sec_groups), error_msg)
        nsx_firewall = self.nsx.get_firewall_sections()
        scale_firewall = \
            [dfw for dfw in nsx_firewall
             if dfw['display_name'].startswith('tempest-uniscale-')]
        error_msg = ("Logical  on backend doesn't match the "
                     "number of routers on OpenStack")
        self.assertIsNotNone(len(scale_firewall), error_msg)

    def _create_scale_logical_security_group_rules(self, scale):
        sg = self.create_topology_security_group()
        self.create_topology_network("network_sw_1")
        for i in range(scale):
            if i % 2 == 0:
                protocol = 'tcp'
            else:
                protocol = 'udp'
            sw_rules = [dict(direction='ingress', protocol=protocol,
                             port_range_min=i + 1,
                             port_range_max=i + 1, )]
            try:
                for rule in sw_rules:
                    self.add_security_group_rule(sg, rule)
            except:
                pass
        sec_rules = self.security_group_rules_client.list_security_group_rules(
        )
        error_msg = "Neutron sec group rules doesn't created"
        self.assertIsNotNone(len(sec_rules), error_msg)
        nsx_firewall = self.nsx.get_firewall_sections()
        sec_group = [dfw for dfw in nsx_firewall
                     if sg['name'] in dfw['display_name']][0]
        self.assertIsNotNone(len(sec_group))
        nsx_firewall = self.nsx.get_firewall_section_rules(sec_group)
        scale_firewall_rule = [dfw for dfw in nsx_firewall
                               if dfw['id'] is not None]
        self.assertIsNotNone(len(scale_firewall_rule))

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('a12264a2-daab-451f-ad3b-f0713a390f47')
    def test_create_500_dfw_groups(self):
        self._create_scale_logical_security_groups(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b1222b0f-4593-4509-8998-a3002ce63406')
    def test_create_1k_dfw_groups(self):
        self._create_scale_logical_security_groups(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c123d789-838a-428a-b4fe-8fe214f0e956')
    def test_create_2k_dfw_groups(self):
        self._create_scale_logical_security_groups(2000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('d12441be-a700-45fa-bec1-b1d100acbb73')
    def test_create_4k_dfw_groups(self):
        self._create_scale_logical_security_groups(4000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('e12484e3-f9b8-4562-8a4c-d8974a703767')
    def test_create_1000_dfw_group_ruless(self):
        self._create_scale_logical_security_group_rules(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f128af8c-db3a-4ad2-8954-c41670956c52')
    def test_create_2000_dfw_group_ruless(self):
        self._create_scale_logical_security_group_rules(2000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('g125db0b-5922-494d-bcd3-9d5b0b10b684')
    def test_create_4000_dfw_group_ruless(self):
        self._create_scale_logical_security_group_rules(4000)

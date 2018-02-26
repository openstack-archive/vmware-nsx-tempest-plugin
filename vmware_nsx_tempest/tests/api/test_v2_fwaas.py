# Copyright 2018 VMware Inc
# All Rights Reserved.
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
from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest.lib.common.utils import data_utils
from tempest import test

from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsx_client


CONF = config.CONF
CONF.validation.auth_method = 'None'

LOG = logging.getLogger(__name__)


class TestFwaasV2Ops(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestFwaasV2Ops, cls).skip_checks()
        if not test.is_extension_enabled('fwaasv2', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        cls.admin_mgr = cls.get_client_manager('admin')
        super(TestFwaasV2Ops, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestFwaasV2Ops, cls).setup_clients()
        cls.nsx_client = nsx_client.NSXClient(
            CONF.network.backend,
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)

    def create_fw_basic_topo(self, protocol_name=None):
        if protocol_name is None:
            protocol_name = 'icmp'
        rule_name = data_utils.rand_name('fw-rule-')
        # Create firewall rule
        fw_rules = self.create_firewall_rule(name=rule_name,
                                             protocol=protocol_name)
        rules = []
        show_rules = self.show_firewall_rule(fw_rules['firewall_rule']['id'])
        # Check firewall rule
        self.assertEqual(show_rules.get('firewall_rule')['name'], rule_name)
        self.assertEqual(show_rules.get('firewall_rule')['protocol'],
                         protocol_name)
        # Update firewall rule
        self.update_firewall_rule(
            fw_rules['firewall_rule']['id'],
            protocol='tcp')
        self.update_firewall_rule(
            fw_rules['firewall_rule']['id'],
            name='new-rule')
        show_rules = self.show_firewall_rule(fw_rules['firewall_rule']['id'])
        # Check firewall rule after updated value
        self.assertEqual(show_rules.get('firewall_rule')['name'], 'new-rule')
        self.assertEqual(show_rules.get('firewall_rule')['protocol'],
                         'tcp')
        rules.append(fw_rules['firewall_rule']['id'])
        policy_name = data_utils.rand_name('fw-policy-')
        # Create firewall policy
        fw_policy = self.create_firewall_policy(name=policy_name,
                                                firewall_rules=rules)
        show_policy = self.show_firewall_policy(
            fw_policy['firewall_policy']['id'])
        # Check firewall policy
        self.assertEqual(
            show_policy.get('firewall_policy')['name'],
            policy_name)
        self.assertEqual(show_policy.get('firewall_policy')
                         ['firewall_rules'], rules)
        # Update firewall policy
        self.update_firewall_policy(fw_policy['firewall_policy']['id'],
                                    name='new-policy')
        show_policy = self.show_firewall_policy(
            fw_policy['firewall_policy']['id'])
        # Check firewall policy
        self.assertEqual(
            show_policy.get('firewall_policy')['name'],
            'new-policy')
        policy_id = fw_policy['firewall_policy']['id']
        group_name = data_utils.rand_name('fw-group-')
        # Create firewall group
        fw_group = self.create_firewall_group(
            name=group_name,
            ingress_firewall_policy_id=policy_id,
            egress_firewall_policy_id=policy_id)
        show_group = self.show_firewall_group(fw_group["firewall_group"]["id"])
        # Check firewall group values
        self.assertEqual(show_group.get('firewall_group')['name'], group_name)
        self.assertEqual(show_group.get('firewall_group')[
                         'ingress_firewall_policy_id'], policy_id)
        self.assertEqual(show_group.get('firewall_group')[
                         'egress_firewall_policy_id'], policy_id)
        fw_topo = dict(fw_rules=fw_rules, fw_policy=fw_policy,
                       fw_group=fw_group)
        return fw_topo

    def create_fw_group_port_topo(
            self,
            group_delete=True,
            project_id=None,
            ports=None,
            protocol_name=None):
        if protocol_name is None:
            protocol_name = 'icmp'
        rule_name = data_utils.rand_name('fw-rule-')
        # Create firewall rule
        fw_rules = self.create_firewall_rule(
            name=rule_name, protocol=protocol_name, project_id=project_id)
        rules = []
        show_rules = self.show_firewall_rule(fw_rules['firewall_rule']['id'])
        # Check firewall rule
        self.assertEqual(show_rules.get('firewall_rule')['name'], rule_name)
        self.assertEqual(show_rules.get('firewall_rule')['protocol'],
                         protocol_name)
        rules.append(fw_rules['firewall_rule']['id'])
        policy_name = data_utils.rand_name('fw-policy-')
        # Create firewall policy
        fw_policy = self.create_firewall_policy(name=policy_name,
                                                firewall_rules=rules,
                                                project_id=project_id)
        show_policy = self.show_firewall_policy(
            fw_policy['firewall_policy']['id'])
        # Check firewall policy
        self.assertEqual(
            show_policy.get('firewall_policy')['name'],
            policy_name)
        self.assertEqual(show_policy.get('firewall_policy')
                         ['firewall_rules'], rules)
        policy_id = fw_policy['firewall_policy']['id']
        group_name = data_utils.rand_name('fw-group-')
        # Create firewall group
        fw_group = self.create_firewall_group(
            name=group_name,
            ingress_firewall_policy_id=policy_id,
            egress_firewall_policy_id=policy_id,
            ports=ports,
            project_id=project_id)
        self._wait_firewall_ready(fw_group["firewall_group"]["id"])
        show_group = self.show_firewall_group(fw_group["firewall_group"]["id"])
        self.assertEqual(show_group.get('firewall_group')['ports'], ports)
        if group_delete is True:
            # Update firewall group
            self.update_firewall_group(fw_group["firewall_group"]["id"],
                                       ports=[])
            # Check updated values of firewall group
            self.assertEqual(
                show_group.get('firewall_group')['name'],
                group_name)
            self.assertEqual(show_group.get('firewall_group')[
                             'ingress_firewall_policy_id'], policy_id)
            self.assertEqual(show_group.get('firewall_group')[
                             'egress_firewall_policy_id'], policy_id)
            # Delete firewall group
            self.fwaas_v2_client.delete_firewall_v2_group(
                fw_group["firewall_group"]["id"])
        else:
            fw_topo = dict(fw_rules=fw_rules, fw_policy=fw_policy,
                           fw_group=fw_group)
            return fw_topo

    def create_fw_with_port_topology(self, group_delete, protocol_name):
        # Create network topo
        network = \
            self.create_topology_network(network_name="fw-network")
        router_name = 'fw-router'
        # Create router topo
        router = self.create_topology_router(router_name)
        subnet_name = 'fw-subnet'
        # Create subnet topo
        self.create_topology_subnet(subnet_name, network,
                                    router_id=router['id'])
        p_client = self.ports_client
        ports = []
        ports.append(self.get_router_port(p_client))
        if not group_delete:
            fw_topo = self.create_fw_group_port_topo(
                group_delete, network['project_id'], ports, protocol_name)
            return fw_topo
        else:
            self.create_fw_group_port_topo(
                group_delete, network['project_id'], ports, protocol_name)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('431288d7-9213-4b1e-a11d-15840c8e2f12')
    def test_fwaas_basic_icmp(self):
        """
        Test fwaasv2 api to create icmp rule/policy/group and update it and
        verifying its values
        """
        self.create_fw_basic_topo('icmp')

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('76a188d7-9812-5b1e-a11d-65840c9e2fd6')
    def test_fwaas_basic_tcp(self):
        """
        Test fwaasv2 api to create tcp rule/policy/group and update it and
        verifying its values
        """
        self.create_fw_basic_topo('tcp')

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('a5b188d7-0183-4b1e-9111-15840c8e2fd6')
    def test_fwaas_basic_udp(self):
        """
        Test fwaasv2 api to create udp rule/policy/group and update it and
        verifying its values
        """
        self.create_fw_basic_topo('udp')

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('95b188d7-0183-4b1e-a11d-15840c8e2345')
    def test_fwaas_router_port_icmp(self):
        """
        Test fwaasv2 api to create icmp rule/policy/group with router port and
        update it and verifying its values
        """
        self.create_fw_with_port_topology('icmp')

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('25b188d7-0183-4b1e-5123-15840c8e2fd6')
    def test_fwaas_router_port_tcp(self):
        """
        Test fwaasv2 api to create tcp rule/policy/group with router port and
        update it and verifying its values
        """
        self.create_fw_with_port_topology('tcp')

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('501288d7-0183-4b1e-a11d-15840c8e2fd6')
    def test_fwaas_router_port_udp(self):
        """
        Test fwaasv2 api to create udp rule/policy/group with router port and
        update it and verifying its values
        """
        self.create_fw_with_port_topology('udp')

    @decorators.attr(type='nsxv3')
    @decorators.attr(type=["negative"])
    @decorators.idempotent_id('434588d7-0183-4b12-a11d-15840c8e2fd6')
    def test_delete_fw_group_when_port_in_use(self):
        """
        Try to delete firewall group when its in use
        """
        fw_topo = self.create_fw_with_port_topology(
            group_delete=False, protocol_name='icmp')
        self.assertRaises(exceptions.Conflict,
                          self.fwaas_v2_client.delete_firewall_v2_group,
                          fw_topo["fw_group"]["firewall_group"]["id"])
        self.update_firewall_group(fw_topo["fw_group"]["firewall_group"]["id"],
                                   ports=[])
        self.fwaas_v2_client.delete_firewall_v2_group(
            fw_topo["fw_group"]["firewall_group"]["id"])

    @decorators.attr(type='nsxv3')
    @decorators.attr(type=["negative"])
    @decorators.idempotent_id('201228d7-0183-4b1e-a11d-35821c8e2fd6')
    def test_delete_fw_rule_when_in_use(self):
        """
        Try to delete firewall rule when its in use
        """
        fw_topo = self.create_fw_basic_topo('icmp')
        self.assertRaises(exceptions.Conflict,
                          self.fwaas_v2_client.delete_firewall_v2_rule,
                          fw_topo["fw_rules"]["firewall_rule"]["id"])

    @decorators.attr(type='nsxv3')
    @decorators.attr(type=["negative"])
    @decorators.idempotent_id('901488d7-1184-4b1e-511d-15878c8e2fd6')
    def test_delete_fw_policy_when_in_use(self):
        """
        Try to delete firewall policy when its in use
        """
        fw_topo = self.create_fw_basic_topo('icmp')
        self.assertRaises(exceptions.Conflict,
                          self.fwaas_v2_client.delete_firewall_v2_policy,
                          fw_topo["fw_policy"]["firewall_policy"]["id"])

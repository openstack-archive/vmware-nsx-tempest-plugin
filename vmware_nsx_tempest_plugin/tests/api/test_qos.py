# Copyright 2017 VMware, Inc.
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

import testtools
import time

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.services import nsxp_client
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services.qos import base_qos

CONF = config.CONF


class BaseQosTest(base.BaseAdminNetworkTest):
    """Base class for Qos Test.

    1. Setup QoS clients for admin and primary users.
    2. Manages qos resources creation and deletion.
    3. Manages network/port creation and deletion as network cannot be
       deleted if ports are associated which test framework won't handle.
    """

    @classmethod
    def skip_checks(cls):
        """skip tests if qos is not enabled."""
        super(BaseQosTest, cls).skip_checks()
        if not test.is_extension_enabled('qos', 'network'):
            msg = "q-qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(BaseQosTest, cls).resource_setup()
        cls.admin_mgr = cls.get_client_manager(credential_type='admin')
        cls.primary_mgr = cls.get_client_manager()
        cls.adm_qos_client = base_qos.BaseQosClient(cls.admin_mgr)
        cls.pri_qos_client = base_qos.BaseQosClient(cls.primary_mgr)
        cls.qos_available_rule_types = (
            cls.adm_qos_client.available_rule_types())
        cls.policies_created = []
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)
        cls.nsxp = nsxp_client.NSXPClient(CONF.nsxv3.nsx_manager,
                                          CONF.nsxv3.nsx_user,
                                          CONF.nsxv3.nsx_password)

    @classmethod
    def resource_cleanup(cls):
        """cleanup resources handled by base class."""
        super(BaseQosTest, cls).resource_cleanup()

    @classmethod
    def create_port(cls, network, client_mgr=None, **kwargs):
        """create port."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        body = client_mgr.ports_client.create_port(
            network_id=network['id'], **kwargs)
        port = body.get('port', body)
        cls.ports = []
        cls.ports.append(port)
        return port

    @classmethod
    def update_port(cls, port_id, client_mgr=None, **kwargs):
        """update port."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        body = client_mgr.ports_client.update_port(
            port_id, **kwargs)
        return body.get('port', body)

    @classmethod
    def show_port(cls, port_id, client_mgr=None):
        """show port."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        body = client_mgr.ports_client.show_port(port_id)
        return body.get('port', body)

    @classmethod
    def delete_port(cls, port_id, client_mgr=None, **kwargs):
        """delete port."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        body = client_mgr.ports_client.delete_port(port_id)
        return body.get('port', body)

    @classmethod
    def create_network(cls, network_name=None, client_mgr=None, **kwargs):
        """create network."""
        network_name = network_name or data_utils.rand_name('qos-net')
        client_mgr = client_mgr if client_mgr else cls.admin_mgr

        body = client_mgr.networks_client.create_network(
            name=network_name, **kwargs)
        network = body['network']
        return network

    @classmethod
    def create_shared_network(cls, network_name=None, client_mgr=None,
                              **kwargs):
        """create shared network."""
        return cls.create_network(network_name, client_mgr,
                                  shared=True, **kwargs)

    @classmethod
    def show_network(cls, network_id, client_mgr=None):
        """show network."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        network = client_mgr.networks_client.show_network(network_id)
        return network.get('network', network)

    @classmethod
    def update_network(cls, network_id, client_mgr=None, **kwargs):
        """update network."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        network = client_mgr.networks_client.update_network(
            network_id, **kwargs)
        return network.get('network', network)

    @classmethod
    def delete_network(cls, network_id, client_mgr=None):
        """delete network."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        network = client_mgr.networks_client.delete_network(network_id)
        return network.get('network', network)

    @classmethod
    def create_qos_policy(cls, name='test-policy',
                          description='test policy desc',
                          shared=False,
                          qos_client=None, **kwargs):
        """create qos policy."""
        qos_client = qos_client if qos_client else cls.adm_qos_client
        policy = qos_client.create_policy(
            name=name, description=description,
            shared=shared, **kwargs)
        cls.policies_created.append(policy)
        return policy

    @classmethod
    def create_qos_bandwidth_limit_rule(cls, policy_id,
                                        qos_client=None, **kwargs):
        """create qos-bandwidth-limit-rule."""
        qos_client = qos_client if qos_client else cls.adm_qos_client
        rule = qos_client.create_bandwidth_limit_rule(policy_id, **kwargs)
        return rule

    @classmethod
    def create_qos_dscp_marking_rule(cls, policy_id, dscp_mark,
                                     qos_client=None, **kwargs):
        """create qos-dscp-marking-rule."""
        qos_client = qos_client if qos_client else cls.adm_qos_client
        rule = qos_client.create_dscp_marking_rule(
            policy_id, dscp_mark, **kwargs)
        return rule

    def verify_backend(self, policy):
        """Verify backend NSXT for the policy created."""
        #check backend if the policy was created
        msg = 'QoS Policy %s not found' % policy['name']
        time.sleep(constants.NSXP_BACKEND_SMALL_TIME_INTERVAL)
        self.assertIsNotNone(self.nsxp.get_qos_profile(
                             policy['name'], policy['id']), msg)
        #Checking the MP backend for qos profiles
        self.assertIsNotNone(self.nsx.get_qos_profile(
                             policy['name'], policy['id']), msg)

    def verify_backend_port(self, policy, network, port):
        """Verify backend NSXT port is updated with qos policy."""
        #check backend if the policy was created
        msg = 'QoS Policy %s not attached to the port' % policy['name']
        time.sleep(constants.NSXP_BACKEND_SMALL_TIME_INTERVAL)
        segment = self.nsxp.get_logical_switch(network['name'], network['id'])
        self.assertEqual(policy['id'],
                         self.nsxp.get_port_qos_profile_binding_map(
                         segment['id'], port['id']), msg)

    def verify_backend_bandwidth_rule(self, policy, rule):
        """Verify backend NSXT for the rule created."""
        #check backend if the rule was created
        msg = 'QoS Rule %s not found' % rule['id']
        time.sleep(constants.NSXP_BACKEND_SMALL_TIME_INTERVAL)
        rule_backend = self.nsxp.get_qos_profile(policy['name'], policy['id'])
        self.assertEqual((rule['max_kbps'] / 1000) * 2,
            rule_backend['shaper_configurations'][0]['peak_bandwidth'], msg)
        self.assertEqual((rule['max_kbps'] / 1000),
            rule_backend['shaper_configurations'][0]['average_bandwidth'], msg)
        if rule['direction'] == 'egress':
            self.assertEqual('IngressRateLimiter',
                rule_backend['shaper_configurations'][0]['resource_type'], msg)
        else:
            self.assertEqual('EgressRateLimiter',
                rule_backend['shaper_configurations'][0]['resource_type'], msg)

    def verify_backend_bandwidth_rules(self, policy, rule, index):
        """Verify backend NSXT for the rule created."""
        #check backend if the rule was created
        msg = 'QoS Rule %s not found' % rule['id']
        time.sleep(constants.NSXP_BACKEND_SMALL_TIME_INTERVAL)
        rules_backend = self.nsxp.get_qos_profile(policy['name'], policy['id'])
        self.assertEqual((rule['max_kbps'] / 1000) * 2,
            rules_backend['shaper_configurations'][index]['peak_bandwidth'],
            msg)
        self.assertEqual((rule['max_kbps'] / 1000),
            rules_backend['shaper_configurations'][index]['average_bandwidth'],
            msg)
        if rule['direction'] == 'egress':
            self.assertEqual('IngressRateLimiter',
                rules_backend['shaper_configurations'][index]['resource_type'],
                msg)
        else:
            self.assertEqual('EgressRateLimiter',
                rules_backend['shaper_configurations'][index]['resource_type'],
                msg)

    def verify_backend_dscp_rule(self, policy, rule):
        """Verify backend NSXT for the rule created."""
        #check backend if the rule was created
        msg = 'QoS Rule %s not found' % rule['id']
        time.sleep(constants.NSXP_BACKEND_SMALL_TIME_INTERVAL)
        rule_backend = self.nsxp.get_qos_profile(policy['name'], policy['id'])
        self.assertEqual(rule['dscp_mark'], rule_backend['dscp']['priority'], msg)


class QosPolicyTest(BaseQosTest):
    """QoS Policy CURD operations.

    test qos policies and network/port association and disassociation.
    """

    @decorators.idempotent_id('108fbdf7-3463-4e47-9871-d07f3dcf5bbb')
    def test_create_policy(self):
        """qos-policy-create: create policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy desc1',
                                        shared=False)

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        # Test 'show policy'
        retrieved_policy = self.adm_qos_client.show_policy(policy['id'])
        self.assertEqual('test-policy', retrieved_policy['name'])
        self.assertEqual('test policy desc1',
                         retrieved_policy['description'])
        self.assertFalse(retrieved_policy['shared'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        # Test 'list policies'
        policies = self.adm_qos_client.list_policies()
        policies_ids = [p['id'] for p in policies]
        self.assertIn(policy['id'], policies_ids)

    @decorators.idempotent_id('f8d20e92-f06d-4805-b54f-230f77715815')
    def test_list_policy_filter_by_name(self):
        """qos-policy-list --name=<name>: list policies."""
        name1 = data_utils.rand_name('test-policy')
        name2 = name1 + "0"
        policy_name1 = self.create_qos_policy(
            name=name1, description='test policy', shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy_name1['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy_name1)
        policy_name2 = self.create_qos_policy(
            name=name2, description='test policy', shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy_name2['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy_name2)
        policies = self.adm_qos_client.list_policies(name=name1)
        self.assertEqual(1, len(policies))

        retrieved_policy = policies[0]
        self.assertEqual(name1, retrieved_policy['name'])

    @decorators.idempotent_id('8e88a54b-f0b2-4b7d-b061-a15d93c2c7d6')
    def test_policy_update(self):
        """qos-policy-update POLICY_ID."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        self.adm_qos_client.update_policy(policy['id'],
                                          description='test policy desc2',
                                          shared=True)
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)

        retrieved_policy = self.adm_qos_client.show_policy(policy['id'])
        self.assertEqual('test policy desc2',
                         retrieved_policy['description'])
        self.assertTrue(retrieved_policy['shared'])
        self.assertEmpty(retrieved_policy['rules'])

    @decorators.idempotent_id('1cb42653-54bd-4a9a-b888-c55e18199201')
    def test_delete_policy(self):
        """qos-policy-delete POLICY_ID."""
        policy = self.create_qos_policy(
            'test-policy', 'desc', True)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        retrieved_policy = self.adm_qos_client.show_policy(policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        self.assertEqual('test-policy', retrieved_policy['name'])

        self.adm_qos_client.delete_policy(policy['id'])
        self.assertRaises(exceptions.NotFound,
                          self.adm_qos_client.show_policy, policy['id'])

    def _test_list_admin_rule_types(self):
        """qos-available-rule-types: available rule type from admin view."""
        self._test_list_rule_types(self.adm_qos_client)

    def _test_list_regular_rule_types(self):
        """qos-available-rule-types: available rule type from project view."""
        self._test_list_rule_types(self.pri_qos_client)

    def _test_list_rule_types(self, client):
        # List supported rule types
        # TODO(QoS): since in gate we run both ovs and linuxbridge ml2 drivers,
        # and since Linux Bridge ml2 driver does not have QoS support yet, ml2
        # plugin reports no rule types are supported. Once linuxbridge will
        # receive support for QoS, the list of expected rule types will change.
        #
        # In theory, we could make the test conditional on which ml2 drivers
        # are enabled in gate (or more specifically, on which supported qos
        # rules are claimed by core plugin), but that option doesn't seem to be
        # available thru tempest.lib framework
        expected_rule_types = []
        expected_rule_details = ['type']

        rule_types = client.available_rule_types()
        actual_rule_types = [rule['type'] for rule in rule_types]

        # TODO(akang): seems not correct
        # Verify that only required fields present in rule details
        for rule in actual_rule_types:
            self.assertEqual(tuple(rule.keys()), tuple(expected_rule_details))

        # Verify if expected rules are present in the actual rules list
        for rule in expected_rule_types:
            self.assertIn(rule, actual_rule_types)

    def _disassociate_network(self, network_id, client_mgr=None):
        self.update_network(network_id, client_mgr=client_mgr,
                            qos_policy_id=None)
        updated_network = self.show_network(network_id,
                                            client_mgr=client_mgr)
        self.assertIsNone(updated_network['qos_policy_id'])

    @decorators.idempotent_id('65b9ef75-1911-406a-bbdb-ca1d68d528b0')
    def test_policy_association_with_admin_network(self):
        """admin can create network with non-shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        network = self.create_shared_network('test-network',
                                             qos_policy_id=policy['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        retrieved_network = self.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['qos_policy_id'])
        self._disassociate_network(network['id'], self.admin_mgr)

    @decorators.idempotent_id('1738de5d-0476-4163-9022-5e1b548c208e')
    def test_policy_association_with_tenant_network(self):
        """project/tenant can create network with shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        network = self.create_network('test-network',
                                      client_mgr=self.primary_mgr,
                                      qos_policy_id=policy['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        retrieved_network = self.show_network(network['id'],
                                              client_mgr=self.primary_mgr)
        self.assertEqual(
            policy['id'], retrieved_network['qos_policy_id'])

        self._disassociate_network(network['id'], self.primary_mgr)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('9efe63d0-836f-4cc2-b00c-468e63aa614e')
    def test_policy_association_with_network_nonexistent_policy(self):
        """Can not attach network to a nonexist policy."""
        self.assertRaises(
            exceptions.NotFound,
            self.create_network,
            'test-network',
            qos_policy_id='9efe63d0-836f-4cc2-b00c-468e63aa614e')

    @decorators.attr(type='negative')
    @decorators.idempotent_id('1aa55a79-324f-47d9-a076-894a8fc2448b')
    def test_policy_association_with_network_non_shared_policy(self):
        """tenant/project can not attach network with not-shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            exceptions.NotFound,
            self.create_network,
            'test-network', qos_policy_id=policy['id'],
            client_mgr=self.primary_mgr)

    @decorators.idempotent_id('10a9392c-1359-4cbb-989f-fb768e5834a8')
    def test_policy_update_association_with_admin_network(self):
        """admin can create associate non-shared policy to network."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        network = self.create_shared_network('test-network')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        retrieved_network = self.show_network(network['id'])
        self.assertIsNone(retrieved_network['qos_policy_id'])

        self.update_network(
            network['id'], qos_policy_id=policy['id'])
        retrieved_network = self.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['qos_policy_id'])

        self._disassociate_network(network['id'], self.admin_mgr)

    def _disassociate_port(self, port_id, client_mgr=None):
        client_mgr = client_mgr if client_mgr else self.admin_mgr
        self.update_port(port_id, qos_policy_id=None,
                         client_mgr=client_mgr)
        updated_port = self.show_port(port_id, client_mgr=client_mgr)
        self.assertIsNone(updated_port['qos_policy_id'])

    @decorators.attr(type='nsxv3')
    @decorators.attr(type='negative')
    @decorators.idempotent_id('98fcd95e-84cf-4746-860e-44692e674f2e')
    def test_policy_association_with_port_shared_policy(self):
        """test port can associate shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        network = self.create_shared_network('test-network')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        port = self.create_port(network, qos_policy_id=policy['id'],
                                client_mgr=self.primary_mgr)
        #check backend if the port qos profile is updated
        if CONF.network.backend == 'nsxp':
            self.verify_backend_port(policy, network, port)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_port, port['id'])
        retrieved_port = self.show_port(port['id'],
                                        client_mgr=self.primary_mgr)
        self.assertEqual(
            policy['id'], retrieved_port['qos_policy_id'])

        self._disassociate_port(port['id'], client_mgr=self.primary_mgr)

    @decorators.attr(type='negative')
    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('49e02f5a-e1dd-41d5-9855-cfa37f2d195e')
    def test_policy_association_with_port_nonexistent_policy(self):
        """test port cannot be created with nonexist policy."""
        network = self.create_shared_network('test-network')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        self.assertRaises(
            exceptions.NotFound,
            self.create_port,
            network,
            qos_policy_id='49e02f5a-e1dd-41d5-9855-cfa37f2d195e')

    @decorators.attr(type='negative')
    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f53d961c-9fe5-4422-8b66-7add972c6031')
    def test_policy_association_with_port_non_shared_policy(self):
        """project/tenant can not associate port with non-shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        network = self.create_shared_network('test-network')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        self.assertRaises(
            exceptions.NotFound,
            self.create_port,
            network,
            qos_policy_id=policy['id'], client_mgr=self.primary_mgr)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f8163237-fba9-4db5-9526-bad6d2343c76')
    def test_policy_update_association_with_port_shared_policy(self):
        """project/tenant can update port with shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        network = self.create_shared_network('test-network')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        port = self.create_port(network, client_mgr=self.primary_mgr)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_port, port['id'])
        retrieved_port = self.show_port(port['id'],
                                        client_mgr=self.primary_mgr)
        self.assertIsNone(retrieved_port['qos_policy_id'])

        self.update_port(port['id'], qos_policy_id=policy['id'],
                         client_mgr=self.primary_mgr)
        retrieved_port = self.show_port(port['id'],
                                        client_mgr=self.primary_mgr)
        #check backend if the port qos profile is updated
        if CONF.network.backend == 'nsxp':
            self.verify_backend_port(policy, network, port)
        self.assertEqual(
            policy['id'], retrieved_port['qos_policy_id'])

        self._disassociate_port(port['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('18163237-8ba9-4db5-9525-bad6d2343c75')
    def test_delete_not_allowed_if_policy_in_use_by_network(self):
        """can not delete policy if used by network."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        network = self.create_shared_network(
            'test-network', qos_policy_id=policy['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        self.assertRaises(
            exceptions.Conflict,
            self.adm_qos_client.delete_policy, policy['id'])

        self._disassociate_network(network['id'], self.admin_mgr)
        self.adm_qos_client.delete_policy(policy['id'])

    @decorators.attr(type='negative')
    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('24153230-84a9-4dd5-9525-bad6d2343c75')
    def test_delete_not_allowed_if_policy_in_use_by_port(self):
        """can not delete policy if used by port."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        network = self.create_shared_network('test-network')
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network['id'])
        port = self.create_port(network, qos_policy_id=policy['id'],
                                client_mgr=self.primary_mgr)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_port, port['id'])
        #check backend if the port qos profile is updated
        if CONF.network.backend == 'nsxp':
            self.verify_backend_port(policy, network, port)
        self.assertRaises(
            exceptions.Conflict,
            self.adm_qos_client.delete_policy, policy['id'])

        self._disassociate_port(port['id'], client_mgr=self.primary_mgr)
        self.adm_qos_client.delete_policy(policy['id'])

    @decorators.idempotent_id('a2a5849b-dd06-4b18-9664-0b6828a1fc27')
    def test_qos_policy_delete_with_rules(self):
        """Policy with rules attached can be deleted."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        self.adm_qos_client.create_bandwidth_limit_rule(
            policy['id'], 2000, 1337)

        self.adm_qos_client.delete_policy(policy['id'])

        with testtools.ExpectedException(exceptions.NotFound):
            self.adm_qos_client.show_policy(policy['id'])


class QosBandwidthLimitRuleTest(BaseQosTest):
    """QoS Bandwidth limit rule CURD operations."""

    @decorators.idempotent_id('8a59b00b-3e9c-4787-92f8-93a5cdf5e378')
    def test_egress_rule_create(self):
        """qos-bandwidth-limit-egress-rule-create POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=2000, max_burst_kbps=1337)

        # Test 'show rule'
        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy, rule)
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(2000, retrieved_rule['max_kbps'])
        self.assertEqual(1337, retrieved_rule['max_burst_kbps'])
        # Test 'list rules'
        rules = qos_client.list_bandwidth_limit_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        retrieved_policy = qos_client.show_policy(policy['id'])
        policy_rules = retrieved_policy['rules']
        self.assertEqual(1, len(policy_rules))
        self.assertEqual(rule['id'], policy_rules[0]['id'])
        self.assertEqual(base_qos.RULE_TYPE_BANDWIDTH_LIMIT,
                         policy_rules[0]['type'])

    @decorators.idempotent_id('4486734b-d235-4e9f-ad6a-eb9600c50fbe')
    def test_ingress_rule_create(self):
        """qos-bandwidth-limit-ingress-rule-create POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=2000, max_burst_kbps=1337,
            direction='ingress')

        # Test 'show rule'
        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy, rule)
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(2000, retrieved_rule['max_kbps'])
        self.assertEqual(1337, retrieved_rule['max_burst_kbps'])
        self.assertEqual('ingress', retrieved_rule['direction'])

        # Test 'list rules'
        rules = qos_client.list_bandwidth_limit_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        retrieved_policy = qos_client.show_policy(policy['id'])
        policy_rules = retrieved_policy['rules']
        self.assertEqual(1, len(policy_rules))
        self.assertEqual(rule['id'], policy_rules[0]['id'])
        self.assertEqual(base_qos.RULE_TYPE_BANDWIDTH_LIMIT,
                         policy_rules[0]['type'])

    @decorators.idempotent_id('859288c6-3e45-415b-9aad-0d347a715a96')
    def test_bandwidth_rule_create(self):
        """qos-bandwidth-limit-rule-create POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        egress_rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=2000, max_burst_kbps=1337,
            direction='egress')
        ingress_rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=2000, max_burst_kbps=1337,
            direction='ingress')
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rules(policy, ingress_rule, 1)
        # Test 'show rule'
        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            egress_rule['id'], policy['id'])
        self.assertEqual(egress_rule['id'], retrieved_rule['id'])
        self.assertEqual(2000, retrieved_rule['max_kbps'])
        self.assertEqual(1337, retrieved_rule['max_burst_kbps'])
        self.assertEqual('egress', retrieved_rule['direction'])
        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            ingress_rule['id'], policy['id'])
        self.assertEqual(ingress_rule['id'], retrieved_rule['id'])
        self.assertEqual(2000, retrieved_rule['max_kbps'])
        self.assertEqual(1337, retrieved_rule['max_burst_kbps'])
        self.assertEqual('ingress', retrieved_rule['direction'])
        # Test 'list rules'
        rules = qos_client.list_bandwidth_limit_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(egress_rule['id'], rules_ids)
        self.assertIn(ingress_rule['id'], rules_ids)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('8a59b00b-ab01-4787-92f8-93a5cdf5e378')
    def test_rule_create_fail_for_the_same_type(self):
        """One bandwidth limit rule per policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=2000, max_burst_kbps=1337)

        self.assertRaises(exceptions.Conflict,
                          self.create_qos_bandwidth_limit_rule,
                          policy_id=policy['id'],
                          max_kbps=2001, max_burst_kbps=1338)

    @decorators.idempotent_id('149a6988-2568-47d2-931e-2dbc858943b3')
    def test_egress_rule_update(self):
        """qos-bandwidth-limit-egress-rule-update RULE-ID POLICY_ID."""
        qos_client = self.adm_qos_client
        max_kbps = 2000
        max_burst_kbps = 1337
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=2000, max_burst_kbps=1000)

        qos_client.update_bandwidth_limit_rule(
            rule['id'], policy['id'],
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps)

        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy, retrieved_rule)
        self.assertEqual(max_kbps, retrieved_rule['max_kbps'])
        self.assertEqual(max_burst_kbps, retrieved_rule['max_burst_kbps'])

    @decorators.idempotent_id('11d24de5-660f-4956-934e-d972239ccc83')
    def test_ingress_rule_update(self):
        """qos-bandwidth-limit-ingress-rule-update RULE-ID POLICY_ID."""
        qos_client = self.adm_qos_client
        max_kbps = 2000
        max_burst_kbps = 1337
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=2000, max_burst_kbps=1000,
            direction='ingress')

        qos_client.update_bandwidth_limit_rule(
            rule['id'], policy['id'],
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps)

        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy, retrieved_rule)
        self.assertEqual(max_kbps, retrieved_rule['max_kbps'])
        self.assertEqual(max_burst_kbps, retrieved_rule['max_burst_kbps'])
        self.assertEqual('ingress', retrieved_rule['direction'])

    @decorators.idempotent_id('14b3c06b-8dff-4b95-b868-bdfb2ad95c2d')
    def test_bandwidth_rule_update(self):
        """qos-bandwidth-limit-rule-update direction type."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=2000, max_burst_kbps=1000,
            direction='ingress')

        qos_client.update_bandwidth_limit_rule(
            rule['id'], policy['id'],
            direction='egress')

        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy, retrieved_rule)
        self.assertEqual(2000, retrieved_rule['max_kbps'])
        self.assertEqual(1000, retrieved_rule['max_burst_kbps'])
        self.assertEqual('egress', retrieved_rule['direction'])

    @decorators.idempotent_id('67ee6efd-7b33-4a68-927d-275b4f8ba958')
    def test_egress_rule_delete(self):
        """qos-bandwidth-limit-egress-rule-delete RULE-ID POLICY_ID."""
        qos_client = self.adm_qos_client
        max_kbps = 2000
        max_burst_kbps = 1337
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_bandwidth_limit_rule(
            policy['id'],
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps)

        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy, retrieved_rule)

        qos_client.delete_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertRaises(exceptions.NotFound,
                          qos_client.show_bandwidth_limit_rule,
                          rule['id'], policy['id'])

    @decorators.idempotent_id('b39e0398-fcd9-4357-bfb3-e3464ca46240')
    def test_ingress_rule_delete(self):
        """qos-bandwidth-limit-ingress-rule-delete RULE-ID POLICY_ID."""
        qos_client = self.adm_qos_client
        max_kbps = 2000
        max_burst_kbps = 1337
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_bandwidth_limit_rule(
            policy['id'],
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps,
            direction='ingress')

        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy, retrieved_rule)

        qos_client.delete_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertRaises(exceptions.NotFound,
                          qos_client.show_bandwidth_limit_rule,
                          rule['id'], policy['id'])

    @decorators.idempotent_id('aadf409b-66ef-42b9-bf5c-da8a121676af')
    def test_bandwidth_rule_delete(self):
        """qos-bandwidth-limit-rule-delete for both rules under a policy."""
        qos_client = self.adm_qos_client
        max_kbps = 2000
        max_burst_kbps = 1337
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        egress_rule = self.create_qos_bandwidth_limit_rule(
            policy['id'],
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps,
            direction='egress')
        ingress_rule = self.create_qos_bandwidth_limit_rule(
            policy['id'],
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps,
            direction='ingress')
        egress_retrieved_rule = qos_client.show_bandwidth_limit_rule(
            egress_rule['id'], policy['id'])
        self.assertEqual(egress_rule['id'], egress_retrieved_rule['id'])
        ingress_retrieved_rule = qos_client.show_bandwidth_limit_rule(
            ingress_rule['id'], policy['id'])
        self.assertEqual(ingress_rule['id'], ingress_retrieved_rule['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rules(policy,
                                                egress_retrieved_rule, 0)
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rules(policy,
                                                ingress_retrieved_rule, 1)
        qos_client.delete_bandwidth_limit_rule(
            egress_rule['id'], policy['id'])
        self.assertRaises(exceptions.NotFound,
                          qos_client.show_bandwidth_limit_rule,
                          egress_rule['id'], policy['id'])
        qos_client.delete_bandwidth_limit_rule(
            ingress_rule['id'], policy['id'])
        self.assertRaises(exceptions.NotFound,
                          qos_client.show_bandwidth_limit_rule,
                          ingress_rule['id'], policy['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('f211222c-5808-46cb-a961-983bbab6b852')
    def test_rule_create_rule_nonexistent_policy(self):
        """Cannot create rule with nonexist policy."""
        self.assertRaises(
            exceptions.NotFound,
            self.create_qos_bandwidth_limit_rule,
            'policy', max_kbps=200, max_burst_kbps=1337)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('eed8e2a6-22da-421b-89b9-935a2c1a1b50')
    def test_policy_create_forbidden_for_regular_tenants(self):
        """project/tenant cannot create policy."""
        self.assertRaises(
            exceptions.Forbidden,
            self.create_qos_policy,
            'test-policy', 'test policy', False,
            qos_client=self.pri_qos_client)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a4a2e7ad-786f-4927-a85a-e545a93bd274')
    def test_rule_create_forbidden_for_regular_tenants(self):
        """project/tenant cannot create rule."""
        self.assertRaises(
            exceptions.Forbidden,
            self.create_qos_bandwidth_limit_rule,
            'policy', max_kbps=1, max_burst_kbps=2,
            qos_client=self.pri_qos_client)

    @decorators.idempotent_id('ce0bd0c2-54d9-4e29-85f1-cfb36ac3ebe2')
    def test_get_rules_by_policy(self):
        """qos-bandwidth-limit-rule-list POLICY_ID."""
        policy1 = self.create_qos_policy(name='test-policy1',
                                         description='test policy1',
                                         shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy1['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy1)
        rule1 = self.create_qos_bandwidth_limit_rule(
            policy_id=policy1['id'], max_kbps=2000, max_burst_kbps=1337)
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy1, rule1)

        policy2 = self.create_qos_policy(name='test-policy2',
                                         description='test policy2',
                                         shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy2['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy2)
        rule2 = self.create_qos_bandwidth_limit_rule(
            policy_id=policy2['id'], max_kbps=5000, max_burst_kbps=2523)
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_bandwidth_rule(policy2, rule2)

        # Test 'list rules'
        rules = self.adm_qos_client.list_bandwidth_limit_rules(policy1['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule1['id'], rules_ids)
        self.assertNotIn(rule2['id'], rules_ids)


class QosDscpMarkingRuleTest(BaseQosTest):
    """QoS Dscp Marking Rule CRUD operation."""

    VALID_DSCP_MARK1 = 56
    VALID_DSCP_MARK2 = 48

    @decorators.idempotent_id('8a59b40b-3e9c-4787-92f8-93a5cdf5e378')
    def test_rule_create(self):
        """qos-dscp-marking-rule-create POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)

        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_dscp_rule(policy, rule)

        # Test 'show rule'
        retrieved_rule = qos_client.show_dscp_marking_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(self.VALID_DSCP_MARK1, retrieved_rule['dscp_mark'])

        # Test 'list rules'
        rules = qos_client.list_dscp_marking_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        retrieved_policy = qos_client.show_policy(policy['id'])
        policy_rules = retrieved_policy['rules']
        self.assertEqual(1, len(policy_rules))
        self.assertEqual(rule['id'], policy_rules[0]['id'])
        self.assertEqual(base_qos.RULE_TYPE_DSCP_MARK,
                         policy_rules[0]['type'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('8b59b10b-ab01-4787-92f8-93a5cdf5e378')
    def test_rule_create_fail_for_the_same_type(self):
        """One dscp marking rule per policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_dscp_rule(policy, rule)

        self.assertRaises(exceptions.Conflict,
                          self.create_qos_dscp_marking_rule,
                          policy_id=policy['id'],
                          dscp_mark=self.VALID_DSCP_MARK2)

    @decorators.idempotent_id('249a6988-2568-47d2-931e-2dbc858943b3')
    def test_rule_update(self):
        """qos-dscp-marking-rule-create POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)

        qos_client.update_dscp_marking_rule(
            rule['id'], policy['id'], dscp_mark=self.VALID_DSCP_MARK2)

        retrieved_rule = qos_client.show_dscp_marking_rule(
            rule['id'], policy['id'])
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_dscp_rule(policy, retrieved_rule)
        self.assertEqual(self.VALID_DSCP_MARK2, retrieved_rule['dscp_mark'])

    @decorators.idempotent_id('67ed6efd-7b33-4a68-927d-275b4f8ba958')
    def test_rule_delete(self):
        """qos-dscp-marking-rule-delete POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        rule = self.create_qos_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)

        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_dscp_rule(policy, rule)

        retrieved_rule = qos_client.show_dscp_marking_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])

        qos_client.delete_dscp_marking_rule(rule['id'], policy['id'])
        self.assertRaises(exceptions.NotFound,
                          qos_client.show_dscp_marking_rule,
                          rule['id'], policy['id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('f215222c-5808-46cb-a961-983bbab6b852')
    def test_rule_create_rule_nonexistent_policy(self):
        """can not create dscp marking rule with nonexist policy."""
        self.assertRaises(
            exceptions.NotFound,
            self.create_qos_dscp_marking_rule,
            'policy', self.VALID_DSCP_MARK1)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a4a2e3ad-786f-4927-a85a-e545a93bd274')
    def test_rule_create_forbidden_for_regular_tenants(self):
        """project/tenant can not create dscp marking rule."""
        self.assertRaises(
            exceptions.Forbidden,
            self.create_qos_dscp_marking_rule,
            'policy', self.VALID_DSCP_MARK1,
            qos_client=self.pri_qos_client)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('32646b08-4f05-4493-a48a-bde768a18533')
    def test_invalid_rule_create(self):
        """Can not create rule with invalid dscp_mark value."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy)
        self.assertRaises(
            exceptions.BadRequest,
            self.create_qos_dscp_marking_rule,
            policy['id'], 58)

    @decorators.idempotent_id('cf0bd0c2-54d9-4e29-85f1-cfb36ac3ebe2')
    def test_get_rules_by_policy(self):
        """qos-dscp-marking-rule-list POLICY_ID."""
        policy1 = self.create_qos_policy(name='test-policy1',
                                         description='test policy1',
                                         shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy1['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy1)
        rule1 = self.create_qos_dscp_marking_rule(
            policy1['id'], self.VALID_DSCP_MARK1)
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_dscp_rule(policy1, rule1)

        policy2 = self.create_qos_policy(name='test-policy2',
                                         description='test policy2',
                                         shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy2['id'])
        #check backend if the policy was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend(policy2)
        rule2 = self.create_qos_dscp_marking_rule(
            policy2['id'], self.VALID_DSCP_MARK2)
        #check backend if the rule was created
        if CONF.network.backend == 'nsxp':
            self.verify_backend_dscp_rule(policy2, rule2)

        # Test 'list rules'
        rules = self.adm_qos_client.list_dscp_marking_rules(policy1['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule1['id'], rules_ids)
        self.assertNotIn(rule2['id'], rules_ids)

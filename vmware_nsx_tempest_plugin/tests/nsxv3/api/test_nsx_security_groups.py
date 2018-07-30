# Copyright 2013 OpenStack Foundation
# Copyright 2016 VMware Inc.
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

import time

from oslo_log import log as logging
import six
from tempest.api.network import base_security_groups as base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest import test

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.services import nsxv3_client

LOG = logging.getLogger(__name__)

CONF = config.CONF


class NSXv3SecGroupTest(base.BaseSecGroupTest):
    _project_network_cidr = CONF.network.project_network_cidr

    @classmethod
    def skip_checks(cls):
        super(NSXv3SecGroupTest, cls).skip_checks()
        if not test.is_extension_enabled('security-group', 'network'):
            msg = "security-group extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(NSXv3SecGroupTest, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    def _create_verify_security_group_rule(self, sg_id, direction,
                                           ethertype, protocol,
                                           port_range_min,
                                           port_range_max,
                                           remote_group_id=None,
                                           remote_ip_prefix=None):
        # Create Security Group rule with the input params and validate
        # that SG rule is created with the same parameters.
        sec_group_rules_client = self.security_group_rules_client
        rule_create_body = sec_group_rules_client.create_security_group_rule(
            security_group_id=sg_id,
            direction=direction,
            ethertype=ethertype,
            protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_group_id=remote_group_id,
            remote_ip_prefix=remote_ip_prefix
        )

        sec_group_rule = rule_create_body['security_group_rule']
        self.addCleanup(self._delete_security_group_rule,
                        sec_group_rule['id'])

        expected = {'direction': direction, 'protocol': protocol,
                    'ethertype': ethertype, 'port_range_min': port_range_min,
                    'port_range_max': port_range_max,
                    'remote_group_id': remote_group_id,
                    'remote_ip_prefix': remote_ip_prefix}
        for key, value in six.iteritems(expected):
            self.assertEqual(value, sec_group_rule[key],
                             "Field %s of the created security group "
                             "rule does not match with %s." %
                             (key, value))

    def _wait_till_firewall_gets_realize(self, secgroup, dfw_error_msg=""):
        nsx_firewall_time_counter = 0
        nsx_dfw_section = None
        # wait till timeout or till dfw section
        while nsx_firewall_time_counter < \
                constants.NSX_FIREWALL_REALIZED_TIMEOUT and \
                not nsx_dfw_section:
            nsx_firewall_time_counter += 1
            nsx_nsgroup = self.nsx.get_ns_group(secgroup['name'],
                                                secgroup['id'])
            nsx_dfw_section = self.nsx.get_firewall_section(secgroup['name'],
                                                            secgroup['id'])
            time.sleep(constants.ONE_SEC)
        self.assertIsNotNone(nsx_nsgroup)
        self.assertIsNotNone(nsx_dfw_section, dfw_error_msg)
        return nsx_nsgroup, nsx_dfw_section

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('105ca2c6-a14e-448b-b227-a7366e611bf2')
    def test_create_sec_group_with_0_0_0_0_remote_ip_prefix(self):
        # Create a security group
        group_create_body, name = self._create_security_group()
        secgroup = group_create_body['security_group']
        dfw_error_msg = "Firewall section not found for %s!" % secgroup['name']
        nsx_nsgroup, nsx_dfw_section = \
            self._wait_till_firewall_gets_realize(secgroup, dfw_error_msg)
        client = self.security_group_rules_client
        rule_create_body = client.create_security_group_rule(
            security_group_id=secgroup['id'],
            protocol='tcp',
            direction='ingress',
            port_range_min=22,
            port_range_max=23,
            ethertype=self.ethertype,
            remote_ip_prefix='0.0.0.0/0',
        )
        secgroup_rule = rule_create_body['security_group_rule']
        nsx_dfw_rule = self.nsx.get_firewall_section_rule(
            nsx_dfw_section,
            secgroup_rule['id'])
        self.assertIsNotNone(nsx_dfw_rule)
        # Delete the security group rule
        client.delete_security_group_rule(secgroup_rule['id'])
        nsx_dfw_rule = self.nsx.get_firewall_section_rule(
            nsx_dfw_section,
            secgroup_rule['id'])
        self.assertIsNone(nsx_dfw_rule)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('904ca2c1-a14d-448b-b723-a7366e613bf1')
    def test_create_update_nsx_security_group(self):
        # Create a security group
        group_create_body, name = self._create_security_group()
        secgroup = group_create_body['security_group']
        dfw_error_msg = "Firewall section not found for %s!" % secgroup['name']
        self._wait_till_firewall_gets_realize(secgroup, dfw_error_msg)
        # List security groups and verify if created group is there in response
        list_body = self.security_groups_client.list_security_groups()
        secgroup_list = list()
        for sg in list_body['security_groups']:
            secgroup_list.append(sg['id'])
        self.assertIn(secgroup['id'], secgroup_list)
        # Update the security group
        new_name = data_utils.rand_name('security-')
        new_description = data_utils.rand_name('security-description')
        update_body = self.security_groups_client.update_security_group(
            secgroup['id'], name=new_name, description=new_description)
        # Verify if security group is updated
        updated_secgroup = update_body['security_group']
        self.assertEqual(updated_secgroup['name'], new_name)
        self.assertEqual(updated_secgroup['description'], new_description)
        dfw_error_msg = "Firewall section is not updated for %s!" % \
                        updated_secgroup['name']
        self._wait_till_firewall_gets_realize(updated_secgroup, dfw_error_msg)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('e637cc59-c5e6-49b5-a539-e517e780656e')
    def test_delete_nsx_security_group(self):
        # Create a security group
        name = data_utils.rand_name('secgroup-')
        create_body = self.security_groups_client.create_security_group(
            name=name)
        secgroup = create_body['security_group']
        dfw_error_msg = "Firewall section not found for %s!" % secgroup['name']
        self._wait_till_firewall_gets_realize(secgroup, dfw_error_msg)
        self.assertEqual(secgroup['name'], name)
        # Delete the security group
        self._delete_security_group(secgroup['id'])
        nsx_nsgroup = self.nsx.get_ns_group(secgroup['name'],
                                            secgroup['id'])
        nsx_dfw_section = self.nsx.get_firewall_section(name, secgroup['id'])
        self.assertIsNone(nsx_nsgroup)
        self.assertIsNone(nsx_dfw_section)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('91c298c0-fbbd-4597-b4c6-1a7ecfb8a2de')
    def test_create_nsx_security_group_rule(self):
        # Create a security group
        create_body, _ = self._create_security_group()
        secgroup = create_body['security_group']
        dfw_error_msg = "Firewall section not found for %s!" % secgroup['name']
        nsx_nsgroup, nsx_dfw_section = self._wait_till_firewall_gets_realize(
            secgroup, dfw_error_msg)
        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        client = self.security_group_rules_client
        for protocol in protocols:
            rule_create_body = client.create_security_group_rule(
                security_group_id=secgroup['id'],
                protocol=protocol,
                direction='ingress',
                ethertype=self.ethertype
            )
            secgroup_rule = rule_create_body['security_group_rule']

            # Show details of the created security rule
            show_rule_body = client.show_security_group_rule(
                secgroup_rule['id'])
            create_dict = rule_create_body['security_group_rule']
            for key, value in six.iteritems(create_dict):
                self.assertEqual(value,
                                 show_rule_body['security_group_rule'][key],
                                 "%s does not match." % key)

            # List rules and verify created rule is in response
            rule_list_body = (
                self.security_group_rules_client.list_security_group_rules())
            rule_list = [rule['id']
                         for rule in rule_list_body['security_group_rules']]
            self.assertIn(rule_create_body['security_group_rule']['id'],
                          rule_list)
            nsx_dfw_rule = self.nsx.get_firewall_section_rule(
                nsx_dfw_section,
                secgroup_rule['id'])
            self.assertIsNotNone(nsx_dfw_rule)
            expected_rule = {
                'display_name': secgroup_rule['id'],
                'action': 'ALLOW',
                'direction': 'IN',
                'destinations': [
                    {
                        'target_display_name': nsx_nsgroup['display_name'],
                        'is_valid': True,
                        'target_type': 'NSGroup',
                        'target_id': nsx_nsgroup['id']
                    }
                ]
            }
            for key, value in six.iteritems(expected_rule):
                self.assertEqual(value, nsx_dfw_rule[key],
                                 "%s does not match." % key)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b6c424e5-3553-4b7d-bd95-8b1f0a860fb4')
    def test_delete_nsx_security_group_rule(self):
        # Create a security group
        create_body, _ = self._create_security_group()
        secgroup = create_body['security_group']
        dfw_error_msg = "Firewall section not found for %s!" % secgroup['name']
        nsx_nsgroup, nsx_dfw_section = self._wait_till_firewall_gets_realize(
            secgroup, dfw_error_msg)
        # Create a security group rule
        client = self.security_group_rules_client
        rule_create_body = client.create_security_group_rule(
            security_group_id=secgroup['id'],
            protocol='tcp',
            direction='ingress',
            port_range_min=22,
            port_range_max=23,
            ethertype=self.ethertype
        )
        secgroup_rule = rule_create_body['security_group_rule']
        nsx_dfw_rule = self.nsx.get_firewall_section_rule(
            nsx_dfw_section,
            secgroup_rule['id'])
        self.assertIsNotNone(nsx_dfw_rule)
        # Delete the security group rule
        client.delete_security_group_rule(secgroup_rule['id'])
        nsx_dfw_rule = self.nsx.get_firewall_section_rule(
            nsx_dfw_section,
            secgroup_rule['id'])
        self.assertIsNone(nsx_dfw_rule)

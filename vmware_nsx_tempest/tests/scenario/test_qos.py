# Copyright 2017 VMware Inc
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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest import test

from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsx_client

import time

CONF = config.CONF
CONF.validation.auth_method = 'None'

LOG = logging.getLogger(__name__)

DSCP_MARK = 12
DSCP_MARK_UPDATED = 16
BW_VALUE_KBPS = 3000
BW_VALUE_MBPS = 3
UPDATED_BW_VALUE_KBPS = 7000
UPDATED_BW_VALUE_MBPS = 7
MAX_BURST_KBPS = 3000000
MAX_BURST_MBPS = 3


class TestQosOps(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestQosOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        if not CONF.network.public_network_cidr:
            msg = "public_network_cidr must be defined in network section."
            raise cls.skipException(msg)
        if not test.is_extension_enabled('qos', 'network'):
            msg = "q-qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        cls.admin_mgr = cls.get_client_manager('admin')
        super(TestQosOps, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestQosOps, cls).setup_clients()
        cls.nsx_client = nsx_client.NSXClient(
            CONF.network.backend,
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)

    def define_security_groups(self):
        self.qos_sg = self.create_topology_empty_security_group(
            namestart="qos_sg_")
        # Common rules to allow the following traffic
        # 1. Egress ICMP IPv4 any any
        # 2. Egress ICMP IPv6 any any
        # 3. Ingress ICMP IPv4 from public network
        # 4. Ingress TCP 22 (SSH) from public network
        common_ruleset = [dict(direction='egress', protocol='icmp'),
                          dict(direction='egress', protocol='icmp',
                               ethertype='IPv6'),
                          dict(direction='egress', protocol='tcp',
                               port_range_min=22, port_range_max=22),
                          dict(direction='egress', protocol='udp'),
                          dict(direction='ingress', protocol='tcp',
                               port_range_min=22, port_range_max=22),
                          dict(direction='ingress', protocol='udp'),
                          dict(direction='ingress', protocol='icmp')]
        for rule in common_ruleset:
            self.add_security_group_rule(self.qos_sg, rule)

    def check_show_policy(self, policy_id, rule_type=None,
                          rule_bw=None, rule_dscp=None):
        retrieved_policy = self.show_qos_policy(policy_id)
        policy_rules = retrieved_policy['rules']
        if rule_type == 'bw':
            self.assertEqual(1, len(policy_rules))
            self.assertEqual(rule_bw['id'], policy_rules[0]['id'])
            self.assertEqual(feature_manager.RULE_TYPE_BANDWIDTH_LIMIT,
                             policy_rules[0]['type'])
        elif rule_type == 'dscp':
            self.assertEqual(1, len(policy_rules))
            self.assertEqual(rule_dscp['id'], policy_rules[0]['id'])
            self.assertEqual(feature_manager.RULE_TYPE_DSCP_MARK,
                             policy_rules[0]['type'])
        elif rule_type == 'bw+dscp':
            self.assertEqual(2, len(policy_rules))
            self.assertEqual(rule_bw['id'], policy_rules[0]['id'])
            self.assertEqual(rule_dscp['id'], policy_rules[1]['id'])
            self.assertEqual(feature_manager.RULE_TYPE_BANDWIDTH_LIMIT,
                             policy_rules[0]['type'])
            self.assertEqual(feature_manager.RULE_TYPE_DSCP_MARK,
                             policy_rules[1]['type'])

    def deploy_qos_ops_topology(self):
        router_qos = self.create_topology_router("router_qos")
        # Qos network
        network_qos = self.create_topology_network("network_qos")
        self.create_topology_subnet("subnet_qos", network_qos,
                           router_id=router_qos["id"])
        return network_qos

    def create_qos_bw_setup(self, bw_value_kbps, burst_kbps=0):
        #network = self.deploy_qos_ops_topology()
        name = data_utils.rand_name('test-qos-policy-')
        policy = self.create_qos_policy(name,
                                        description='bandwidth_rule',
                                        shared=False)
        rule = self.create_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=bw_value_kbps,
            max_burst_kbps=burst_kbps)
        # Test 'show rule'
        retrieved_rule = self.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(bw_value_kbps, retrieved_rule['max_kbps'])
        self.assertEqual(burst_kbps, retrieved_rule['max_burst_kbps'])

        network = self.deploy_qos_ops_topology()
        # Test 'list rules'
        rules = self.list_bandwidth_limit_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        self.check_show_policy(policy_id=policy['id'], rule_type='bw',
            rule_bw=rule)

        #Verify backend
        nsx_policy = self.nsx_client.get_qos_switching_profile(policy['name'])
        #verify bandwidth-limit rule at the backend
        avg_bw, peak_bw, max_burst = self.nsx_client.get_qos_bandwidth_rule(
            nsx_policy['id'])
        #check the values at the backend
        msg = 'Backend bw-limit rule values are incorrect'
        self.assertEqual(avg_bw, BW_VALUE_MBPS, msg)
        self.assertEqual(peak_bw, BW_VALUE_MBPS * 2, msg)
        self.assertEqual(max_burst, 0, msg)
        return dict(network_qos=network,
            policy_id=policy['id'])

    def create_qos_dscp_setup(self):
        name = data_utils.rand_name('test-qos-policy-')
        policy = self.create_qos_policy(name,
                                        description='dscp_rule',
                                        shared=False)
        # add dscp rule
        rule = self.create_dscp_marking_rule(
            policy_id=policy['id'], dscp_mark=DSCP_MARK)

        network = self.deploy_qos_ops_topology()
        # Test 'show rule'
        retrieved_rule = self.show_dscp_marking_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(DSCP_MARK, retrieved_rule['dscp_mark'])

        # Test 'list rules'
        rules = self.list_dscp_marking_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        self.check_show_policy(policy_id=policy['id'],
            rule_type='dscp', rule_dscp=rule)
        return dict(network_qos=network,
            policy_id=policy['id'], rule_id=rule['id'])

    def create_vms(self, network):
        #Obtain image id of debian_vmdk used for qos testing
        image_id = self.get_image_id(image_name='debian-2.6.32-i686-ESX')
        self.create_topology_instance(
            "qos_src_vm", [network],
            security_groups=[{'name': self.qos_sg['name']}],
            create_floating_ip=True, image_id=image_id)
        self.create_topology_instance(
            "qos_dst_vm", [network],
            security_groups=[{'name': self.qos_sg['name']}],
            create_floating_ip=True, image_id=image_id)

    def check_internal_connectivity(self, network):
        src_server_floatingip = self.topology_servers["qos_src_vm"][
            "floating_ip"]
        src_server = self.topology_servers["qos_src_vm"]
        self.check_vm_internal_connectivity(network,
            src_server_floatingip, src_server)
        dst_server_floatingip = self.topology_servers["qos_dst_vm"][
            "floating_ip"]
        dst_server = self.topology_servers["qos_dst_vm"]
        self.check_vm_internal_connectivity(network,
           dst_server_floatingip, dst_server)

    def test_bandwidth_rule(self, max_mbps, max_burst=0):
        """Check if traffic received is greater than configured value
        For example if configured value is 5Mbps and sending rate is 6Mbps
        Traffic should be capped below 5.5 which includes default burst
        """
        send_rate = max_mbps + max_burst + 1
        bw_value = self.use_iperf_send_traffic(
            src_server=self.topology_servers["qos_src_vm"],
            dst_server=self.topology_servers["qos_dst_vm"],
            send_rate=send_rate, traffic_type='udp')
        if float(bw_value) - (float(max_mbps) + float(max_burst)) > 0.5:
            LOG.info("Traffic received: {bw}".format(bw=bw_value))
            raise Exception('Traffic is not limited by bw-limit rule')
        elif((float(max_mbps) + float(max_burst)) - float(bw_value)) > 0.5:
            LOG.info("Traffic received: {bw}".format(bw=bw_value))
            raise Exception('Traffic is limited below configured value')


class QosBandwidthLimitRuleTest(TestQosOps):

    @decorators.idempotent_id('68fa3170-b61c-4e69-b0b7-6cbe34b57724')
    def test_qos_bw_rule_network(self):
        """
        Test bandwidth_limit rule by sending traffic between two instances
        and verifying if egress traffic is being bandwidth-limited
        """
        self.define_security_groups()
        qos_bw_dict = self.create_qos_bw_setup(bw_value_kbps=BW_VALUE_KBPS)
        self.admin_mgr.networks_client.update_network(
            qos_bw_dict['network_qos']['id'],
            qos_policy_id=qos_bw_dict['policy_id'])
        updated_network = self.admin_mgr.networks_client.show_network(
            qos_bw_dict['network_qos']['id'])
        qos_network = updated_network.get('network', updated_network)
        self.assertEqual(
            qos_bw_dict['policy_id'], qos_network['qos_policy_id'])
        self.create_vms(qos_bw_dict['network_qos'])
        #sleep to ensure VMs have finished complete bootup
        time.sleep(120)
        #check bandwidth rule
        self.test_bandwidth_rule(max_mbps=BW_VALUE_MBPS)

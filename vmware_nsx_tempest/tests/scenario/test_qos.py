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

import pyshark

CONF = config.CONF
CONF.validation.auth_method = 'None'

LOG = logging.getLogger(__name__)

DSCP_MARK = 12
DSCP_MARK_UPDATED = 16
BW_VALUE_KBPS = 1024
BW_VALUE_MBPS = 1
UPDATED_BW_VALUE_KBPS = 2048
UPDATED_BW_VALUE_MBPS = 2
MAX_BURST_KBPS = 1024000
MAX_BURST_MBPS = 1


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

    def create_qos_dscp_setup(self, dscp_mark):
        name = data_utils.rand_name('test-qos-policy-')
        policy = self.create_qos_policy(name,
                                        description='dscp_rule',
                                        shared=False)
        # add dscp rule
        rule = self.create_dscp_marking_rule(
            policy_id=policy['id'], dscp_mark=dscp_mark)

        # Test 'show rule'
        retrieved_rule = self.show_dscp_marking_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(DSCP_MARK, retrieved_rule['dscp_mark'])

        network = self.deploy_qos_ops_topology()
        # Test 'list rules'
        rules = self.list_dscp_marking_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        self.check_show_policy(policy_id=policy['id'],
            rule_type='dscp', rule_dscp=rule)
        #Verify backend
        nsx_policy = self.nsx_client.get_qos_switching_profile(policy['name'])
        #verify dscp rule at the backend
        dscp_value = self.nsx_client.get_qos_dscp_rule(
            nsx_policy['id'])
        #check the values at the backend
        msg = 'Backend DSCP value is incorrect'
        self.assertEqual(dscp_value, DSCP_MARK, msg)
        return dict(network_qos=network,
            policy_id=policy['id'])

    def create_qos_bw_dscp_setup(self, bw_value_kbps, dscp_mark, burst_kbps=0):
        name = data_utils.rand_name('test-qos-policy-')
        policy = self.create_qos_policy(name,
                                        description='bw_dscp_rule',
                                        shared=False)
        # add bw rule
        self.create_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=bw_value_kbps,
            max_burst_kbps=burst_kbps)
        # add dscp rule
        self.create_dscp_marking_rule(
            policy_id=policy['id'], dscp_mark=dscp_mark)
        network = self.deploy_qos_ops_topology()
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
        #verify dscp rule at the backend
        dscp_value = self.nsx_client.get_qos_dscp_rule(
            nsx_policy['id'])
        #check the values at the backend
        msg = 'Backend DSCP value is incorrect'
        self.assertEqual(dscp_value, DSCP_MARK, msg)
        return dict(network_qos=network,
            policy_id=policy['id'])

    def create_vms(self, network):
        #Obtain image id of debian_vmdk used for qos testing
        image_id = self.get_glance_image_id('debian')
        qos_src_vm = self.create_topology_instance(
            "qos_src_vm", [network],
            security_groups=[{'name': self.qos_sg['name']}],
            create_floating_ip=True, image_id=image_id)
        qos_dst_vm = self.create_topology_instance(
            "qos_dst_vm", [network],
            security_groups=[{'name': self.qos_sg['name']}],
            create_floating_ip=True, image_id=image_id)
        return (qos_src_vm, qos_dst_vm)

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

    def verify_bandwidth_rule(self, max_mbps, max_burst=0):
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

    def verify_dscp_rule(self, dscp_value):
        """Check if traffic received is marked with configured dscp value
        """
        dscp_filename = self.capture_iperf_traffic_dscp(
            src_server=self.topology_servers["qos_src_vm"],
            dst_server=self.topology_servers["qos_dst_vm"],
            traffic_type='udp', send_dscp='0', interface='eth0')
        """Check the entire file to see if any UDP packets are sent without configured
        dscp value.Example capture all UDP packets with DSCP value !=12"""
        src_vm_ip_dict = self.topology_servers['qos_src_vm']['floating_ips'][0]
        filter_string = (
            'ip.dsfield.dscp != %s && udp.dstport == 49162 '
            '&& ip.src == %s && ip.dst == %s' %
            (str(dscp_value),
            src_vm_ip_dict['fixed_ip_address'],
            self.topology_servers['qos_dst_vm']))
        capture = pyshark.FileCapture(dscp_filename,
                                      display_filter=filter_string)
        # capture file includes all packets that match the filter criteria
        if len(capture) > 0:
            raise Exception('Traffic is being marked with incorrect DSCP')


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
        self.verify_bandwidth_rule(max_mbps=BW_VALUE_MBPS)

    @decorators.idempotent_id('bf687826-ec76-4655-90a0-cc8f5316eaaf')
    def test_qos_bw_rule_network_with_burst(self):
        """
        Test bandwidth_limit rule by sending traffic between two instances
        and verifying if egress traffic is being bandwidth-limited
        """
        self.define_security_groups()
        qos_bw_dict = self.create_qos_bw_setup(bw_value_kbps=BW_VALUE_KBPS,
            burst_kbps=MAX_BURST_KBPS)
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
        self.verify_bandwidth_rule(max_mbps=BW_VALUE_MBPS,
            max_burst=MAX_BURST_MBPS)

    @decorators.idempotent_id('531c7476-6cee-4224-9b23-8e67e4c30703')
    def test_qos_bw_rule_port(self):
        """
        Test bandwidth_limit rule by sending traffic between two instances
        and verifying if egress traffic is being bandwidth-limited
        """
        self.define_security_groups()
        qos_bw_dict = self.create_qos_bw_setup(bw_value_kbps=BW_VALUE_KBPS)
        qos_src_vm, qos_dst_vm = self.create_vms(qos_bw_dict['network_qos'])
        self.os_admin.ports_client.update_port(
            qos_src_vm['floating_ips'][0]['port_id'],
            qos_policy_id=qos_bw_dict['policy_id'])
        self.os_admin.ports_client.update_port(
            qos_dst_vm['floating_ips'][0]['port_id'],
            qos_policy_id=qos_bw_dict['policy_id'])
        #sleep to ensure VMs have finished complete bootup
        time.sleep(120)
        #check bandwidth rule
        self.verify_bandwidth_rule(max_mbps=BW_VALUE_MBPS)

    @decorators.idempotent_id('ae40717f-6a08-4e9c-86d0-87e45375c844')
    def test_qos_bw_rule_port_with_burst(self):
        """
        Test bandwidth_limit rule by sending traffic between two instances
        and verifying if egress traffic is being bandwidth-limited
        """
        self.define_security_groups()
        qos_bw_dict = self.create_qos_bw_setup(bw_value_kbps=BW_VALUE_KBPS,
            burst_kbps=MAX_BURST_KBPS)
        qos_src_vm, qos_dst_vm = self.create_vms(qos_bw_dict['network_qos'])
        self.os_admin.ports_client.update_port(
            qos_src_vm['floating_ips'][0]['port_id'],
            qos_policy_id=qos_bw_dict['policy_id'])
        self.os_admin.ports_client.update_port(
            qos_dst_vm['floating_ips'][0]['port_id'],
            qos_policy_id=qos_bw_dict['policy_id'])
        #sleep to ensure VMs have finished complete bootup
        time.sleep(120)
        #check bandwidth rule
        self.verify_bandwidth_rule(max_mbps=BW_VALUE_MBPS,
            max_burst=MAX_BURST_MBPS)


class QosDSCPRuleTest(TestQosOps):

    @decorators.idempotent_id('40995e11-9231-406e-b3d7-b36dd362a94b')
    def test_qos_dscp_mark_network(self):
        """
        Test qos dscp rule by sending traffic between two instance
        and verifying if egress traffic is marked with dscp value
        """
        self.define_security_groups()
        qos_dscp_dict = self.create_qos_dscp_setup(dscp_mark=DSCP_MARK)
        self.admin_mgr.networks_client.update_network(
            qos_dscp_dict['network_qos']['id'],
            qos_policy_id=qos_dscp_dict['policy_id'])
        updated_network = self.admin_mgr.networks_client.show_network(
            qos_dscp_dict['network_qos']['id'])
        qos_network = updated_network.get('network', updated_network)
        self.assertEqual(
            qos_dscp_dict['policy_id'], qos_network['qos_policy_id'])
        self.create_vms(qos_dscp_dict['network_qos'])
        #sleep to ensure VMs have finished complete bootup
        time.sleep(240)
        #check dscp rule
        self.verify_dscp_rule(dscp_value=DSCP_MARK)

    @decorators.idempotent_id('4c5dc539-2878-4235-8880-35927b7a0c33')
    def test_qos_dscp_mark_port(self):
        """
        Test qos dscp rule by sending traffic between two instance
        and verifying if egress traffic is marked with dscp value
        """
        self.define_security_groups()
        qos_dscp_dict = self.create_qos_dscp_setup(dscp_mark=DSCP_MARK)
        qos_src_vm, qos_dst_vm = self.create_vms(qos_dscp_dict['network_qos'])
        self.os_admin.ports_client.update_port(
            qos_src_vm['floating_ips'][0]['port_id'],
            qos_policy_id=qos_dscp_dict['policy_id'])
        self.os_admin.ports_client.update_port(
            qos_dst_vm['floating_ips'][0]['port_id'],
            qos_policy_id=qos_dscp_dict['policy_id'])
        #sleep to ensure VMs have finished complete bootup
        time.sleep(240)
        #check dscp rule
        self.verify_dscp_rule(dscp_value=DSCP_MARK)


class QosPolicyRuleTest(TestQosOps):

    @decorators.idempotent_id('3566016a-31cc-4905-b217-98844caad4a9')
    def test_qos_bw_dscp_rule_network(self):
        """
        Test qos and bw dscp rule by sending traffic between two instance
        and verifying if traffic is rate-limited and marked with dscp value
        """
        self.define_security_groups()
        qos_bw_dscp_dict = self.create_qos_bw_dscp_setup(
            bw_value_kbps=BW_VALUE_KBPS,
            dscp_mark=DSCP_MARK)
        self.admin_mgr.networks_client.update_network(
            qos_bw_dscp_dict['network_qos']['id'],
            qos_policy_id=qos_bw_dscp_dict['policy_id'])
        updated_network = self.admin_mgr.networks_client.show_network(
            qos_bw_dscp_dict['network_qos']['id'])
        qos_network = updated_network.get('network', updated_network)
        self.assertEqual(
            qos_bw_dscp_dict['policy_id'], qos_network['qos_policy_id'])
        self.create_vms(qos_bw_dscp_dict['network_qos'])
        #sleep to ensure VMs have finished complete bootup
        time.sleep(240)
        #check bandwidth rule
        self.verify_bandwidth_rule(max_mbps=BW_VALUE_MBPS)
        #check dscp rule
        self.verify_dscp_rule(dscp_value=DSCP_MARK)

    @decorators.idempotent_id('c545c322-b37e-45e2-af22-b160a5320594')
    def test_qos_bw_dscp_rule_port(self):
        """
        Test qos and bw dscp rule by sending traffic between two instance
        and verifying if traffic is rate-limited and marked with dscp value
        """
        self.define_security_groups()
        qos_bw_dscp_dict = self.create_qos_bw_dscp_setup(
            bw_value_kbps=BW_VALUE_KBPS,
            dscp_mark=DSCP_MARK)
        qos_src_vm, qos_dst_vm = self.create_vms(
            qos_bw_dscp_dict['network_qos'])
        self.os_admin.ports_client.update_port(
            qos_src_vm['floating_ips'][0]['port_id'],
            qos_policy_id=qos_bw_dscp_dict['policy_id'])
        self.os_admin.ports_client.update_port(
            qos_dst_vm['floating_ips'][0]['port_id'],
            qos_policy_id=qos_bw_dscp_dict['policy_id'])
        #sleep to ensure VMs have finished complete bootup
        time.sleep(240)
        #check bandwidth rule
        self.verify_bandwidth_rule(max_mbps=BW_VALUE_MBPS)
        #check dscp rule
        self.verify_dscp_rule(dscp_value=DSCP_MARK)

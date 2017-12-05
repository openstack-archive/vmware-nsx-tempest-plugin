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

from tempest.common import utils
from tempest import config
from tempest.lib import decorators

from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestNetOps(feature_manager.FeatureManager):
    """Test TestNetOps.

    Adding test cases to test network ops.
    """

    def setUp(self):
        super(TestNetOps, self).setUp()
        self.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                            CONF.nsxv3.nsx_user,
                                            CONF.nsxv3.nsx_password)

    @classmethod
    def skip_checks(cls):
        """Class level skip checks.

        Class level check. Skip all the MDproxy tests, if native_dhcp_metadata
        is not True under nsxv3 section of the config
        """
        super(TestNetOps, cls).skip_checks()

    def define_security_groups(self):
        self.net_ssh_icmp_sg = self.create_topology_empty_security_group(
            namestart="net_ssh_icmp_sg")
        # Common rules to allow the following traffic
        # 1. Egress ICMP IPv4 any any
        # 3. Ingress ICMP IPv4
        # 4. Ingress TCP 22 (SSH) from public network
        ruleset = [dict(direction='egress', protocol='icmp'),
                   dict(direction='ingress', protocol='icmp'),
                   dict(direction='ingress', protocol='tcp',
                        port_range_min=22, port_range_max=22,
                        remote_ip_prefix=CONF.network
                        .public_network_cidr)]
        for rule in ruleset:
            self.add_security_group_rule(self.net_ssh_icmp_sg, rule)

    def deploy_net_topology(self):
        router_ops = self.create_topology_router("router_ops")
        network_ops = self.create_topology_network("network_ops")
        self.create_topology_subnet("subnet_ops", network_ops,
            router_id=router_ops["id"])
        self.create_topology_instance(
            "server_ops", [network_ops],
            security_groups=[{'name': self.net_ssh_icmp_sg['name']}])

    def verify_ping_to_fip_from_ext_vm(self, server_details):
        self.using_floating_ip_check_server_and_project_network_connectivity(
            server_details)

    def verify_ping_own_fip(self, server):
        fip = server["floating_ips"][0]["floating_ip_address"]
        client = self.verify_server_ssh(server, floating_ip=fip)
        ping_cmd = "ping -c 1 %s " % fip
        self.exec_cmd_on_server_using_fip(ping_cmd, ssh_client=client)

    @decorators.idempotent_id("b24c2a91-aa7a-4c04-82b0-8508adba1388")
    @utils.services("network")
    def test_ping_vms_own_fip(self):
        # Define security group
        self.define_security_groups()
        # Deploy topology without tier1 router
        self.deploy_net_topology()
        # Verify fip ping
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)
        self.verify_ping_own_fip(self.topology_servers["server_ops"])

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

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client

CONF = config.CONF
LOG = constants.log.getLogger(__name__)


class ProviderSecGroupTrafficScenario(feature_manager.FeatureManager):
    """Test Provider Sec group Traffic Scenario

    """

    @classmethod
    def skip_checks(cls):
        super(ProviderSecGroupTrafficScenario, cls).skip_checks()
        if not test.is_extension_enabled('provider-security-group', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(ProviderSecGroupTrafficScenario, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(ProviderSecGroupTrafficScenario, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    def define_security_groups(self):
        self.provider_sg = self.create_topology_empty_security_group(
            namestart="provider_sg_")
        # Common rules to allow the following traffic
        # 1. Egress ICMP IPv4 any any
        # 2. Egress ICMP IPv6 any any
        # 3. Ingress ICMP IPv4 from public network
        # 4. Ingress TCP 22 (SSH) from public network
        # 5. Ingress/Egress TCP 49162 port allow
        common_ruleset = [dict(direction='egress', protocol='icmp'),
                          dict(direction='egress', protocol='icmp',
                               ethertype='IPv6'),
                          dict(direction='egress', protocol='tcp',
                               port_range_min=22, port_range_max=22),
                          dict(direction='egress', protocol='tcp',
                               port_range_min=49162, port_range_max=49162),
                          dict(direction='ingress', protocol='tcp',
                               port_range_min=49162, port_range_max=49162),
                          dict(direction='ingress', protocol='tcp',
                               port_range_min=22, port_range_max=22),
                          dict(direction='egress', protocol='udp'),
                          dict(direction='ingress', protocol='udp'),
                          dict(direction='ingress', protocol='icmp')]
        for rule in common_ruleset:
            self.add_security_group_rule(self.provider_sg, rule)

    def create_psg_topo(self):
        """
        Create Provider sec group basic topo
        """
        self.define_security_groups()
        network = \
            self.create_topology_network(network_name="provider-sec-net")
        router_name = 'psg-router'
        router = self.create_topology_router(router_name)
        subnet_name = 'psg-subnet'
        self.create_topology_subnet(subnet_name, network,
                                    router_id=router['id'])
        image_id = self.get_glance_image_id('debian')
        self.create_topology_instance(
            "psg-server1", [network],
            security_groups=[{'name': self.provider_sg['name']}],
            image_id=image_id)
        self.create_topology_instance(
            "psg-server2", [network],
            security_groups=[{'name': self.provider_sg['name']}],
            image_id=image_id)

    def create_psg_topo_across_networks(self):
        """
        Create Provider sec group topo using 2 logical switches which are
        connected via tier-1 router.
        """
        self.define_security_groups()
        network = \
            self.create_topology_network(network_name="provider-sec-net")
        router_name = 'psg-router'
        router = self.create_topology_router(router_name)
        subnet_name = 'psg-subnet'
        subnet_name1 = 'psg-subnet1'
        network1 = \
            self.create_topology_network(network_name="provider-sec-net1")
        self.create_topology_subnet(subnet_name, network,
                                    router_id=router['id'])
        self.create_topology_subnet(subnet_name1, network1,
                                    router_id=router['id'],
                                    cidr='33.0.0.0/24')
        image_id = self.get_glance_image_id('debian')
        self.create_topology_instance(
            "psg-server1", [network],
            security_groups=[{'name': self.provider_sg['name']}],
            image_id=image_id)
        self.create_topology_instance(
            "psg-server2", [network1],
            security_groups=[{'name': self.provider_sg['name']}],
            image_id=image_id)

    def check_traffic_topology(self, across_networks=False):
        """
        Prepare traffic topology to check UDP/TCP traffic during
        port-security is enabled for TCP but disbaled for udp and vice-versa.
        update port with port-security enabled and disabled.
        """
        constants.NSX_BACKEND_TIME_INTERVAL
        # check iperf traffic when udp traffic when everything is allowed
        self.use_iperf_send_traffic(
            src_server=self.topology_servers["psg-server1"],
            dst_server=self.topology_servers["psg-server2"],
            traffic_type='udp')
        project_id = self.topology_networks['provider-sec-net']['tenant_id']
        # Create provider sec group icmp
        sg = self.create_topology_security_provider_group(
            client=self.cmgr_adm, provider=True, project_id=project_id)
        icmp_rule = dict(direction='ingress', protocol='icmp')
        # Add rule to provider sec group
        self.add_security_group_rule(
            sg,
            icmp_rule,
            tenant_id=project_id,
            ruleclient=self.cmgr_adm.security_group_rules_client,
            secclient=self.cmgr_adm.security_groups_client)
        p_client = self.ports_client
        kwargs = {"provider_security_groups": ["%s" % sg.get('id')]}
        constants.NSX_BACKEND_TIME_INTERVAL
        # check iperf traffic when tcp traffic when icmp is disallowed
        self.use_iperf_send_traffic(
            src_server=self.topology_servers["psg-server1"],
            dst_server=self.topology_servers["psg-server2"],
            traffic_type='tcp')
        if across_networks:
            port_id_psg2 = self._get_port_id(
                self.topology_networks['provider-sec-net1']['id'],
                self.topology_subnets['psg-subnet1']['id'],
                self.topology_servers['psg-server2'])
        else:
            port_id_psg2 = self._get_port_id(
                self.topology_networks['provider-sec-net']['id'],
                self.topology_subnets['psg-subnet']['id'],
                self.topology_servers['psg-server2'])
        # Update dest port with provider sec group
        p_client.update_port(port_id_psg2, **kwargs)
        constants.NSX_BACKEND_TIME_INTERVAL
        self.use_iperf_send_traffic(
            src_server=self.topology_servers["psg-server1"],
            dst_server=self.topology_servers["psg-server2"],
            traffic_type='udp')
        tcp_rule = [dict(direction='egress', protocol='tcp',
                         port_range_min=49162, port_range_max=49162),
                    dict(direction='ingress', protocol='tcp',
                         port_range_min=49162, port_range_max=49162)]
        for tcp in tcp_rule:
            self.add_security_group_rule(
                sg,
                tcp,
                tenant_id=project_id,
                ruleclient=self.cmgr_adm.security_group_rules_client,
                secclient=self.cmgr_adm.security_groups_client)
        constants.NSX_BACKEND_TIME_INTERVAL
        self.use_iperf_send_traffic(
            src_server=self.topology_servers["psg-server1"],
            dst_server=self.topology_servers["psg-server2"],
            traffic_type='udp')
        constants.NSX_BACKEND_TIME_INTERVAL
        # Adding udp rules is drop
        udp_rule = [dict(direction='egress', protocol='udp',
                         port_range_min=49162, port_range_max=49162),
                    dict(direction='ingress', protocol='udp',
                         port_range_min=49162, port_range_max=49162)]
        for udp in udp_rule:
            self.add_security_group_rule(
                sg,
                udp,
                tenant_id=project_id,
                ruleclient=self.cmgr_adm.security_group_rules_client,
                secclient=self.cmgr_adm.security_groups_client)
        try:
            # check iperf traffic when tcp rules is drop and udp is allow
            constants.NSX_BACKEND_TIME_INTERVAL
            self.use_iperf_send_traffic(
                src_server=self.topology_servers["psg-server1"],
                dst_server=self.topology_servers["psg-server2"],
                traffic_type='udp')
        except BaseException:
            pass
        try:
            # check iperf traffic when tcp rules is drop
            constants.NSX_BACKEND_TIME_INTERVAL
            self.use_iperf_send_traffic(
                src_server=self.topology_servers["psg-server1"],
                dst_server=self.topology_servers["psg-server2"],
                traffic_type='tcp')
        except BaseException:
            pass
        # Remove provider security group
        kwargs = {"provider_security_groups": []}
        p_client.update_port(port_id_psg2, **kwargs)
        constants.NSX_BACKEND_TIME_INTERVAL
        self.use_iperf_send_traffic(
            src_server=self.topology_servers["psg-server1"],
            dst_server=self.topology_servers["psg-server2"],
            traffic_type='udp')
        constants.NSX_BACKEND_TIME_INTERVAL
        self.use_iperf_send_traffic(
            src_server=self.topology_servers["psg-server1"],
            dst_server=self.topology_servers["psg-server2"],
            traffic_type='tcp')

    @decorators.idempotent_id('1206016a-91cc-8905-b217-98844caa24a1')
    def test_psg_traffic(self):
        """
        Check provider secgroup traffic between 2 vms which are connected via
        same network.
        """
        self.create_psg_topo()
        self.check_traffic_topology()

    @decorators.idempotent_id('9366016a-33cc-6905-b217-98844c11d459')
    def test_psg_traffic_accross_networks(self):
        """
        Check provider secgroup traffic between 2 vms which are connected via
        differnet network via Tier-1 router.
        """
        self.create_psg_topo_across_networks()
        self.check_traffic_topology(across_networks=True)

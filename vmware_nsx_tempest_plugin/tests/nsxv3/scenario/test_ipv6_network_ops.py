
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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from vmware_nsx_tempest_plugin.lib import feature_manager
CONF = config.CONF


class NetworkOpsTest(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(NetworkOpsTest, cls).skip_checks()
        if not (CONF.network_feature_enabled.ipv6 and
                CONF.network_feature_enabled.ipv6_subnet_attributes):
            raise cls.skipException('IPv6 or its attributes not supported')
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(NetworkOpsTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(NetworkOpsTest, cls).resource_setup()

    def _create_ipv6_subnet(self, network, router):
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network['name'] + 'ipv6-sub'
        address_cidr = CONF.network.project_network_v6_cidr
        address_prefixlen = CONF.network.project_network_v6_mask_bits
        if ((address_prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address_cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools': [{
                            'start': str(address_cidr).split('/')[0] + '2',
                            'end':str(address_cidr).split('/')[0] + '70'}]}
        subnet = self.create_topology_subnet(subnet_name, network,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            ip_version=6, ipv6_ra_mode='slaac',
            ipv6_address_mode='slaac',
            **allocation_pools)
        return subnet

    def _create_single_ipv6_rtr_topology(self):
        """Create dual stack network with IPv4
           and IPv6 subnet and attach them to a 
           router
        """
        rtr_name = data_utils.rand_name("dual-rtr")
        router = self.create_topology_router(
            rtr_name, routers_client=self.cmgr_adm.routers_client)
        name = data_utils.rand_name("dual-network")
        networks_client = self.cmgr_adm.networks_client
        network = self.create_topology_network(name,
                                               networks_client=networks_client)
        self._create_ipv6_subnet(network, router)
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network['name'] + 'ipv4-sub'
        self.create_topology_subnet(subnet_name, network,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'])
        return network, router

    def _create_single_rtr_multiple_net_topology(self):
        """Create two dual stack networks with IPv4
           and IPv6 subnet and attach them to the 
           same router
        """ 
        rtr_name = data_utils.rand_name("dual-rtr")
        router = self.create_topology_router(
            rtr_name, routers_client=self.cmgr_adm.routers_client)
        name = data_utils.rand_name("dual-network-1")
        networks_client = self.cmgr_adm.networks_client
        network_1 = self.create_topology_network(name,
            networks_client=networks_client)
        self._create_ipv6_subnet(network_1, router)
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network_1['name'] + 'ipv4-sub'
        self.create_topology_subnet(subnet_name, network_1,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            ip_version=6, enable_dhcp=False,
            **allocation_pools)
        name = data_utils.rand_name("dual-network-2")
        network_2 = self.create_topology_network(name,
            networks_client=networks_client)
        self._create_ipv6_subnet(network_2, router)
        subnet_name = network_2['name'] + 'ipv4-sub'
        self.create_topology_subnet(subnet_name, network_2,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            ip_version=6, enable_dhcp=False,
            **allocation_pools)
        networks = [network_1, network_2]
        return networks, router

    def _create_security_group(self):
        sec_rule_client = self.cmgr_adm.security_group_rules_client
        sec_client = self.cmgr_adm.security_groups_client
        kwargs = dict(tenant_id=network['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        sg = self._create_empty_security_group(
            namestart="tempest-ipv6-", client=sec_client)
        common_ruleset = [dict(direction='egress', protocol='icmp'),
                          dict(direction='egress', protocol='icmp',
                               ethertype='IPv6'),
                          dict(direction='ingress', protocol='tcp',
                               port_range_min=22, port_range_max=22,
                               remote_ip_prefix=CONF.network
                               .public_network_cidr),
                          dict(direction='ingress', protocol='icmp',
                               remote_ip_prefix=CONF.network
                               .public_network_cidr)]
        for rule in common_ruleset:
            self._create_security_group_rule(
                sec_group_rules_client=sec_rule_client,
                security_groups_client=sec_client,
                secgroup=sg,
                **rule)
        return sg

    @decorators.attr(type=['nsxv3', 'positive'])
    @decorators.idempotent_id('67dc21c8-0f40-4bee-bc03-e44538437e19')
    def test_ipv4_v6_connectivity_same_network(self):
        """Test IPv4 and IPv6 connectivity across
           VMs connected across same network
        """
        #Create topology with single router
        network, rtr = self._create_single_ipv6_rtr_topology()
        sg = self._create_security_group()
        #Boot two VMs on the same network
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        self.create_topology_instance(
            "vm_1", [network],
            security_groups=[{'name': sg['name']}],
            create_floating_ip=True, image_id=image_id,
            clients=self.cmgr_adm)
        vm1_server_floatingip = self.topology_servers["vm_1"][
            "floating_ips"][0]["floating_ip_address"]
        self.create_topology_instance(
            "vm_2", [network],
            security_groups=[{'name': sg['name']}],
            create_floating_ip=True, image_id=image_id,
            clients=self.cmgr_adm)
        vm2_server_floatingip = self.topology_servers["vm_2"][
            "floating_ips"][0]["floating_ip_address"]
        #Check connectivity across the same network
        vm1_server = self.topology_servers["vm_1"]
        vm2_server = self.topology_servers["vm_2"]
        self.check_vm_internal_connectivity(network,
           vm1_server_floatingip, vm1_server)
        self.check_vm_internal_connectivity(network,
           vm2_server_floatingip, vm2_server)

    @decorators.attr(type=['nsxv3', 'positive'])
    @decorators.idempotent_id('0074ae58-2de9-4cb2-a225-12a2b093f8d2')
    def test_ipv4_v6_connectivity_same_rtr_diff_network(self):
        """Test IPv4 and IPv6 connectivity across
           VMs connected across different networks
           on the same router
        """
        #Create topology with single router
        networks, rtr=self._create_single_rtr_multiple_net_topology()
        sg = self._create_security_group()
        #Boot two VMs on the different network
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        self.create_topology_instance(
            "vm_1", [networks[0]],
            security_groups=[{'name': sg['name']}],
            create_floating_ip=True, image_id=image_id, clients=self.cmgr_adm)
        vm1_server_floatingip = self.topology_servers["vm_1"][
            "floating_ips"][0]["floating_ip_address"]
        self.create_topology_instance(
            "vm_2", [networks[1]],
            security_groups=[{'name': sg['name']}],
            create_floating_ip=True, image_id=image_id, clients=self.cmgr_adm)
        vm2_server_floatingip = self.topology_servers["vm_2"][
            "floating_ips"][0]["floating_ip_address"]
        #Check connectivity across the same network
        vm1_server = self.topology_servers["vm_1"]
        vm2_server = self.topology_servers["vm_2"]
        self.check_vm_internal_connectivity(networks[0],
           vm1_server_floatingip, vm1_server)
        self.check_vm_internal_connectivity(networks[1],
           vm2_server_floatingip, vm2_server)
        #Check connectivity across differnet network
        #checking VM2 Connectivity with VM1's network
        self.check_cross_network_connectivity(
            networks[0],vm2_server_floatingip,vm2_server)
        #checking VM1 Connectivity with VM2's network
        self.check_cross_network_connectivity(
            networks[1],vm1_server_floatingip,vm1_server)

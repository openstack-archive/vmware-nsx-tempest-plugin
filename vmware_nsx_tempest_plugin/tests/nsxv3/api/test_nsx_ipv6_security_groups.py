
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
from tempest.lib import exceptions

from vmware_nsx_tempest_plugin.lib import feature_manager
CONF = config.CONF


class IPv6SecurityGroupsTest(feature_manager.FeatureManager):
    """Test the following operations for security groups:
        port create
        port delete
        port list
        port show
        port update
    """

    @classmethod
    def skip_checks(cls):
        super(IPv6SecurityGroupsTest, cls).skip_checks()
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
        super(IPv6SecurityGroupsTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(IPv6SecurityGroupsTest, cls).resource_setup()

    def _create_ipv6_topology(self):
        name = "ipv6-network"
        networks_client = self.cmgr_adm.networks_client
        network = self.create_topology_network(name,
                                               networks_client=networks_client)
        address_cidr = CONF.network.project_network_v6_cidr
        address_prefixlen = CONF.network.project_network_v6_mask_bits
        if ((address_prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address_cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools': [{
                            'start': str(address_cidr).split('/')[0] + '2',
                            'end':str(address_cidr).split('/')[0] + '70'}]}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network['name'] + 'sub'
        self.create_topology_subnet(subnet_name, network,
                                    subnets_client=subnet_client,
                                    ip_version=6, enable_dhcp=False,
                                    **allocation_pools)
        return network

    def _create_ipv4_v6_topology(self):
        name = "ipv4-v6-network"
        networks_client = self.cmgr_adm.networks_client
        network = self.create_topology_network(name,
                                               networks_client=networks_client)
        address_cidr = CONF.network.project_network_v6_cidr
        address_prefixlen = CONF.network.project_network_v6_mask_bits
        if ((address_prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address_cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools': [{
                            'start': str(address_cidr).split('/')[0] + '2',
                            'end':str(address_cidr).split('/')[0] + '70'}]}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_name = network['name'] + 'ipv6-sub'
        self.create_topology_subnet(subnet_name, network,
                                    subnets_client=subnet_client,
                                    ip_version=6, enable_dhcp=False,
                                    **allocation_pools)
        subnet_name = network['name'] + 'ipv4-sub'
        self.create_topology_subnet(subnet_name, network,
                                    subnets_client=subnet_client)
        return network

    @decorators.attr(type=['nsxv3', 'positive'])
    @decorators.idempotent_id('a8dfdba6-7dcf-4082-9669-0fbaa4b0fb2c')
    def test_create_security_group_rules_with_v4_v6_prefix(self):
        """
        Test create security group with ipv4
        and ipv6 remote ip prefix rules
        """
        sg = self.create_topology_security_group()
        ipv4_prefix = "192.168.1.0/24"
        ipv6_prefix = "2010:1:10::/64"
        sg_ipv4_rule = self.add_security_group_rule(
            security_group=sg,
            protocol='tcp', ethertype='IPv4',
            direction='ingress',
            remote_ip_prefix=ipv4_prefix)
        self.assertEqual(sg_ipv4_rule['remote_ip_prefix'], ipv4_prefix)
        sg_ipv6_rule = self.add_security_group_rule(
            security_group=sg,
            protocol='tcp', ethertype='IPv6',
            direction='egress',
            remote_ip_prefix=ipv6_prefix)
        self.assertEqual(sg_ipv6_rule['remote_ip_prefix'], ipv6_prefix)

    @decorators.attr(type=['nsxv3', 'positive'])
    @decorators.idempotent_id('037413a8-0db7-411a-a389-0ecc9007b6ef')
    def test_create_security_group_with_ipv6_port(self):
        """
        Test create security group with ipv6 rule
        and attach to port with ipv6 address
        """
        sec_client = self.cmgr_adm.security_groups_client
        sec_rule_client = self.cmgr_adm.security_group_rules_client
        network = self._create_ipv6_topology()
        sec_group = self._create_empty_security_group(
            namestart="tempest-ipv6-", client=sec_client)
        rule = dict(
                   direction='ingress',
                   ethertype='IPv6',
                   protocol='udp',
                   remote_ip_prefix='2010:1:10::/64')
        sg_ipv6_rule = self._create_security_group_rule(
            sec_group_rules_client=sec_rule_client,
            security_groups_client=sec_client,
            secgroup=sec_group,
            **rule)
        port_client = self.cmgr_adm.ports_client
        body = self.create_topology_port(network=network,
                                         ports_client=port_client,
                                         security_groups=[sec_group['id']])
        port = body['port']
        for sg in port["security_groups"]:
            self.assertEqual(sg, sec_group['id'])

    @decorators.attr(type=['nsxv3', 'positive'])
    @decorators.idempotent_id('0604fee9-011e-4b5e-886a-620669a8c2f5')
    def test_create_security_group_with_ipv4_v6_port(self):
        """
        Test create security group with ipv6 rule
        and attach to port with ipv6 address
        """
        sec_client = self.cmgr_adm.security_groups_client
        sec_rule_client = self.cmgr_adm.security_group_rules_client
        network = self._create_ipv4_v6_topology()
        sec_group = self._create_empty_security_group(
            namestart="tempest-ipv6-", client=sec_client
            )
        rule = dict(
                   direction='ingress',
                   ethertype='IPv6',
                   protocol='tcp')
        self._create_security_group_rule(
            sec_group_rules_client=sec_rule_client,
            security_groups_client=sec_client,
            secgroup=sec_group,
            **rule)
        port_client = self.cmgr_adm.ports_client
        body = self.create_topology_port(network=network,
                                         ports_client=port_client,
                                         security_groups=[sec_group['id']])
        port = body['port']
        for sg in port["security_groups"]:
            self.assertEqual(sg, sec_group['id'])

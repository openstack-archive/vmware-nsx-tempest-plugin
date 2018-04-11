# Copyright 2017 VMware, Inc.
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
from tempest import test

from vmware_nsx_tempest.lib import feature_manager


CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestZonesV2Ops(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestZonesV2Ops, cls).skip_checks()
        if not test.is_extension_enabled('designate', 'network'):
            msg = "Extension designate is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        cls.admin_mgr = cls.get_client_manager('admin')
        super(TestZonesV2Ops, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestZonesV2Ops, cls).setup_clients()

    def define_security_groups(self):
        self.zone_sg = self.create_topology_empty_security_group(
            namestart="zone_sg_")
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


class TestZonesScenario(TestZonesV2Ops):

    @decorators.idempotent_id('e26cf8c6-164d-4097-b066-4e2100382d53')
    def test_network_zone_update(self):
        """
        Test
        Create a zone, check zone exits, create a network
        update network with the zone
        """
        LOG.info('Create a zone')
        zone = self.create_zone(wait_until=True)
        LOG.info('Ensure we respond with CREATE+PENDING')
        self.assertEqual('CREATE', zone['action'])
        self.assertEqual('PENDING', zone['status'])
        network_designate = self.create_topology_network(
                            "network_designate", dns_domain=zone['name'])
        self.create_topology_subnet("subnet_designate", network_designate)
        self.assertEqual(network_designate['dns_domain'], zone['name'])
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.assertEqual(recordset['metadata']['total_count'], 2)
        if any(record['type'] == 'NS' for record in recordset['recordsets']):
            LOG.info('NS record is present')
        else:
            LOG.error('NS record is missing')
        if any(record['type'] == 'SOA' for record in recordset['recordsets']):
            LOG.info('SOA record if present')
        else:
            LOG.info('NS record is missing')

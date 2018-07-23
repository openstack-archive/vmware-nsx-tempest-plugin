# Copyright 2018 VMware, Inc.
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
import dns.resolver

import time

from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from vmware_nsx_tempest_plugin.common import constants as const
from vmware_nsx_tempest_plugin.lib import feature_manager


CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestZonesV2Ops(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestZonesV2Ops, cls).skip_checks()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestZonesV2Ops, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    def define_security_groups(self, tenant_id):
        sec_rule_client = self.os_admin.security_group_rules_client
        sec_client = self.os_admin.security_groups_client
        kwargs = dict(tenant_id=tenant_id,
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.designate_sg = self.create_topology_security_group(
            **kwargs)
        common_ruleset = [dict(direction='egress', protocol='tcp',
                               port_range_min=53, port_range_max=53, ),
                          dict(direction='ingress', protocol='tcp',
                               port_range_min=53, port_range_max=53, )]
        for rule in common_ruleset:
            self.add_security_group_rule(self.designate_sg, rule,
                ruleclient=sec_rule_client, secclient=sec_client,
                tenant_id=tenant_id)

    def create_designate_zone(self):
        LOG.info('Create a zone')
        zone = self.create_zone(wait_until=True)
        LOG.info('Ensure we respond with CREATE+PENDING')
        self.assertEqual('CREATE', zone['action'])
        self.assertEqual('PENDING', zone['status'])
        return zone

    def create_zone_topology(self, zone_name):
        networks_client = self.cmgr_adm.networks_client
        network_designate = self.create_topology_network(
            "network_designate", networks_client=networks_client,
            dns_domain=zone_name)
        tenant_id = network_designate['tenant_id']
        self.define_security_groups(tenant_id)
        subnet_client = self.os_adm.subnets_client
        routers_client = self.os_adm.routers_client
        router_designate = self.create_topology_router("router_designate",
            routers_client=routers_client)
        self.create_topology_subnet("subnet_designate",
            network_designate, subnets_client=subnet_client,
            routers_client=routers_client, router_id=router_designate['id'])
        return network_designate

    def verify_recordset(self, record_set, count):
        self.assertEqual(record_set[1]['metadata']['total_count'], count)
        if any(record['type'] == 'NS'
               for record in record_set[1]['recordsets']):
            LOG.info('NS record is present')
        else:
            LOG.error('NS record is missing')
            raise Exception('ERROR: NS record is absent')
        if any(record['type'] == 'SOA'
               for record in record_set[1]['recordsets']):
            LOG.info('SOA record is present')
        else:
            LOG.error('SOA record is missing')
            raise Exception('ERROR: SOA record is absent')
        if count == 3:
            if any(record['type'] == 'A'
                   for record in record_set[1]['recordsets']):
                LOG.info('A record is present')
            else:
                LOG.error('A record is missing')
                raise Exception('ERROR: A record is absent')

    def verify_recordset_floatingip(self, record_set, fip):
        for record in record_set[1]['recordsets']:
            if record['type'] == 'A':
                if record['records'][0] == fip:
                    LOG.info('Record contains fip of the vm')
                    return record
        return None


class TestZonesScenario(TestZonesV2Ops):

    @decorators.idempotent_id('17ba050e-8256-4ff5-bc9e-8da7628c433c')
    def test_zone_list_without_fip_instance(self):
        """
        Create a zone, check zone exits
        Create a network and subnet
        Update network with the zone
        Boot a VM
        Verify recordset only has SOA and NS record types
        """
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        zone = self.create_designate_zone()
        network_designate = self.create_zone_topology(zone['name'])
        self.assertEqual(network_designate['dns_domain'], zone['name'])
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)
        self.create_topology_instance(
            "dns_vm", [network_designate],
            security_groups=[{'name': self.designate_sg['name']}],
            clients=self.os_adm,
            create_floating_ip=False, image_id=image_id)
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)

    @decorators.idempotent_id('a4de3cca-54e1-4e8b-8b52-2148e55eed84')
    def test_zone_list_with_fip_instance(self):
        """
        Create a zone, check zone exits
        Create a network and subnet
        Update network with the zone
        Boot a VM and associate fip
        Verify recordset contains entry for fip
        """
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        zone = self.create_zone()
        network_designate = self.create_zone_topology(zone['name'])
        self.assertEqual(network_designate['dns_domain'], zone['name'])
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)
        dns_vm = self.create_topology_instance(
            "dns_vm", [network_designate],
            security_groups=[{'name': self.designate_sg['name']}],
            clients=self.os_adm,
            create_floating_ip=True, image_id=image_id)
        fip = dns_vm['floating_ips'][0]['floating_ip_address']
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 3)
        record = self.verify_recordset_floatingip(recordset, fip)
        if record is None:
            raise Exception('fip is missing in the recordset')

    @decorators.idempotent_id('c7a169ce-365d-40ac-8690-003bf6c623fd')
    def test_zone_list_with_fip_deletion_instance(self):
        """
        Create a zone, check zone exits
        Create a network and subnet
        Update network with the zone
        Boot a VM and assign fip
        Verify recordset contains the fip
        Delete VM
        Verify recordset does not have entry for fip
        """
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        zone = self.create_zone()
        network_designate = self.create_zone_topology(zone['name'])
        self.assertEqual(network_designate['dns_domain'], zone['name'])
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)
        dns_vm = self.create_topology_instance(
            "dns_vm", [network_designate],
            security_groups=[{'name': self.designate_sg['name']}],
            clients=self.os_adm,
            create_floating_ip=True, image_id=image_id)
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        fip = dns_vm['floating_ips'][0]['floating_ip_address']
        self.verify_recordset(recordset, 3)
        self.verify_recordset_floatingip(recordset, fip)
        fip_id = dns_vm['floating_ips'][0]['id']
        self.os_admin.floating_ips_client.delete_floatingip(fip_id)
        self.os_admin.servers_client.delete_server(dns_vm['id'])
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)

    @decorators.idempotent_id('4375b8fb-54c0-403d-a65b-ae6744dcad86')
    def test_zone_list_without_fip_port(self):
        """
        Create a zone, check zone exits
        Create a network and subnet
        Update network with the zone
        Create a port
        Verify zone record set has SOA and NS record typres
        """
        zone = self.create_designate_zone()
        network_designate = self.create_zone_topology(zone['name'])
        self.assertEqual(network_designate['dns_domain'], zone['name'])
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)
        ports_client = self.os_admin.ports_client
        self.create_topology_port(network_designate, ports_client)
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)

    @decorators.idempotent_id('f7df72d8-ee96-4a7a-b03d-ca6d04b9f589')
    def test_zone_list_with_fip_port(self):
        """
        Create a zone, check zone exits
        Create a network and subnet
        Update network with the zone
        Create a port and assign fip
        Verify record set for the zone contains fip
        """
        zone = self.create_zone()
        network_designate = self.create_zone_topology(zone['name'])
        self.assertEqual(network_designate['dns_domain'], zone['name'])
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)
        ports_client = self.os_admin.ports_client
        post_body = {"dns_name": "tempest-port"}
        port = self.create_topology_port(network_designate, ports_client,
            **post_body)
        fip = self.create_floatingip(port['port'], port['port']['id'],
            client=self.os_admin.floating_ips_client)
        time.sleep(const.ZONE_WAIT_TIME)
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 3)
        record = self.verify_recordset_floatingip(recordset,
            fip['floating_ip_address'])
        if record is None:
            raise Exception('fip is missing in the recordset')

    @decorators.idempotent_id('863ebce1-9a4c-43c3-95d8-ad0b4c3f4b36')
    def test_zone_nslookup_from_extvm(self):
        """
        Create a zone
        Update network with zone
        Boot an instance and associate fip
        Perform nslookup for the dns name from ext vm
        """
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        zone = self.create_zone()
        network_designate = self.create_zone_topology(zone['name'])
        self.assertEqual(network_designate['dns_domain'], zone['name'])
        dns_vm = self.create_topology_instance(
            "dns_vm", [network_designate],
            security_groups=[{'name': self.designate_sg['name']}],
            clients=self.os_adm,
            create_floating_ip=True, image_id=image_id)
        fip = dns_vm['floating_ips'][0]['floating_ip_address']
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 3)
        record = self.verify_recordset_floatingip(recordset, fip)
        if record is None:
            raise Exception('fip is missing in the recordset')
        my_resolver = dns.resolver.Resolver()
        nameserver = CONF.dns.nameservers[:-3]
        my_resolver.nameservers = [nameserver]
        #wait for status to change from pending to active
        time.sleep(const.ZONE_WAIT_TIME)
        try:
            answer = my_resolver.query(record['name'])
        except Exception:
            LOG.error('ns lookup failed on ext-vm')
        if (record['name'] not in answer.response.to_text()
           or fip not in answer.response.to_text()):
            LOG.error('failed to resolve dns for the instance')
            raise Exception('DNS response does not have entry '
                            'for the instance')

    @decorators.idempotent_id('6286cbd5-b0e4-4daa-9d8f-f27802c95925')
    def test_zone_deletion_post_fip_association(self):
        """
        Create a zone
        Update network with zone
        Boot an instance and associate fip
        Delete zone successfully
        """
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        zone = self.create_zone()
        network_designate = self.create_zone_topology(zone['name'])
        self.assertEqual(network_designate['dns_domain'], zone['name'])
        dns_vm = self.create_topology_instance(
            "dns_vm", [network_designate],
            security_groups=[{'name': self.designate_sg['name']}],
            clients=self.os_adm,
            create_floating_ip=True, image_id=image_id)
        fip = dns_vm['floating_ips'][0]['floating_ip_address']
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 3)
        record = self.verify_recordset_floatingip(recordset, fip)
        if record is None:
            raise Exception('fip is missing in the recordset')
        LOG.info('Delete the zone')
        body = self.delete_zone(zone['id'])
        LOG.info('Ensure we respond with DELETE+PENDING')
        self.assertEqual('DELETE', body['action'])
        self.assertEqual('PENDING', body['status'])
        # sleep for delete zone to change from PENDING to SUCCESS
        time.sleep(const.ZONE_WAIT_TIME)
        self.assertRaises(lib_exc.NotFound, self.delete_zone,
                          zone['id'])

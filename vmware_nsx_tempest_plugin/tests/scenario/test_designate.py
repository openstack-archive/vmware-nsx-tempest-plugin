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
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxv_client

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

    @classmethod
    def resource_setup(cls):
        super(TestZonesV2Ops, cls).resource_setup()
        if CONF.network.backend == 'nsxv':
            manager_ip = CONF.nsxv.manager_uri.split("/")[2]
            cls.nsx = nsxv_client.VSMClient(manager_ip,
                                            CONF.nsxv.user,
                                            CONF.nsxv.password)
            out = cls.nsx.get_all_vdn_scopes()
        else:
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
            out = cls.nsx.get_transport_zones()
        vlan_flag = 0
        vxlan_flag = 0
        for tz in out:
            if "transport_type" in tz.keys() and (vlan_flag == 0
                                                  or vxlan_flag == 0):
                if vxlan_flag == 0 and tz['transport_type'] == "OVERLAY":
                    cls.overlay_id = tz['id']
                    vxlan_flag = 1
                if vlan_flag == 0 and tz['transport_type'] == "VLAN":
                    cls.vlan_id = tz['id']
                    vlan_flag = 1

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

    def create_zone_provider_vlan_vxlan_topology(self, network_type,
                                                 zone_name):
        if network_type == 'vlan':
            network_designate = self.create_provider_network(
                const.VLAN_TYPE,
                zone_name,
                tz_id=self.vlan_id)
        elif network_type == 'vxlan':
            network_designate = self.create_provider_network(
                const.VXLAN_TYPE,
                zone_name,
                tz_id=self.overlay_id)
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
        zone = self.create_zone()
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

    @decorators.idempotent_id('6cb8ce24-f19f-466d-9386-ae0d45ed518f')
    def test_zone_list_without_fip_instance_provider_vxlan(self):
        """
        Create a zone, check zone exits
        Create a network and subnet
        Update network with the zone
        Boot a VM
        Verify recordset only has SOA and NS record types
        """
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        zone = self.create_zone()
        network_designate = self.create_zone_provider_vlan_vxlan_topology(
                            'vxlan', zone['name'])
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
        self.verify_recordset(recordset, 3)

    @decorators.idempotent_id('35ad8341-e96a-49ba-8463-54465051c7a4')
    def test_zone_list_without_fip_instance_provider_vlan(self):
        """
        Create a zone, check zone exits
        Create a network and subnet
        Update network with the zone
        Boot a VM
        Verify recordset only has SOA and NS record types
        """
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        zone = self.create_zone()
        network_designate = self.create_zone_provider_vlan_vxlan_topology(
                            'vxlan', zone['name'])
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
        self.verify_recordset(recordset, 3)

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
        zone = self.create_zone()
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
        if type(CONF.dns.nameservers) is list:
            nameserver = CONF.dns.nameservers[0][:-3]
        else:
            nameserver = CONF.dns.nameservers.split(":")[0]
        my_resolver.nameservers = [nameserver]
        # wait for status to change from pending to active
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

    @decorators.idempotent_id('2c3c0f63-c557-458f-a8f4-3b0e3065ed97')
    def test_zone_reverse_dnslookup_from_extvm(self):
        """
        Create a floating ip
        set a ptr record for the floating ip
        Perform nslookup for the floating ip from ext vm
        """
        fip = self.create_floatingip(client=self.os_admin.floating_ips_client)
        ptr_rev_name = '.'.join(reversed(
            fip['floating_ip_address'].split("."))) + ".in-addr.arpa."
        if CONF.network.region != "":
            region = CONF.network.region
        else:
            region = const.REGION_NAME
        resp = self.set_ptr_record(region, fip['id'], ptr_rev_name)
        ptr_record = self.show_ptr_record(region, fip['id'])
        self.assertEqual(fip['floating_ip_address'],
            ptr_record[1]['address'])
        if type(CONF.dns.nameservers) is list:
            nameserver = CONF.dns.nameservers[0][:-3]
        else:
            nameserver = CONF.dns.nameservers.split(":")[0]
        nslookup_cmd = "nslookup %s %s" % (fip['floating_ip_address'],
            nameserver)
        try:
            output = subprocess.check_output(
                nslookup_cmd, shell=True)
        except Exception:
            LOG.error('Reverse dns lookup failed on ext-vm')
        if ptr_rev_name not in output:
            LOG.error('failed to perform reverse dns for the floating ip')
            raise Exception('Reverse DNS response does not have entry '
                            'for the floating ip')

    @decorators.idempotent_id('6286cbd5-b0e4-4daa-9d8f-f27802c95925')
    def test_zone_deletion_post_fip_association(self):
        """
        Create a zone
        Update network with zone
        Boot an instance and associate fip
        Delete zone successfully
        """
        try:
            image_id = self.get_glance_image_id(['cirros', 'esx'])
        except Exception:
            LOG.error('cirros image is absent for esx HV')
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

    @decorators.idempotent_id('6963e17e-9404-4397-8738-cf0190ab2a66')
    def test_negative_dns_network_update(self):
        """
        Create a zone
        Update network with different dns name
        Boot an instance and associate fip
        Verify the recordset of the guestVM does not contain
        'A' record type
        """
        image_id = self.get_glance_image_id(['cirros', 'esx'])
        zone = self.create_zone()
        network_designate = self.create_zone_topology(
            const.ZONE_NAME)
        self.assertNotEqual(network_designate['dns_domain'], zone['name'])
        self.create_topology_instance(
            "dns_vm", [network_designate],
            security_groups=[{'name': self.designate_sg['name']}],
            clients=self.os_adm,
            create_floating_ip=True, image_id=image_id)
        LOG.info('Show recordset of the zone')
        recordset = self.list_record_set_zone(zone['id'])
        self.verify_recordset(recordset, 2)

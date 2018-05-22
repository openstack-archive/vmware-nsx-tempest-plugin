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
import collections

import netaddr
from oslo_log import log as logging
from oslo_utils import netutils

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.tests.scenario import manager

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ApplianceManager(manager.NetworkScenarioTest):
    server_details = collections.namedtuple('server_details',
                                            ['server', 'floating_ips',
                                             'networks'])

    def setUp(self):
        super(ApplianceManager, self).setUp()
        self.topology_routers = {}
        self.topology_networks = {}
        self.topology_subnets = {}
        self.topology_servers = {}
        self.topology_servers_floating_ip = []
        self.topology_public_network_id = CONF.network.public_network_id
        self.topology_config_drive = CONF.compute_feature_enabled.config_drive
        self.topology_keypairs = {}
        self.servers_details = {}
        self.topology_port_ids = {}
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.run_ssh = CONF.validation.run_validation
        self.ssh_user = CONF.validation.image_ssh_user

    def get_internal_ips(self, server, network, device="network"):
        internal_ips = [p['fixed_ips'][0]['ip_address'] for p in
                        self.os_admin.ports_client.list_ports(
                            tenant_id=server['tenant_id'],
                            network_id=network['id'])['ports'] if
                        p['device_owner'].startswith(device)]
        return internal_ips

    def _verify_empty_security_group_status(self, security_group):
        ip_protocols = ["IPV6", "IPV4"]
        nsx_fw_section, nsx_fw_section_rules = \
            self.nsx_client.get_firewall_section_and_rules(
                security_group['name'], security_group['id'])
        msg = "Newly created empty security group does not meet criteria !!!"
        self.assertEqual(nsx_fw_section["rule_count"], 2, msg)
        self.assertEqual(nsx_fw_section_rules[0]["action"], "ALLOW", msg)
        self.assertEqual(nsx_fw_section_rules[1]["action"], "ALLOW", msg)
        self.assertEqual(nsx_fw_section_rules[0]["direction"], "OUT", msg)
        self.assertEqual(nsx_fw_section_rules[1]["direction"], "OUT", msg)
        self.assertIn(nsx_fw_section_rules[0]["ip_protocol"], ip_protocols,
                      msg)
        self.assertIn(nsx_fw_section_rules[1]["ip_protocol"], ip_protocols,
                      msg)

    def create_topology_empty_security_group(self, namestart="vmw_"):
        security_group = self._create_empty_security_group(namestart=namestart)
        self._verify_empty_security_group_status(security_group)
        return security_group

    def add_security_group_rule(self, security_group, rule,
                                ruleclient=None,
                                tenant_id=None, secclient=None):
        return self._create_security_group_rule(
            secgroup=security_group,
            tenant_id=tenant_id,
            sec_group_rules_client=ruleclient,
            security_groups_client=secclient,
            **rule)

    def get_server_key(self, server):
        return self.topology_keypairs[server['key_name']]['private_key']

    def create_topology_router(self, router_name, routers_client=None,
                               tenant_id=None, set_gateway=True, **kwargs):
        if not routers_client:
            routers_client = self.routers_client
        if not tenant_id:
            tenant_id = routers_client.tenant_id
        router_name_ = constants.APPLIANCE_NAME_STARTS_WITH + router_name
        name = data_utils.rand_name(router_name_)
        router = routers_client.create_router(
            name=name, admin_state_up=True, tenant_id=tenant_id)['router']
        if set_gateway is not False:
            if kwargs.get("enable_snat"):
                public_network_info = {"external_gateway_info": dict(
                    network_id=self.topology_public_network_id,
                    enable_snat=kwargs["enable_snat"])}
            else:
                public_network_info = {"external_gateway_info": dict(
                    network_id=self.topology_public_network_id)}
            routers_client.update_router(router['id'], **public_network_info)
        self.topology_routers[router_name] = router
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        routers_client.delete_router, router['id'])
        return router

    def update_topology_router(
            self, router_id, routers_client=None, **update_kwargs):
        if not routers_client:
            routers_client = self.routers_client
        result = routers_client.update_router(router_id,
                                              **update_kwargs)
        return result

    def delete_topology_router(
            self, router_id, routers_client=None):
        if not routers_client:
            routers_client = self.routers_client
        routers_client.delete_router(router_id)

    def create_topology_network(
            self, network_name, networks_client=None,
            tenant_id=None, port_security_enabled=True, **kwargs):
        if not networks_client:
            networks_client = self.networks_client
        if not tenant_id:
            tenant_id = networks_client.tenant_id
        network_name_ = constants.APPLIANCE_NAME_STARTS_WITH + network_name
        name = data_utils.rand_name(network_name_)
        # Neutron disables port security by default so we have to check the
        # config before trying to create the network with port_security_enabled
        if CONF.network_feature_enabled.port_security:
            port_security_enabled = True
        else:
            port_security_enabled = False
        result = networks_client.create_network(
            name=name, tenant_id=tenant_id,
            port_security_enabled=port_security_enabled, **kwargs)
        network = result['network']
        self.assertEqual(network['name'], name)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        networks_client.delete_network, network['id'])
        self.topology_networks[network_name] = network
        return network

    def update_topology_network(
            self, network_id, networks_client=None, **update_kwargs):
        if not networks_client:
            networks_client = self.networks_client
        result = networks_client.update_network(network_id,
                                                **update_kwargs)
        return result

    def delete_topology_network(
            self, network_id, networks_client=None):
        if not networks_client:
            networks_client = self.networks_client
        networks_client.delete_network(network_id)

    def create_topology_subnet(
            self, subnet_name, network, routers_client=None,
            subnets_client=None, router_id=None, ip_version=4, cidr=None,
            mask_bits=None, **kwargs):
        subnet_name_ = constants.APPLIANCE_NAME_STARTS_WITH + subnet_name
        if not subnets_client:
            subnets_client = self.subnets_client
        if not routers_client:
            routers_client = self.routers_client

        def cidr_in_use(cidr, tenant_id):
            """Check cidr existence

            :returns: True if subnet with cidr already exist in tenant
                  False else

            """
            cidr_in_use = \
                self.os_admin.subnets_client.list_subnets(
                    tenant_id=tenant_id, cidr=cidr)['subnets']
            return len(cidr_in_use) != 0

        if ip_version == 6:
            tenant_cidr = (cidr or netaddr.IPNetwork(
                CONF.network.project_network_v6_cidr))
            mask_bits = mask_bits or CONF.network.project_network_v6_mask_bits
        else:
            tenant_cidr = cidr or netaddr.IPNetwork(
                CONF.network.project_network_cidr)
            mask_bits = mask_bits or CONF.network.project_network_mask_bits
        str_cidr = str(tenant_cidr)
        if not cidr:
            # Repeatedly attempt subnet creation with sequential cidr
            # blocks until an unallocated block is found.
            for subnet_cidr in tenant_cidr.subnet(mask_bits):
                str_cidr = str(subnet_cidr)
                if not cidr_in_use(str_cidr, tenant_id=network['tenant_id']):
                    break
        else:
            if cidr_in_use(str_cidr, tenant_id=network['tenant_id']):
                LOG.error("Specified subnet %r is in use" % str_cidr)
                raise
        subnet = dict(name=data_utils.rand_name(subnet_name_),
                      network_id=network['id'], tenant_id=network['tenant_id'],
                      cidr=str_cidr, ip_version=ip_version, **kwargs)
        try:
            result = None
            result = subnets_client.create_subnet(**subnet)
        except lib_exc.Conflict as e:
            is_overlapping_cidr = 'overlaps with another subnet' in str(e)
            if not is_overlapping_cidr:
                raise
        self.assertIsNotNone(result, 'Unable to allocate tenant network')
        subnet = result['subnet']
        self.assertEqual(subnet['cidr'], str_cidr)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnets_client.delete_subnet, subnet['id'])
        self.topology_subnets[subnet_name] = subnet
        if router_id:
            if not routers_client:
                routers_client = self.routers_client
            routers_client.add_router_interface(
                router_id, subnet_id=subnet["id"])
            self.addCleanup(
                test_utils.call_and_ignore_notfound_exc,
                routers_client.remove_router_interface, router_id,
                subnet_id=subnet["id"])
        return subnet

    def create_topology_security_provider_group(
            self, client=None, project_id=None, provider=False):
        if client is None:
            sg_client_admin = self.security_groups_client
        else:
            sg_client_admin = client.security_groups_client
        sg_dict = dict(name=data_utils.rand_name('provider-sec-group'))
        if project_id:
            sg_dict['tenant_id'] = project_id
        if provider:
            sg_dict['provider'] = True
        sg = sg_client_admin.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        sg_client_admin.delete_security_group,
                        sg.get('id'))
        return sg

    def _get_port_id(self, network_id, subnet_id, instance):
        _, instance_addr = instance["addresses"].items()[0]
        instance_fixed_ip = instance_addr[0]["addr"]
        for port in self._list_ports():
            port_fixed_ip = port["fixed_ips"][0]["ip_address"]
            if port["network_id"] == network_id and port["fixed_ips"][0][
                    "subnet_id"] == subnet_id and instance["id"] == port[
                    "device_id"] and port_fixed_ip == instance_fixed_ip:
                port_id = port["id"]
        self.assertIsNotNone(port_id, "Failed to find Instance's port id!!!")
        return port_id

    def create_topology_security_group(self, **kwargs):
        return self._create_security_group(**kwargs)

    def update_topology_security_group(self, sg_id, client=None,
                                       **updated_kwargs):
        sg = self.security_groups_client.\
            update_security_group(sg_id, **updated_kwargs)
        return sg

    def delete_topology_security_group(self, sg_id, client=None):
        sg = self.security_groups_client.delete_security_group(sg_id)
        return sg

    def _get_server_portid_and_ip4(self, server, ip_addr=None):
        ports = self.os_admin.ports_client.list_ports(
            device_id=server['id'], fixed_ip=ip_addr)['ports']
        p_status = ['ACTIVE']
        if getattr(CONF.service_available, 'ironic', False):
            p_status.append('DOWN')
        port_map = [(p["id"], fxip["ip_address"])
                    for p in ports
                    for fxip in p["fixed_ips"]
                    if netutils.is_valid_ipv4(fxip["ip_address"])
                    and p['status'] in p_status]
        inactive = [p for p in ports if p['status'] != 'ACTIVE']
        if inactive:
            LOG.warning("Instance has ports that are not ACTIVE: %s", inactive)

        self.assertNotEqual(0, len(port_map),
                            "No IPv4 addresses found in: %s" % ports)
        return port_map

    def remove_router_interface(
            self,
            router_id,
            subnet_id,
            router_client=None):
        if router_client is None:
            router_client = self.routers_client
        router_client.remove_router_interface(router_id,
                                              subnet_id=subnet_id)

    def update_subnet(self, subnet_id, subnet_client=None, **kwargs):
        if subnet_client is None:
            subnet_client = self.subnets_client
        result = subnet_client.update_subnet(subnet_id, **kwargs)
        subnet = result['subnet']
        return subnet

    def create_floatingip(self, thing, port_id, external_network_id=None,
                          ip4=None, client=None):
        """Create a floating IP and associates to a resource/port on Neutron"""
        if not external_network_id:
            external_network_id = self.topology_public_network_id
        if not client:
            client = self.floating_ips_client
        result = client.create_floatingip(
            floating_network_id=external_network_id,
            port_id=port_id,
            tenant_id=thing['tenant_id'],
            fixed_ip_address=ip4
        )
        floating_ip = result['floatingip']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_floatingip,
                        floating_ip['id'])
        return floating_ip

    def create_topology_instance(
            self, server_name, networks, security_groups=None,
            config_drive=None, keypair=None, image_id=None,
            clients=None, create_floating_ip=True, **kwargs):
        # Define security group for server.
        if CONF.nsxv3.ens is not True:
            if security_groups:
                kwargs["security_groups"] = security_groups
            else:
                _sg = self.create_topology_security_group()
                _security_groups = [{'name': _sg['name']}]
                kwargs["security_groups"] = _security_groups
        # Define config drive for server.
        if not config_drive:
            kwargs["config_drive"] = self.topology_config_drive
        else:
            kwargs["config_drive"] = config_drive
        if not keypair:
            if clients:
                client = clients.keypairs_client
                keypair = self.create_keypair(client)
            else:
                keypair = self.create_keypair()
            self.topology_keypairs[keypair['name']] = keypair
            kwargs["key_name"] = keypair['name']
        else:
            kwargs["key_name"] = keypair['name']
        # Define image id for server.
        if image_id:
            kwargs["image_id"] = image_id
        server_name_ = constants.APPLIANCE_NAME_STARTS_WITH + server_name
        # Collect all the networks for server.
        networks_ = []
        for net in networks:
            net_ = {"uuid": net["id"]}
            networks_.append(net_)
        # Deploy server with all the args.
        server = self.create_server(
            name=server_name_, networks=networks_, clients=clients, **kwargs)
        floating_ips = []
        if create_floating_ip:
            ports = self._get_server_portid_and_ip4(server)
            for port_id, ip4 in ports:
                if clients is None:
                    floating_ip = self.create_floatingip(server, port_id,
                                                         ip4=ip4)
                else:
                    floating_ip = self.\
                        create_floatingip(server,
                                          port_id, ip4=ip4,
                                          client=clients.floating_ips_client)
                if server.get("floating_ips"):
                    server["floating_ips"].append(floating_ip)
                else:
                    server["floating_ips"] = [floating_ip]
                self.topology_servers_floating_ip.append(floating_ip)
                floating_ips.append(floating_ip)
        server_details = self.server_details(server=server,
                                             floating_ips=floating_ips,
                                             networks=networks)
        self.servers_details[server_name] = server_details
        self.topology_servers[server_name] = server
        return server

    def _list_ports(self, *args, **kwargs):
        """List ports using admin creds """
        ports_list = self.os_admin.ports_client.list_ports(
            *args, **kwargs)
        return ports_list['ports']

    def get_network_ports_id(self):
        for port in self._list_ports():
            for fixed_ip in port["fixed_ips"]:
                ip = fixed_ip["ip_address"]
                port_id = port["id"]
                tenant_id = port["tenant_id"]
                if tenant_id in self.topology_port_ids:
                    self.topology_port_ids[tenant_id][ip] = port_id
                else:
                    self.topology_port_ids[tenant_id] = {ip: port_id}

    def get_glance_image_id(self, params):
        """
        Get the glance image id based on the params

        :param params: List of sub-string of image name
        :return:
        """
        # Retrieve the list of images that meet the filter
        images_list = self.os_admin.image_client_v2.list_images()['images']
        # Validate that the list was fetched sorted accordingly
        msg = "No images were found that met the filter criteria."
        self.assertNotEmpty(images_list, msg)
        image_id = None
        for image in images_list:
            for param in params:
                if not param.lower() in image["name"].lower():
                    break
            else:
                image_id = image["id"]
                break
        self.assertIsNotNone(image_id, msg)
        return image_id

    def get_user_id(self, client_id):
        """
        Get the user id based on the openstack client
        """
        if client_id == 'network':
            user_id = self.networks_client.user_id
            tenant_id = self.networks_client.tenant_id
        elif client_id == 'router':
            user_id = self.routers_client.user_id
            tenant_id = self.routers_client.tenant_id
        elif client_id == 'sg':
            user_id = self.security_groups_client.user_id
            tenant_id = self.security_groups_client.tenant_id
        return user_id, tenant_id

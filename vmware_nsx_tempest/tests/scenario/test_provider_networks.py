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
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF
LOG = constants.log.getLogger(__name__)


class ProviderNetworks(feature_manager.FeatureManager):
    """Test Provider Physical Networks

    1. Create Vxlan Provider networks.
    2. Create Vlan Provider networks.
    3. Create Vlan/Vxlan provider networks using worng ID.
    """

    @classmethod
    def skip_checks(cls):
        super(ProviderNetworks, cls).skip_checks()
        if not test.is_extension_enabled('provider-security-group', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(ProviderNetworks, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(ProviderNetworks, cls).resource_setup()
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

    def provider_networks_topoloy(self, net_type,
                                  admin_state_up=True,
                                  tz_id=None,
                                  vlan_id_unique=None):
        networks_client = self.cmgr_adm.networks_client
        if net_type == constants.VXLAN_TYPE:
            name = "provider_network_vxlan"
            body = {"provider:physical_network": tz_id,
                    "provider:network_type": net_type,
                    "admin_state_up": admin_state_up}
        elif net_type == constants.VLAN_TYPE:
            name = "provider_network_vlan"
            if vlan_id_unique is not None:
                vlan_id_no = vlan_id_unique
            else:
                vlan_id_no = constants.VLAN
            if tz_id is None:
                body = {"provider:segmentation_id": vlan_id_no,
                        "provider:network_type": net_type,
                        "admin_state_up": admin_state_up}
            else:
                body = {"provider:segmentation_id": vlan_id_no,
                        "provider:network_type": net_type,
                        "provider:physical_network": tz_id,
                        "admin_state_up": admin_state_up}
        network = self.create_topology_network(name,
                                               networks_client=networks_client,
                                               **body)
        return network

    @decorators.idempotent_id('21d11308-8e16-4f41-bd2b-e95588fa4c23')
    def test_provider_vlan_networks_using_router(self):
        provider_network = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id)
        subnet_client = self.cmgr_adm.subnets_client
        router = self.create_topology_router("rtr-provider")
        subnet_name = provider_network['name'] + '_subnet'
        kwargs = {"enable_dhcp": "True"}
        self.create_topology_subnet(
            subnet_name,
            provider_network,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            **kwargs)
        provider_network1 = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id,
            vlan_id_unique=1004)
        subnet_name = provider_network1['name'] + '_subnet1'
        kwargs = {"enable_dhcp": "True"}
        self.create_topology_subnet(
            subnet_name,
            provider_network1,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            cidr="19.0.0.0/24",
            **kwargs)

    @decorators.idempotent_id('7b0fe384-ff1d-441d-b587-1b43fef498d8')
    def test_N_S_traffic_using_vlan_network(self):
        provider_network = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id)
        subnet_client = self.cmgr_adm.subnets_client
        router = self.create_topology_router("rtr-provider")
        subnet_name = provider_network['name'] + '_subnet'
        kwargs = {"enable_dhcp": "True"}
        self.create_topology_subnet(
            subnet_name,
            provider_network,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            **kwargs)
        provider_network1 = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id,
            vlan_id_unique=1004)
        subnet_name = provider_network1['name'] + '_subnet1'
        kwargs = {"enable_dhcp": "True"}
        self.create_topology_subnet(
            subnet_name,
            provider_network1,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            cidr="19.0.0.0/24",
            **kwargs)
        sec_rule_client = self.cmgr_adm.security_group_rules_client
        sec_client = self.cmgr_adm.security_groups_client
        kwargs = dict(tenant_id=provider_network['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        sg = self.create_topology_security_group(**kwargs)
        self.create_topology_instance(
            "provider-server1", [provider_network],
            security_groups=[{'name': sg['name']}],
            clients=self.cmgr_adm)
        self.create_topology_instance(
            "provider-server2", [provider_network1],
            security_groups=[{'name': sg['name']}],
            clients=self.cmgr_adm)
        for server_name in self.topology_servers.keys():
            server = self.servers_details[server_name].server
            fip_data = server.get('floating_ips')[0]
            fip = fip_data['floating_ip_address']
            self.verify_server_ssh(
                server=server, floating_ip=fip)

    @decorators.idempotent_id('a813f45a-aad0-489e-a976-e2b48cd6e2f2')
    def test_provider_vlan_networks_using_router_Adn_verify(self):
        provider_network = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id)
        subnet_client = self.cmgr_adm.subnets_client
        router_op = self.create_topology_router("rtr-provider")
        subnet_name = provider_network['name'] + '_subnet'
        kwargs = {"enable_dhcp": "True"}
        subnet = self.create_topology_subnet(
            subnet_name,
            provider_network,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router_op['id'],
            **kwargs)
        self.check_centralized_port_created(router_op, subnet)
        network = self.create_topology_network(network_name="overlay-network")
        subnet1 = self.create_topology_subnet("overlay_subnet", network,
                                              cidr="21.1.1.0/24",
                                              router_id=router_op['id'])
        self.check_downlink_port_created(router_op, subnet1)

    @decorators.idempotent_id('3ca5b0d5-5be0-42e3-b3b1-eb653753fbfe')
    def test_vlan_network_attach_router_fails(self):
        provider_network = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id)
        subnet_client = self.cmgr_adm.subnets_client
        router = self.create_topology_router("rtr-provider", set_gateway=False)
        subnet_name = provider_network['name'] + '_subnet1'
        kwargs = {"enable_dhcp": "True"}
        self.assertRaises(exceptions.BadRequest,
                          self.create_topology_subnet,
                          subnet_name, provider_network,
                          subnets_client=subnet_client,
                          routers_client=self.cmgr_adm.routers_client,
                          router_id=router['id'],
                          **kwargs)

    @decorators.idempotent_id('3e56521f-1c8d-47d5-afa1-de1fd8ac95cd')
    def test_vlan_network_with_multi_subnets_attach_router(self):
        provider_network = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id)
        subnet_client = self.cmgr_adm.subnets_client
        router = self.create_topology_router("rtr-provider")
        subnet_name = provider_network['name'] + '_subnet'
        kwargs = {"enable_dhcp": "True"}
        self.create_topology_subnet(
            subnet_name,
            provider_network,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            **kwargs)
        subnet_name = provider_network['name'] + '_subnet1'
        kwargs = {"enable_dhcp": "False"}
        self.create_topology_subnet(subnet_name, provider_network,
                                    subnets_client=subnet_client,
                                    cidr="19.0.0.0/24",
                                    **kwargs)
        self.assertRaises(exceptions.BadRequest,
                          self.create_topology_subnet,
                          subnet_name, provider_network,
                          subnets_client=subnet_client,
                          routers_client=self.cmgr_adm.routers_client,
                          router_id=router['id'],
                          cidr="20.0.0.0/24",
                          **kwargs)

    @decorators.idempotent_id('f7279148-47d5-4451-94fb-2c6f5213fb97')
    def test_provider_vlan_network_dhcp_disable_attach_router(self):
        provider_network = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id)
        subnet_client = self.cmgr_adm.subnets_client
        router = self.create_topology_router("rtr-provider")
        subnet_name = provider_network['name'] + '_subnet'
        kwargs = {"enable_dhcp": "False"}
        self.create_topology_subnet(
            subnet_name,
            provider_network,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            **kwargs)
        provider_network1 = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            tz_id=self.vlan_id,
            vlan_id_unique=1003)
        subnet_name = provider_network1['name'] + '_subnet1'
        kwargs = {"enable_dhcp": "True"}
        self.create_topology_subnet(
            subnet_name,
            provider_network1,
            subnets_client=subnet_client,
            routers_client=self.cmgr_adm.routers_client,
            router_id=router['id'],
            cidr="19.0.0.0/24",
            **kwargs)

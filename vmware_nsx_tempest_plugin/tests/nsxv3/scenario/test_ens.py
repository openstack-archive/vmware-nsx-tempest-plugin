# Copyright 2018 VMware Inc
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

import time

from tempest import config
from tempest.lib import decorators

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsx_client

CONF = config.CONF


class TestEnsOps(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestEnsOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        if not CONF.network.public_network_cidr:
            msg = "public_network_cidr must be defined in network section."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        cls.admin_mgr = cls.get_client_manager('admin')
        super(TestEnsOps, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestEnsOps, cls).setup_clients()
        cls.nsx_client = nsx_client.NSXClient(
            CONF.network.backend,
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)

    def verify_ping_to_fip_from_ext_vm(self, server_details):
        self.using_floating_ip_check_server_and_project_network_connectivity(
            server_details)

    def verify_ping_own_fip(self, server):
        fip = server["floating_ips"][0]["floating_ip_address"]
        client = self.verify_server_ssh(server, floating_ip=fip)
        ping_cmd = "ping -c 1 %s " % fip
        self.exec_cmd_on_server_using_fip(ping_cmd, ssh_client=client)

    def provider_networks_topoloy(self, net_type,
                                  admin_state_up=True,
                                  tz_id=None,
                                  vlan_id_unique=None):
        networks_client = self.admin_mgr.networks_client
        name = "provider_network_vlan"
        if vlan_id_unique is None:
            vlan_id_no = constants.VLAN
        else:
            vlan_id_no = vlan_id_unique
        body = {"provider:segmentation_id": vlan_id_no,
                "provider:network_type": net_type,
                "admin_state_up": admin_state_up}
        network = self.create_topology_network(name,
                                               networks_client=networks_client,
                                               **body)
        return network


class EnsScenarioTest(TestEnsOps):

    @decorators.idempotent_id('a57de68f-24e5-4cae-833f-0244e4eb3960')
    def test_ens_vlan_traffic_across_networks_scenario(self):
        provider_network = self.provider_networks_topoloy(
            constants.VLAN_TYPE)
        subnet_client = self.admin_mgr.subnets_client
        router = self.create_topology_router(
            "rtr-provider", routers_client=self.admin_mgr.routers_client)
        subnet_name = provider_network['name'] + '_subnet'
        self.create_topology_subnet(
            subnet_name,
            provider_network,
            subnets_client=subnet_client,
            routers_client=self.admin_mgr.routers_client,
            router_id=router['id'])
        provider_network1 = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            vlan_id_unique=1003)
        subnet_name = provider_network1['name'] + '_subnet1'
        kwargs = {"enable_dhcp": "True"}
        self.create_topology_subnet(
            subnet_name,
            provider_network1,
            subnets_client=subnet_client,
            routers_client=self.admin_mgr.routers_client,
            router_id=router['id'],
            cidr="19.0.0.0/24",
            **kwargs)
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [provider_network],
            create_floating_ip=True, image_id=image_id, clients=self.admin_mgr)
        self.create_topology_instance(
            "ens_vm_2", [provider_network1],
            create_floating_ip=True, image_id=image_id, clients=self.admin_mgr)
        # Verify E-W traffic
        self.check_cross_network_connectivity(
            provider_network,
            self.servers_details["ens_vm_1"].floating_ips[0],
            self.servers_details["ens_vm_1"].server, should_connect=True)
        self.check_cross_network_connectivity(
            provider_network1,
            self.servers_details["ens_vm_2"].floating_ips[0],
            self.servers_details["ens_vm_2"].server, should_connect=True)
        # Verify fip ping N-S traffic
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

    @decorators.idempotent_id('3db32aec-afe9-4b94-9a3f-763f5fe0eb50')
    def test_server_vlan_connectivity_suspend_resume(self):
        network_ens = self.provider_networks_topoloy(
            constants.VLAN_TYPE)
        subnet_client = self.admin_mgr.subnets_client
        router_ens = self.create_topology_router(
            "rtr-provider", routers_client=self.admin_mgr.routers_client)
        subnet_name = "subnet_ens"
        self.create_topology_subnet(
            subnet_name,
            network_ens,
            subnets_client=subnet_client,
            routers_client=self.admin_mgr.routers_client,
            router_id=router_ens['id'])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens],
            create_floating_ip=True, image_id=image_id, clients=self.admin_mgr)
        server = self.servers_details["ens_vm_1"].server
        server_id = self.servers_details["ens_vm_1"].server['id']
        self.admin_mgr.servers_client.suspend_server(server_id)
        self.wait_server_status(
            self.admin_mgr.servers_client,
            server_id,
            'SUSPENDED')
        fip_data = server.get('floating_ips')[0]
        self.admin_mgr.servers_client.resume_server(server_id)
        self.wait_server_status(self.admin_mgr.servers_client, server_id)
        self.check_network_internal_connectivity(network_ens, fip_data,
                                                 server, should_connect=True)
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

    @decorators.idempotent_id('5a908dfb-b16b-430a-93c6-be7b28b36b6c')
    def test_server_vlan_connectivity_stop_start(self):
        network_ens = self.provider_networks_topoloy(
            constants.VLAN_TYPE)
        subnet_client = self.admin_mgr.subnets_client
        router_ens = self.create_topology_router(
            "rtr-provider", routers_client=self.admin_mgr.routers_client)
        subnet_name = "subnet_ens"
        self.create_topology_subnet(
            subnet_name,
            network_ens,
            subnets_client=subnet_client,
            routers_client=self.admin_mgr.routers_client,
            router_id=router_ens['id'])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens],
            create_floating_ip=True, image_id=image_id, clients=self.admin_mgr)
        server = self.servers_details["ens_vm_1"].server
        server_id = self.servers_details["ens_vm_1"].server['id']
        self.admin_mgr.servers_client.stop_server(server_id)
        time.sleep(60)
        fip_data = server.get('floating_ips')[0]
        self.admin_mgr.servers_client.start_server(server_id)
        self.wait_server_status(self.admin_mgr.servers_client, server_id)
        self.check_network_internal_connectivity(network_ens, fip_data,
                                                 server, should_connect=True)
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

    @decorators.idempotent_id('14dd6559-8855-4f53-b1cd-82a9ccc98179')
    def test_ens_vlan_traffic_scenario(self):
        provider_network = self.provider_networks_topoloy(
            constants.VLAN_TYPE)
        subnet_client = self.admin_mgr.subnets_client
        router = self.create_topology_router(
            "rtr-provider", routers_client=self.admin_mgr.routers_client)
        subnet_name = provider_network['name'] + '_subnet'
        self.create_topology_subnet(
            subnet_name,
            provider_network,
            subnets_client=subnet_client,
            routers_client=self.admin_mgr.routers_client,
            router_id=router['id'])
        provider_network1 = self.provider_networks_topoloy(
            constants.VLAN_TYPE,
            vlan_id_unique=1003)
        subnet_name = provider_network1['name'] + '_subnet1'
        kwargs = {"enable_dhcp": "True"}
        self.create_topology_subnet(
            subnet_name,
            provider_network1,
            subnets_client=subnet_client,
            routers_client=self.admin_mgr.routers_client,
            router_id=router['id'],
            cidr="19.0.0.0/24",
            **kwargs)
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [provider_network],
            create_floating_ip=True, image_id=image_id, clients=self.admin_mgr)
        self.create_topology_instance(
            "ens_vm_2", [provider_network],
            create_floating_ip=True, image_id=image_id, clients=self.admin_mgr)
        # Verify E-W traffic
        self.check_cross_network_connectivity(
            provider_network,
            self.servers_details["ens_vm_1"].floating_ips[0],
            self.servers_details["ens_vm_1"].server, should_connect=True)
        self.check_cross_network_connectivity(
            provider_network,
            self.servers_details["ens_vm_2"].floating_ips[0],
            self.servers_details["ens_vm_2"].server, should_connect=True)
        # Verify fip ping N-S traffic
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

    @decorators.idempotent_id('2544b6e2-f61b-4f0a-8821-5274e8e1baa1')
    def test_ens_overlay_traffic_scenario(self):
        router_ens = self.create_topology_router("router_ens")
        # Qos network
        network_ens = self.create_topology_network("network_ens")
        self.create_topology_subnet("subnet_ens", network_ens,
                                    router_id=router_ens["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens],
            create_floating_ip=True, image_id=image_id)
        self.create_topology_instance(
            "ens_vm_2", [network_ens],
            create_floating_ip=True, image_id=image_id)
        # Verify E-W traffic
        self.check_cross_network_connectivity(
            self.topology_networks["network_ens"],
            self.servers_details["ens_vm_1"].floating_ips[0],
            self.servers_details["ens_vm_1"].server, should_connect=True)
        self.check_cross_network_connectivity(
            self.topology_networks["network_ens"],
            self.servers_details["ens_vm_2"].floating_ips[0],
            self.servers_details["ens_vm_2"].server, should_connect=True)
        # Verify fip ping N-S traffic
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)
        self.verify_ping_own_fip(self.topology_servers["ens_vm_1"])
        self.verify_ping_own_fip(self.topology_servers["ens_vm_2"])

    @decorators.idempotent_id('660a02f0-c01b-4e0e-9a99-7e6337b895f8')
    def test_ens_overlay_traffic_scenario_diff_tenants(self):
        router_ens = self.create_topology_router("router_ens")
        network_ens1 = self.create_topology_network("network_ens1")
        network_ens2 = self.create_topology_network("network_ens2")
        self.create_topology_subnet("subnet_ens1", network_ens1,
                                    router_id=router_ens["id"])
        self.create_topology_subnet("subnet_ens2", network_ens2,
                                    router_id=router_ens["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens1],
            create_floating_ip=True, image_id=image_id)
        self.create_topology_instance(
            "ens_vm_2", [network_ens2],
            create_floating_ip=True, image_id=image_id)
        # Verify E-W traffic
        self.check_cross_network_connectivity(
            self.topology_networks["network_ens1"],
            self.servers_details["ens_vm_1"].floating_ips[0],
            self.servers_details["ens_vm_1"].server, should_connect=True)
        self.check_cross_network_connectivity(
            self.topology_networks["network_ens2"],
            self.servers_details["ens_vm_2"].floating_ips[0],
            self.servers_details["ens_vm_2"].server, should_connect=True)
        # Verify fip ping N-S traffic
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)
        self.verify_ping_own_fip(self.topology_servers["ens_vm_1"])
        self.verify_ping_own_fip(self.topology_servers["ens_vm_2"])

    @decorators.idempotent_id('fc93db11-164c-40af-8484-ab7561e040e9')
    def test_ens_overlay_traffic_scenario_diff_tier1_routers(self):
        router_ens1 = self.create_topology_router("router_ens1")
        router_ens2 = self.create_topology_router("router_ens2")
        network_ens1 = self.create_topology_network("network_ens1")
        network_ens2 = self.create_topology_network("network_ens2")
        self.create_topology_subnet("subnet_ens1", network_ens1,
                                    router_id=router_ens1["id"])
        self.create_topology_subnet("subnet_ens2", network_ens2,
                                    router_id=router_ens2["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens1],
            create_floating_ip=True, image_id=image_id)
        self.create_topology_instance(
            "ens_vm_2", [network_ens2],
            create_floating_ip=True, image_id=image_id)
        # Verify E-W traffic
        self.check_cross_network_connectivity(
            self.topology_networks["network_ens1"],
            self.servers_details["ens_vm_1"].floating_ips[0],
            self.servers_details["ens_vm_1"].server, should_connect=True)
        self.check_cross_network_connectivity(
            self.topology_networks["network_ens2"],
            self.servers_details["ens_vm_2"].floating_ips[0],
            self.servers_details["ens_vm_2"].server, should_connect=True)
        # Verify fip ping N-S traffic
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)
        self.verify_ping_own_fip(self.topology_servers["ens_vm_1"])
        self.verify_ping_own_fip(self.topology_servers["ens_vm_2"])

    @decorators.idempotent_id('b1496d96-baf3-4ee1-9fda-80b155b95cac')
    def test_server_connectivity_stop_start(self):
        router_ens1 = self.create_topology_router("router_ens1")
        network_ens1 = self.create_topology_network("network_ens1")
        self.create_topology_subnet("subnet_ens1", network_ens1,
                                    router_id=router_ens1["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens1],
            create_floating_ip=True, image_id=image_id)
        server_id = self.servers_details["ens_vm_1"].server['id']
        self.admin_mgr.servers_client.stop_server(server_id)
        time.sleep(60)
        self.wait_server_status(self.admin_mgr.servers_client, server_id)
        server = self.servers_details["ens_vm_1"].server
        fip_data = server.get('floating_ips')[0]
        self.admin_mgr.servers_client.start_server(server_id)
        self.wait_server_status(self.admin_mgr.servers_client, server_id)
        self.check_network_internal_connectivity(network_ens1, fip_data,
                                                 server, should_connect=True)
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

    @decorators.idempotent_id('e8ab2c41-cee4-4b4b-aa7f-da0cb6c37684')
    def test_server_connectivity_reboot(self):
        router_ens1 = self.create_topology_router("router_ens1")
        network_ens1 = self.create_topology_network("network_ens1")
        self.create_topology_subnet("subnet_ens1", network_ens1,
                                    router_id=router_ens1["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens1],
            create_floating_ip=True, image_id=image_id)
        server_id = self.servers_details["ens_vm_1"].server['id']
        server = self.servers_details["ens_vm_1"].server
        fip_data = server.get('floating_ips')[0]
        self.admin_mgr.servers_client.reboot_server(server_id, type='SOFT')
        self.wait_server_status(self.admin_mgr.servers_client, server_id)
        self.check_network_internal_connectivity(network_ens1, fip_data,
                                                 server, should_connect=True)
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

    @decorators.idempotent_id('2ca25c94-195b-4223-921b-1b973da09d29')
    def test_server_connectivity_rebuild(self):
        router_ens1 = self.create_topology_router("router_ens1")
        network_ens1 = self.create_topology_network("network_ens1")
        self.create_topology_subnet("subnet_ens1", network_ens1,
                                    router_id=router_ens1["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens1],
            create_floating_ip=True, image_id=image_id)
        server_id = self.servers_details["ens_vm_1"].server['id']
        server = self.servers_details["ens_vm_1"].server
        fip_data = server.get('floating_ips')[0]
        image_ref_alt = CONF.compute.image_ref_alt
        self.admin_mgr.servers_client.rebuild_server(server_id,
                                                     image_ref=image_ref_alt)
        self.wait_server_status(self.admin_mgr.servers_client, server_id)
        self.check_network_internal_connectivity(network_ens1, fip_data,
                                                 server, should_connect=True)
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

    @decorators.idempotent_id('3468a7bd-085f-4e22-9149-61226964b039')
    def test_server_connectivity_suspend_resume(self):
        router_ens1 = self.create_topology_router("router_ens1")
        network_ens1 = self.create_topology_network("network_ens1")
        self.create_topology_subnet("subnet_ens1", network_ens1,
                                    router_id=router_ens1["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens1],
            create_floating_ip=True, image_id=image_id)
        server_id = self.servers_details["ens_vm_1"].server['id']
        server = self.servers_details["ens_vm_1"].server
        fip_data = server.get('floating_ips')[0]

        self.admin_mgr.servers_client.suspend_server(server_id)
        self.wait_server_status(
            self.admin_mgr.servers_client,
            server_id,
            'SUSPENDED')
        self.check_network_internal_connectivity(network_ens1, fip_data,
                                                 server, should_connect=False)

        self.admin_mgr.servers_client.resume_server(server_id)
        self.wait_server_status(self.admin_mgr.servers_client, server_id)
        self.check_network_internal_connectivity(network_ens1, fip_data,
                                                 server, should_connect=True)
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

    @decorators.idempotent_id('4130df8c-8091-42a8-b90a-4a95ad6de89b')
    def test_server_connectivity_resize(self):
        resize_flavor = CONF.compute.flavor_ref_alt
        router_ens1 = self.create_topology_router("router_ens1")
        network_ens1 = self.create_topology_network("network_ens1")
        self.create_topology_subnet("subnet_ens1", network_ens1,
                                    router_id=router_ens1["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "ens_vm_1", [network_ens1],
            create_floating_ip=True, image_id=image_id)
        server_id = self.servers_details["ens_vm_1"].server['id']
        server = self.servers_details["ens_vm_1"].server
        fip_data = server.get('floating_ips')[0]

        self.admin_mgr.servers_client.resize_server(server['id'],
                                                    flavor_ref=resize_flavor)
        self.wait_server_status(
            self.admin_mgr.servers_client,
            server_id,
            'VERIFY_RESIZE')

        self.admin_mgr.servers_client.confirm_resize_server(server_id)
        server = \
            self.admin_mgr.servers_client.show_server(server['id'])[
                'server']
        self.assertEqual(resize_flavor, server['flavor']['id'])
        self.wait_server_status(self.admin_mgr.servers_client, server_id)
        self.check_network_internal_connectivity(network_ens1, fip_data,
                                                 server, should_connect=True)
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)

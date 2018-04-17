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

from tempest import config
from tempest.lib import decorators

from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsx_client

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


class EnsScenarioTest(TestEnsOps):

    @decorators.idempotent_id('2544b6e2-f61b-4f0a-8821-5274e8e1baa1')
    def test_ens_overlay_traffic_scenario(self):
        router_ens = self.create_topology_router("router_ens")
        # Qos network
        network_ens = self.create_topology_network("network_ens")
        self.create_topology_subnet("subnet_ens", network_ens,
                           router_id=router_ens["id"])
        image_id = self.get_glance_image_id(['cirros', 'esx'])
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

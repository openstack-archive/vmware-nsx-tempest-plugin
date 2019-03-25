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
import re
import testtools
import time

from oslo_utils import uuidutils
from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from tempest.lib import decorators
from tempest.lib import exceptions

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import fwaas_client as FWAASC
from vmware_nsx_tempest_plugin.services import nsxv3_client

from vmware_nsx_tempest_plugin.services import nsxp_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestTier1DeploymentEdgeCluster(feature_manager.FeatureManager):
    """Test TestTier1DeploymentEdgeCluster

    Adding test cases to test deploy tier1
    on sepcific edge_cluster.
    """

    def setUp(self):
        super(TestTier1DeploymentEdgeCluster, self).setUp()
        self.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                            CONF.nsxv3.nsx_user,
                                            CONF.nsxv3.nsx_password)
        self.nsxp = nsxp_client.NSXPClient(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    @classmethod
    def skip_checks(cls):
        """Class level skip checks.

        Class level check. Skip all the MDproxy tests, if native_dhcp_metadata
        is not True under nsxv3 section of the config
        """
        super(TestTier1DeploymentEdgeCluster, cls).skip_checks()

    def create_topo_single_network(self, namestart, create_instance=True,
                                   set_gateway=True, instance_count=None, **kwargs):
        """
        Create Topo where 1 logical switches which is
        connected via tier-1 router.
        """
        rtr_name = data_utils.rand_name(name='tempest-router')
        network_name = data_utils.rand_name(name='tempest-net')
        subnet_name = data_utils.rand_name(name='tempest-subnet')
        router_state = self.create_topology_router(rtr_name,
                                                   set_gateway=set_gateway,
                                                   **kwargs)
        network_state = self.create_topology_network(network_name)
        subnet_state = self.create_topology_subnet(subnet_name, network_state,
                                                   router_id=router_state["id"]
                                                   )
        if create_instance:
            image_id = self.get_glance_image_id(["cirros", "esx"])
            self.create_topology_instance(
                "state_vm_1", [network_state],
                create_floating_ip=True, image_id=image_id)
            self.create_topology_instance(
                "state_vm_2", [network_state],
                create_floating_ip=True, image_id=image_id)
        topology_dict = dict(router_state=router_state,
                             network_state=network_state,
                             subnet_state=subnet_state)
        return topology_dict

    def verify_ping_to_fip_from_ext_vm(self, server_details):
        self.test_fip_check_server_and_project_network_connectivity(
            server_details)

    def verify_ping_own_fip(self, server):
        fip = server["floating_ips"][0]["floating_ip_address"]
        client = self.verify_server_ssh(server, floating_ip=fip)
        ping_cmd = "ping -c 1 %s " % fip
        self.exec_cmd_on_server_using_fip(ping_cmd, ssh_client=client)

    def test_router_check_status_on_edge_cluster(self):
        """
        Check it should not allow to create port with two
        fixed ips.
        """
        rtr_name = data_utils.rand_name(name='tempest-router')
        kwargs = {}
        router_state = self.create_topology_router(rtr_name,
                                                   set_gateway=True,
                                                   **kwargs)
        router_services = self.nsxp.get_logical_router_local_services(router_state['name'], router_state['id'])
        edge_cluster_id = router_services[0]['edge_cluster_path'].split('/')[len(router_services[0]['edge_cluster_path'].split('/')) - 1]
        self.assertEqual(CONF.edge_cluster.edge_cluster_uuid, edge_cluster_id)

    def test_east_west_traffic(self):
        """
        Check it should not allow to create port with two
        fixed ips.
        """
        topology_dict = self.create_topo_single_network("admin_state")
        router_state = topology_dict['router_state']
        network_state = topology_dict['network_state']
        router_services = self.nsxp.get_logical_router_local_services(router_state['name'], router_state['id'])
        edge_cluster_id = router_services[0]['edge_cluster_path'].split('/')[len(router_services[0]['edge_cluster_path'].split('/')) - 1]
        self.assertEqual(CONF.edge_cluster.edge_cluster_uuid, edge_cluster_id)
        # Verify E-W traffic
        self.check_cross_network_connectivity(
            network_state,
            self.servers_details.get("state_vm_1").floating_ips[0],
            self.servers_details.get("state_vm_1").server, should_connect=True)
        self.check_cross_network_connectivity(
            network_state,
            self.servers_details.get("state_vm_2").floating_ips[0],
            self.servers_details.get("state_vm_2").server, should_connect=True)

    def test_north_south_traffic(self):
        """
        Check it should not allow to create port with two
        fixed ips.
        """
        topology_dict = self.create_topo_single_network("admin_state")
        router_state = topology_dict['router_state']
        network_state = topology_dict['network_state']
        router_services = self.nsxp.get_logical_router_local_services(router_state['name'], router_state['id'])
        edge_cluster_id = router_services[0]['edge_cluster_path'].split('/')[len(router_services[0]['edge_cluster_path'].split('/')) - 1]
        self.assertEqual(CONF.edge_cluster.edge_cluster_uuid, edge_cluster_id)
        # Verify fip ping N-S traffic
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)
        self.verify_ping_own_fip(self.topology_servers["state_vm_1"])
        self.verify_ping_own_fip(self.topology_servers["state_vm_2"])



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

#from vmware_nsx_tempest_plugin.services import nsxp_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestTier1DRComponentDeployment(feature_manager.FeatureManager):
    """Test TestTier1DRComponentDeployment

    Adding test cases to test deploy tier1
    on sepcific edge_cluster.
    """

    def setUp(self):
        super(TestTier1DRComponentDeployment, self).setUp()
        self.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                            CONF.nsxv3.nsx_user,
                                            CONF.nsxv3.nsx_password)

    @classmethod
    def skip_checks(cls):
        """Class level skip checks.

        Class level check. Skip all the MDproxy tests, if native_dhcp_metadata
        is not True under nsxv3 section of the config
        """
        super(TestTier1DRComponentDeployment, cls).skip_checks()

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


    def test_only_dr_componet_of_router_should_present(self):
        """
        Check it should not allow to create port with two
        fixed ips.
        """
        kwargs = {"enable_snat": False}
        router_state = self.create_topology_router(set_gateway=True,**kwargs)
        result = self.check_router_components_on_edge(router_state)
        self.assertEqual(True,result[0]['dr_present'])
        self.assertEqual(False,result[1]['sr_present']) 

    def test_tier1_sr_component_should_present(self):
        """
        Check it should not allow to create port with two
        fixed ips.
        """
        kwargs = {"enable_snat": False}
        router_state = self.create_topology_router(set_gateway=True,**kwargs)
        result = self.check_router_components_on_edge(router_state)
        self.assertEqual(True,result[0]['dr_present'])
        self.assertEqual(False,result[1]['sr_present'])
        public_network_info = {"external_gateway_info": dict(
                    network_id=CONF.network.public_network_id)}
        self.routers_client.update_router(router_state['id'], **public_network_info)
        network_name = data_utils.rand_name(name='tempest-net')
        subnet_name = data_utils.rand_name(name='tempest-subnet')
        network_state = self.create_topology_network(network_name)
        subnet_state = self.create_topology_subnet(subnet_name, network_state,
                                                   router_id=router_state["id"]
                                                   )
        result = self.check_router_components_on_edge(router_state)
        self.assertEqual(True,result[0]['dr_present'])
        self.assertEqual(True,result[1]['sr_present'])

    def test_tier1_sr_should_create_when_service_is_enabled (self):
        """
        Check it should not allow to create port with two
        fixed ips.
        """
        kwargs = {"enable_snat": False}
        router_state = self.create_topology_router(set_gateway=True,**kwargs)
        network_lbaas = self.create_topology_network("network_lbaas")
        sec_rule_client = self.manager.security_group_rules_client
        sec_client = self.manager.security_groups_client
        kwargs = dict(tenant_id=network_lbaas_1['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        lbaas_rules = [dict(direction='ingress', protocol='tcp',
                            port_range_min=constants.HTTP_PORT,
                            port_range_max=constants.HTTP_PORT, ),
                       dict(direction='ingress', protocol='tcp',
                            port_range_min=443, port_range_max=443, )]
        for rule in lbaas_rules:
            self.add_security_group_rule(self.sg, rule)
        subnet_lbaas = self.create_topology_subnet(
            "subnet_lbaas", network_lbaas, router_id=router_state["id"])
        for instance in range(0, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_lbaas_1],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id,create_floating_ip=False)
        result = self.check_router_components_on_edge(router_state)
        self.assertEqual(True,result[0]['dr_present'])
        self.assertEqual(False,result[1]['sr_present'])
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='PING', create_fip=False)
        result = self.check_router_components_on_edge(router_state)
        self.assertEqual(True,result[0]['dr_present'])
        self.assertEqual(True,result[1]['sr_present'])

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
import re
import testtools
import time

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsxv3_client
from vmware_nsx_tempest.services import nsxv_client

CONF = config.CONF


class TestNewCase(feature_manager.FeatureManager):
    """Test New Cases Scenario

    """
    @classmethod
    def skip_checks(cls):
        super(TestNewCase, cls).skip_checks()
        if not test.is_extension_enabled('provider-security-group', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(TestNewCase, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(TestNewCase, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
            print cls.nsx
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def create_topo_single_network(self, namestart, **rtr_kwargs):
        """
        Create Topo where 1 logical switches which is
        connected via tier-1 router.
        """
        name = data_utils.rand_name(namestart)
        rtr_name = "rtr" + name
        network_name = "net" + name
        subnet_name = "net" + name
        router_state = self.create_topology_router(rtr_name, **rtr_kwargs)
        network_state = self.create_topology_network(network_name)
        self.create_topology_subnet(subnet_name, network_state,
                                    router_id=router_state["id"])
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "state_vm_1", [network_state],
            create_floating_ip=True, image_id=image_id)
        self.create_topology_instance(
            "state_vm_2", [network_state],
            create_floating_ip=True, image_id=image_id)
        topology_dict = dict(router_state=router_state,
                             network_state=network_state)
        return topology_dict

    def create_topo_across_networks(self, namestart):
        """
        Create Topo where 2 logical switches which are
        connected via tier-1 router.
        """
        name = data_utils.rand_name(namestart)
        rtr_name = "rtr" + name
        network_name1 = "net" + name
        network_name2 = "net1" + name
        subnet_name1 = "sub1" + name
        subnet_name2 = "sub2" + name
        router_state = self.create_topology_router(rtr_name)
        network_state1 = self.create_topology_network(network_name1)
        network_state2 = self.create_topology_network(network_name2)
        self.create_topology_subnet(subnet_name1, network_state1,
                                    router_id=router_state["id"])
        self.create_topology_subnet(subnet_name2, network_state2,
                                    router_id=router_state["id"],
                                    cidr="22.0.9.0/24")
        image_id = self.get_glance_image_id(['cirros'])
        self.create_topology_instance(
            "state_vm_1", [network_state1],
            create_floating_ip=True, image_id=image_id)
        self.create_topology_instance(
            "state_vm_2", [network_state2],
            create_floating_ip=True, image_id=image_id)
        topology_dict = dict(router_state=router_state,
                             network_state1=network_state1,
                             network_state2=network_state2)
        return topology_dict

    @decorators.idempotent_id('1206016a-91cc-8905-b217-98844caa24a1')
    @testtools.skipUnless(
        [
            i for i in CONF.network_feature_enabled.api_extensions
            if i != "router"][0],
        'Router feature is not available.')
    def test_router_admin_state_when_vms_hosted(self):
        """
        Check router admin state should be down if vms hosted from network
        which is attached to router
        """
        # Create single network attached to router topo
        topology_dict = self.create_topo_single_network("admin_state")
        router_state = topology_dict['router_state']
        network_state = topology_dict['network_state']
        # Update router admin state to False
        kwargs = {"admin_state_up": "False"}
        self.assertRaises(exceptions.BadRequest,
                          self.routers_client.update_router,
                          router_state['id'], **kwargs)
        # Verify E-W traffic
        self.check_cross_network_connectivity(
            network_state,
            self.servers_details.get("state_vm_1").floating_ips[0],
            self.servers_details.get("state_vm_1").server, should_connect=True)
        self.check_cross_network_connectivity(
            network_state,
            self.servers_details.get("state_vm_2").floating_ips[0],
            self.servers_details.get("state_vm_2").server, should_connect=True)
        # Verify fip ping N-S traffic
        for server, details in self.servers_details.items():
            self.verify_ping_to_fip_from_ext_vm(details)
        self.verify_ping_own_fip(self.topology_servers["state_vm_1"])
        self.verify_ping_own_fip(self.topology_servers["state_vm_2"])
        # Update router admin state to False
        self.assertRaises(exceptions.BadRequest,
                          self.routers_client.update_router,
                          router_state['id'], **kwargs)

    @decorators.idempotent_id('1206016a-91cc-8905-b217-98844caa2212')
    def test_mac_learning_with_provider_sec_group_enabled_on_port(self):
        """
        Check mac larning to be enabled on port and provider-sec group
        should get disabled.
        """
        self.create_topology_security_provider_group(self.cmgr_adm,
                                                     provider=True)
        network_state = self.create_topology_network("pro-network")
        self.create_topology_subnet("pro-sub", network_state)
        port = self.create_topology_port(
            network_state, ports_client=self.cmgr_adm.ports_client)
        port_id = port.get('port')['id']
        kwargs = {"port_security_enabled": "false",
                  "mac_learning_enabled": "false", "security_groups": [],
                  "provider_security_groups": []}
        self.assertRaises(exceptions.Forbidden, self.update_topology_port,
                          port_id, **kwargs)
        network_state = self.create_topology_network(
            "pro-network-admin", networks_client=self.cmgr_adm.networks_client)
        self.create_topology_subnet(
            "pro-sub-admin",
            network_state,
            subnets_client=self.cmgr_adm.subnets_client)
        port = self.create_topology_port(
            network_state, ports_client=self.cmgr_adm.ports_client)
        port_id = port.get('port')['id']
        kwargs = {"port_security_enabled": "false",
                  "mac_learning_enabled": "false", "security_groups": [],
                  "provider_security_groups": []}
        self.update_topology_port(
            port_id,
            ports_client=self.cmgr_adm.ports_client,
            **kwargs)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2226016a-91cc-8905-b217-12344caa24a1')
    def test_dist_router_update_probhited(self):
        rtr_kwargs = {"distributed": "true",
                      "admin_state_up": "True"}
        topology_dict = self.create_topo_single_network("rtr_update",
                                                        **rtr_kwargs)
        router_state = topology_dict['router_state']
        router_id = router_state['id']
        kwargs = {"router_type": "exclusive"}
        # Update router from distributed to exclusive should be restricted
        self.assertRaises(exceptions.Forbidden, self.update_topology_router,
                          router_id, **kwargs)
        kwargs = {"router_type": "shared"}
        # Update router from distributed to shared should be restricted
        self.assertRaises(exceptions.Forbidden, self.update_topology_router,
                          router_id, **kwargs)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2306016a-91cc-8905-b217-98844caa24a1')
    def test_assign_firewall_to_shared_router_failed(self):
        """
        Firewall creation with shared router should get fail
        """
        # Create shared router
        rtr_kwargs = {"router_type": "shared",
                      "admin_state_up": "True"}
        router = self.create_topology_router("fire-1", **rtr_kwargs)
        firewall = self.create_fw_v1_rule(name=data_utils.rand_name("fw-rule"),
                                          action="allow",
                                          protocol="icmp")
        fw_rule_id1 = firewall['id']
        self.addCleanup(self._delete_rule_if_exists, fw_rule_id1)
        # Create firewall policy
        body = self.create_fw_v1_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['id']
        self.addCleanup(self._delete_policy_if_exists, fw_policy_id)
        # Insert rule to firewall policy
        self.insert_fw_v1_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Create firewall should fail with shared router
        firewall_1 = self.create_fw_v1(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router['id']])
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("ERROR", firewall_info['STATE'])

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2306016a-91cc-8905-b217-98844caa24a1')
    def test_assign_firewall_to_md_router_failed(self):
        """
        Firewall creation with md router should get fail
        """
        firewall = self.create_fw_v1_rule(name=data_utils.rand_name("fw-rule"),
                                          action="allow",
                                          protocol="icmp")
        fw_rule_id1 = firewall['id']
        self.addCleanup(self._delete_rule_if_exists, fw_rule_id1)
        # Create firewall policy
        body = self.create_fw_v1_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['id']
        self.addCleanup(self._delete_policy_if_exists, fw_policy_id)
        # Insert rule to firewall policy
        self.insert_fw_v1_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Create firewall should fail with shared router
        router_list = self.routers_client.list_routers()
        router_id = [
            router for router in router_list
            if "metadata_proxy_router" in router.get('name')]['id']
        firewall_1 = self.create_fw_v1(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router_id])
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("ERROR", firewall_info['STATE'])

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2676016a-91cc-8905-b217-98844caa24a1')
    def test_update_firewall_from_router_to_no_router(self):
        """
        Firewall creation with shared router should get fail
        """
        rtr_kwargs = {"router_type": "shared",
                      "admin_state_up": "True"}
        router = self.create_topology_router("fire-1", **rtr_kwargs)
        firewall = self.create_fw_v1_rule(name=data_utils.rand_name("fw-rule"),
                                          action="allow",
                                          protocol="icmp")
        fw_rule_id1 = firewall['id']
        self.addCleanup(self._delete_rule_if_exists, fw_rule_id1)
        # Create firewall policy
        body = self.create_fw_v1_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['id']
        self.addCleanup(self._delete_policy_if_exists, fw_policy_id)
        # Insert rule to firewall policy
        self.insert_fw_v1_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Create firewall should fail with shared router
        firewall_1 = self.create_fw_v1(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router['id']])
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_1['firewall']['id'])
        self.assertIn("ACTIVE", firewall_info['STATE'])
        kwargs = {"router": []}
        self.fwaasv1_client.update_fw_v1(firewall_1['firewall']['id'],
                                         **kwargs)
        firewall_info = self.show_fw_v1(firewall_1['firewall']['id'])
        self.assertIn("INACTIVE", firewall_info['STATE'])
        kwargs = {"router": [router['id']]}
        self.fwaasv1_client.update_fw_v1(firewall_1['firewall']['id'],
                                         **kwargs)
        self._wait_fw_v1_until_ready(firewall_1['firewall']['id'])
        firewall_info = self.show_fw_v1(firewall_1['firewall']['id'])
        self.assertIn("ACTIVE", firewall_info['STATE'])

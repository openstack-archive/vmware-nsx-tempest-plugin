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

from oslo_utils import uuidutils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxv_client

CONF = config.CONF


class TestNewCase(feature_manager.FeatureManager):

    """Test New Cases Scenario

    """
    @classmethod
    def setup_clients(cls):
        super(TestNewCase, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.routers_client = cls.cmgr_adm.routers_client
        cls.networks_client = cls.cmgr_adm.networks_client
        cls.subnets_client = cls.cmgr_adm.subnets_client
        cls.sec_rule_client = cls.cmgr_adm.security_group_rules_client
        cls.sec_client = cls.cmgr_adm.security_groups_client

    @classmethod
    def resource_setup(cls):
        super(TestNewCase, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def create_topo_single_network(self, namestart, create_instance=True,
                                   set_gateway=True, **kwargs):
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

    def create_topo_two_routers_two_networks(self,
                                             create_instance=True,
                                             set_gateway=True, **kwargs):
        """
        Create Topo where 2 logical switches which are
        two routers are connected to two different sunets.
        """
        rtr_name = data_utils.rand_name(name='tempest-router')
        rtr_name2 = data_utils.rand_name(name='tempest-router')
        network_name1 = data_utils.rand_name(name='tempest-net')
        network_name2 = data_utils.rand_name(name='tempest-net')
        subnet_name1 = data_utils.rand_name(name='tempest-subnet')
        subnet_name2 = data_utils.rand_name(name='tempest-subnet')
        router_state = self.create_topology_router(rtr_name,
                                                   set_gateway=set_gateway,
                                                   **kwargs)
        router_state2 = self.create_topology_router(rtr_name2,
                                                    set_gateway=set_gateway,
                                                    **kwargs)
        network_state1 = self.create_topology_network(network_name1)
        network_state2 = self.create_topology_network(network_name2)
        subnet_state1 = self.create_topology_subnet(
            subnet_name1, network_state1, router_id=router_state["id"])
        subnet_state2 = self.create_topology_subnet(
                                                    subnet_name2,
                                                    network_state2,
                                                    router_id=router_state2["\
                                                    id"],
                                                    cidr=constants.CIDR)
        if create_instance:
            self.create_topology_instance(
                                          "server1",
                                          [network_state1])
            self.create_topology_instance(
                                          "server2",
                                          [network_state2])
        topology_dict = dict(router_state=router_state,
                             router_state2=router_state2,
                             network_state1=network_state1,
                             network_state2=network_state2,
                             subnet_state1=subnet_state1,
                             subnet_state2=subnet_state2)
        return topology_dict

    def create_topo_across_networks(self, namestart, create_instance=True):
        """
        Create Topo where 2 logical switches which are
        connected via tier-1 router.
        """
        rtr_name = data_utils.rand_name(name='tempest-router')
        network_name1 = data_utils.rand_name(name='tempest-net')
        network_name2 = data_utils.rand_name(name='tempest-net')
        subnet_name1 = data_utils.rand_name(name='tempest-subnet')
        subnet_name2 = data_utils.rand_name(name='tempest-subnet')
        router_state = self.create_topology_router(rtr_name)
        network_state1 = self.create_topology_network(network_name1)
        network_state2 = self.create_topology_network(network_name2)
        self.create_topology_subnet(subnet_name1, network_state1,
                                    router_id=router_state["id"])
        self.create_topology_subnet(subnet_name2, network_state2,
                                    router_id=router_state["id"],
                                    cidr=constants.CIDR)
        if create_instance:
            image_id = self.get_glance_image_id(['cirros', "esx"])
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

    def verify_ping_to_fip_from_ext_vm(self, server_details):
        self.test_fip_check_server_and_project_network_connectivity(
            server_details)

    def verify_ping_own_fip(self, server):
        fip = server["floating_ips"][0]["floating_ip_address"]
        client = self.verify_server_ssh(server, floating_ip=fip)
        ping_cmd = "ping -c 1 %s " % fip
        self.exec_cmd_on_server_using_fip(ping_cmd, ssh_client=client)

    @decorators.idempotent_id('1206127a-91cc-8905-b217-98844caa35b2')
    def test_router_interface_port_update(self):
        """
        Check it should not allow to update
        port security of router port
        """
        self.create_topo_single_network(
            "route-port", create_instance=False)
        p_client = self.ports_client
        port = self.get_router_port(p_client)
        kwargs = {'port_security_enabled': True}
        self.assertRaises(exceptions.BadRequest,
                          p_client.update_port,
                          port, **kwargs)

    @decorators.idempotent_id('1206238b-91cc-8905-b217-98844caa46c3')
    @testtools.skipUnless(
        [i for i in CONF.network_feature_enabled.api_extensions
            if i != "mac-learning"][0],
        'Mac learning feature is not available.')
    def test_port_create_mac_learning_port_security(self):
        """
        Check it should create port with port security enabled
        and mac learning disabled.
        """
        topology_dict = self.create_topo_single_network(
            "route-port", create_instance=False)
        network_state = topology_dict['network_state']
        args = {'port_security_enabled': True,
                'mac_learning_enabled': False}
        port = self.create_topology_port(
            network_state, ports_client=self.cmgr_adm.ports_client, **args)
        port = port['port']
        self.assertEqual(True, port['port_security_enabled'])
        if 'mac_learning_enabled' in port:
            raise Exception("Mac learning is enabled")
        self.assertEqual("ACTIVE", port['status'])

    @decorators.idempotent_id('1207349c-91cc-8905-b217-98844caa57d4')
    def test_create_port_with_two_fixed_ip(self):
        """
        Check it should not allow to create port with two
        fixed ips.
        """
        topology_dict = self.create_topo_single_network(
            "instance_port", create_instance=False)
        network_state = topology_dict['network_state']
        subnet_state = topology_dict['subnet_state']
        network_cidr = (
            CONF.network.project_network_cidr.rsplit('/')[0]).rsplit('.',
                                                                     1)
        fix_ip = [{'subnet_id': subnet_state.get(
                   'id'),
                   'ip_address': network_cidr[0] + '.20'},
                  {'subnet_id': subnet_state.get('id'),
                   'ip_address': network_cidr[0] + '.21'}]
        args = {'fixed_ips': fix_ip, 'network_id': network_state['id']}
        self.assertRaises(exceptions.BadRequest,
                          self.cmgr_adm.ports_client.create_port,
                          **args)

    @decorators.idempotent_id('1207450d-91cc-8905-b217-98844caa68e5')
    def test_update_port_with_two_fixed_ip(self):
        """
        Check it should not update port with two
        fixed ips.
        """
        topology_dict = self.create_topo_single_network(
            "instance_port", create_instance=False)
        network_state = topology_dict['network_state']
        subnet_state = topology_dict['subnet_state']
        network_cidr = (
            CONF.network.project_network_cidr.rsplit('/')[0]).rsplit('.',
                                                                     1)
        fix_ip1 = [
            {'subnet_id': subnet_state.get('id'),
             'ip_address': network_cidr[0] + '.20'}]
        port = self.create_topology_port(
            network_state, ports_client=self.cmgr_adm.ports_client,
            fixed_ips=fix_ip1)
        port = port['port']
        self.assertEqual("ACTIVE", port['status'])
        fix_ip = [{'subnet_id': subnet_state.get(
                   'id'),
                   'ip_address': network_cidr[0] + '.21'},
                  {'subnet_id': subnet_state.get('id'),
                   'ip_address': network_cidr[0] + '.22'}]
        args = {'fixed_ips': fix_ip}
        self.assertRaises(exceptions.BadRequest,
                          self.cmgr_adm.ports_client.update_port,
                          port['id'], **args)

    @decorators.idempotent_id('1206016a-91cc-8905-b217-98844caa24a1')
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

    @decorators.idempotent_id('9006016a-91cc-8905-b217-98844caa2212')
    def test_dhcp_port_update_with_device_owner_field(self):
        """
        Check dhcp port update with device owner field doesn't let
        operational down for that port.
        """
        # Create single network attached to router topo
        self.create_topo_single_network(
            "admin_state", create_instance=False)
        ports = self.ports_client.list_ports()
        for port in ports['ports']:
            if 'device_owner' in port:
                if port['device_owner'] == "network:dhcp":
                    kwargs = {"device_owner": "nova:compute"}
                    self.assertRaises(
                        exceptions.BadRequest, self.ports_client.update_port,
                        port['id'], **kwargs)

    @decorators.idempotent_id('9006123b-91cc-8905-b217-98844caa3423')
    def test_boot_instance_with_dhcp_port(self):
        """
        Check it should not allow to boot instance
        with dhcp port.
        """
        # Create single network attached to router topo
        topology_dict = self.create_topo_single_network(
            "dhcp_port", create_instance=False)
        network_state = topology_dict['network_state']
        ports = self.ports_client.list_ports()
        for port in ports['ports']:
            if 'device_owner' in port:
                if port['device_owner'] == "network:dhcp" \
                        and port['network_id'] == network_state['id']:
                    port = port
                    break
        image_id = self.get_glance_image_id(['cirros', "esx"])
        self.assertRaises(exceptions.Conflict, self.create_topology_instance,
                          "state_vm_1", create_floating_ip=False,
                          image_id=image_id, port=port)

    @decorators.idempotent_id('1206016a-91cc-8905-b217-98844caa2212')
    @testtools.skipUnless(
        [i for i in CONF.network_feature_enabled.api_extensions
            if i != "provider-security-group"][0],
        'provider-security-group feature is not available.')
    def test_update_port_with_provider_securtiy_group(self):
        """
        Check provider security group attachment should be failed
        when port security  disabled.
        """
        self.create_topology_security_provider_group(self.cmgr_adm,
                                                     provider=True)
        network_state = self.create_topology_network("pro-network")
        self.create_topology_subnet("pro-sub", network_state)
        kwargs = {"port_security_enabled": "false",
                  "security_groups": []}
        port = self.create_topology_port(
            network_state, ports_client=self.cmgr_adm.ports_client)
        port_id = port.get('port')['id']
        provider_sec = self.create_topology_security_provider_group(
            self.cmgr_adm,
            provider=True)
        kwargs = {
            "provider_security_groups": provider_sec['id']}
        self.assertRaises(
            exceptions.BadRequest, self.ports_client.update_port,
            port_id, **kwargs)

    @decorators.idempotent_id('1208238c-91cc-8905-b217-98844caa4434')
    @testtools.skipUnless(
        [i for i in CONF.network_feature_enabled.api_extensions
            if i != "port-security-enabled"][0],
        'provider-security-group feature is not available.')
    def test_dhcp_port_of_network_with_port_security_disabled(self):
        """
        Check port security of dhcp port should be disabled.
        """
        network_state = self.create_topology_network("test-network")
        kwargs = {"port_security_enabled": "false"}
        self.networks_client.update_network(network_state['id'], **kwargs)
        self.create_topology_subnet("test-sub", network_state)
        ports = self.ports_client.list_ports()
        for port in ports['ports']:
            if 'device_owner' in port:
                if port['device_owner'] == "network:dhcp" and \
                        port['network_id'] == network_state['id']:
                    port = port
                    break
        if port['port_security_enabled'] is not False:
            raise Exception("Port security of dhcp port is enabled")

    @decorators.idempotent_id('1209349d-91cc-8905-b217-98844cab5545')
    @testtools.skipUnless(
        [i for i in CONF.network_feature_enabled.api_extensions
            if i != "provider-security-group"][0],
        'provider-security-group feature is not available.')
    def test_port_security_disabled_port_in_exclude_list(self):
        """
        Check port security disabled port should be in exclude
        list at the backend.
        """
        network_state = self.create_topology_network("test-network")
        self.create_topology_subnet("test-sub", network_state)
        kwargs = {"port_security_enabled": "false",
                  "security_groups": []}
        port = self.create_topology_port(
            network_state, ports_client=self.cmgr_adm.ports_client, **kwargs)
        port_id = port.get('port')['id']
        ports = self.nsx.get_logical_ports()
        port_tags = None
        for port in ports:
            if 'tags' in port:
                for tag in port['tags']:
                    if tag['tag'] == port_id:
                        port_tags = {'tags': port['tags']}
        result = (item for item in port_tags['tags'] if
                  item["tag"] == "Exclude-Port").next()
        if result is None:
            raise Exception("Port is not in exclude list")

    @decorators.idempotent_id('1206016a-91cc-8905-b217-98844caa2212')
    @testtools.skipUnless(
        [i for i in CONF.network_feature_enabled.api_extensions
            if i != "provider-security-group"][0],
        'provider-security-group feature is not available.')
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
                  "mac_learning_enabled": "true", "security_groups": [],
                  "provider_security_groups": []}
        self.update_topology_port(
            port_id, ports_client=self.cmgr_adm.ports_client, **kwargs)
        image_id = self.get_glance_image_id(['cirros', "esx"])
        vm_state = self.create_topology_instance(
            "state_vm_1", create_floating_ip=False,
            image_id=image_id, port=port['port'])
        self.assertEqual("ACTIVE", vm_state['status'])

    @decorators.idempotent_id('1207561e-91cc-8905-b217-98844caa79f6')
    def test_create_port_with_dhcp_port_ip(self):
        topology_dict = self.create_topo_single_network(
            "instance_port", deploy_instance=False)
        network_state = topology_dict['network_state']
        subnet_state = topology_dict['subnet_state']
        network_cidr = (
            CONF.network.project_network_cidr.rsplit('/')[0]).rsplit('.',
                                                                     1)
        fix_ip = [
            {'subnet_id': subnet_state.get('id'),
             'ip_address': network_cidr[0] + '.2'}]
        args = {'fixed_ips': fix_ip, 'network_id': network_state['id']}
        self.assertRaises(exceptions.BadRequest,
                          self.cmgr_adm.ports_client.create_port,
                          **args)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2226016a-91cc-8905-b217-12344caa24a1')
    def test_dist_router_update_probhited(self):
        """
        Updation on distributed router to exclusive should not be
        allowed
        """
        kwargs = {"distributed": "true",
                  "admin_state_up": "True"}
        topology_dict = self.create_topo_single_network("rtr_update",
                                                        create_instance=False,
                                                        set_gateway=False,
                                                        **kwargs)
        router_state = topology_dict['router_state']
        router_id = router_state['id']
        kwargs = {"router_type": "exclusive"}
        # Update router from distributed to exclusive should be restricted
        self.assertRaises(exceptions.BadRequest, self.update_topology_router,
                          router_id, **kwargs)
        kwargs = {"router_type": "shared"}
        # Update router from distributed to shared should be restricted
        self.assertRaises(exceptions.BadRequest, self.update_topology_router,
                          router_id, **kwargs)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2306016a-91cc-8905-b217-98844caa24a1')
    def test_assign_firewall_to_shared_router_failed(self):
        """
        Firewall creation with shared router should get fail
        """
        # Create shared router
        kwargs = {"router_type": "shared",
                  "admin_state_up": "True"}
        router = self.create_topology_router("fire-1", **kwargs)
        firewall = self.create_fw_v1_rule(action="allow",
                                          protocol="icmp")
        fw_rule_id1 = firewall['id']
        # Create firewall policy
        body = self.create_fw_v1_policy()
        fw_policy_id = body['id']
        # Insert rule to firewall policy
        self.insert_fw_v1_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Create firewall should fail with shared router
        firewall_1 = self.create_fw_v1(
            firewall_policy_id=fw_policy_id,
            router_ids=[router['id']])
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("ERROR", firewall_info['firewall']['status'])
        kwargs = {"router_ids": []}
        self.update_fw_v1(firewall_1['id'], **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2306016a-91cc-8905-b217-98844caa24a1')
    def test_assign_firewall_to_md_router_failed(self):
        """
        Firewall creation with md router should get fail
        """
        firewall = self.create_fw_v1_rule(action="allow",
                                          protocol="icmp")
        fw_rule_id1 = firewall['id']
        self.addCleanup(self._delete_rule_if_exists, fw_rule_id1)
        # Create firewall policy
        body = self.create_fw_v1_policy()
        fw_policy_id = body['id']
        # Insert rule to firewall policy
        self.insert_fw_v1_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Create firewall should fail with shared router
        routers_list = self.cmgr_adm.routers_client.list_routers()
        router_id = [
            router for router in routers_list['routers']
            if "metadata_proxy_router" in router.get('name')][0]['id']
        firewall_1 = self.create_fw_v1(
            firewall_policy_id=fw_policy_id,
            router_ids=[router_id])
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("ERROR", firewall_info['firewall']['status'])
        kwargs = {"router_ids": []}
        self.fwaasv1_client.update_fw_v1(firewall_1['id'], **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2676016a-91cc-8905-b217-98844caa24a1')
    def test_update_firewall_from_router_to_no_router(self):
        """
        Firewall update should work on exclusive router
        """
        kwargs = {"router_type": "exclusive",
                  "admin_state_up": "True"}
        router = self.create_topology_router("fire-1", **kwargs)
        firewall = self.create_fw_v1_rule(action="allow",
                                          protocol="icmp")
        fw_rule_id1 = firewall['id']
        # Create firewall policy
        body = self.create_fw_v1_policy()
        fw_policy_id = body['id']
        # Insert rule to firewall policy
        self.insert_fw_v1_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Create firewall should fail with shared router
        firewall_1 = self.create_fw_v1(
            firewall_policy_id=fw_policy_id,
            router_ids=[router['id']])
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("ACTIVE", firewall_info['firewall']['status'])
        kwargs = {"router_ids": []}
        self.update_fw_v1(firewall_1['id'], **kwargs)
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("INACTIVE", firewall_info['firewall']['status'])
        kwargs = {"router_ids": [router['id']]}
        self.update_fw_v1(firewall_1['id'], **kwargs)
        self._wait_fw_v1_until_ready(firewall_1['id'])
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("ACTIVE", firewall_info['firewall']['status'])

    @decorators.idempotent_id('2226016a-91cc-8905-b217-12344caa24a1')
    def test_update_router_with_static_route_via_0_0_0_0(self):
        """
        Check it should not allow to add static route on router with
        0.0.0.0/0 next hop.
        """
        kwargs = {"distributed": "true",
                  "admin_state_up": "True"}
        topology_dict = self.create_topo_single_network("rtr_update",
                                                        create_instance=False,
                                                        set_gateway=False,
                                                        **kwargs)
        next_hop = topology_dict['subnet_state']['allocation_pools'][0]['end']
        router_state = topology_dict['router_state']
        routes = [{
                  "destination": "0.0.0.0/0",
                  "nexthop": next_hop
                  }]
        router_id = router_state['id']
        self.assertRaises(exceptions.BadRequest,
                          self.routers_client.update_router,
                          router_id, routes=routes)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2227127b-91cc-8905-b217-12344cab35b2')
    def test_update_router_nsxv3_with_static_route_via_0_0_0_0(self):
        """
        Check it should not allow to add static route on router with
        0.0.0.0/0 next hop.
        """
        kwargs = {"admin_state_up": "True"}
        topology_dict = self.create_topo_single_network("rtr_update",
                                                        create_instance=False,
                                                        set_gateway=False,
                                                        **kwargs)
        next_hop = topology_dict['subnet_state']['allocation_pools'][0]['end']
        router_state = topology_dict['router_state']
        routes = [{
                  "destination": "0.0.0.0/0",
                  "nexthop": next_hop
                  }]
        router_id = router_state['id']
        self.assertRaises(exceptions.BadRequest,
                          self.routers_client.update_router,
                          router_id, routes=routes)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('1116016a-91cc-8905-b217-12344caa24a1')
    def test_mac_learning_should_not_applied_over_trusted_ports(self):
        """
        Test mac learning shouldn't be applied over trusted ports
        """
        fip = self.create_floatingip(client=self.cmgr_adm.floating_ips_client)
        ports = self.cmgr_adm.ports_client.list_ports()
        port_id = [port.get("id")
                   for port in ports['ports'] if
                   port.get('fixed_ips')[0]["ip_address"] ==
                   fip["floating_ip_address"]][0]
        kwargs = {"mac_learning_enabled": True}
        self.assertRaises(exceptions.BadRequest,
                          self.cmgr_adm.ports_client.update_port, port_id,
                          **kwargs)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('8816016a-91cc-8905-b217-12344caa9112')
    def test_create_sec_group_with_invalid_protocol(self):
        """
        Security group rule shouldn't be created wrong protocol
        """
        sec_group = self.create_topology_empty_security_group()
        rule = dict(direction='egress', protocol='ipip')
        self.add_security_group_rule(sec_group, rule)
        rule = dict(direction='egress', protocol='ipipip')
        self.assertRaises(exceptions.BadRequest,
                          self.add_security_group_rule,
                          sec_group, rule)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2226016a-91cc-8905-b217-12344caa24a1')
    def test_exc_to_shared_router_update_not_allowed_with_fw(self):
        """
        Check if updation of router from exclusive to shared is restricted
        if firewall is attatched
        """
        kwargs = {"router_type": "exclusive",
                  "admin_state_up": "True"}
        name = "rtr-exc"
        router_state = self.create_topology_router(name, set_gateway=True,
                                                   **kwargs)
        router_id = router_state['id']
        firewall = self.create_fw_v1_rule(action="allow",
                                          protocol="icmp")
        fw_rule_id1 = firewall['id']
        # Create firewall policy
        body = self.create_fw_v1_policy()
        fw_policy_id = body['id']
        # Insert rule to firewall policy
        self.insert_fw_v1_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Create firewall should fail with shared router
        firewall_1 = self.create_fw_v1(
            firewall_policy_id=fw_policy_id,
            router_ids=[router_id])
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("ACTIVE", firewall_info['firewall']['status'])
        kwargs = {"router_type": "shared"}
        # Update router from distributed to shared should be restricted
        self.assertRaises(exceptions.BadRequest, self.update_topology_router,
                          router_id, **kwargs)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2226016a-92cc-5098-b217-12344caa24a1')
    def test_vm_traffic_provider_network_vlan(self):
        """
           Create VLAN provider network with dvs as physical network
           create instances of ESX image and check traffic
        """
        router_name = data_utils.rand_name(name='tempest-router')
        net_name = data_utils.rand_name(name='tempest-net')
        vlanid = int(CONF.nsxv.provider_vlan_id)
        router = self.create_topology_router(
                                     router_name,
                                     routers_client=self.routers_client)
        body = {"provider:network_type": constants.VLAN_TYPE,
                "admin_state_up": 'True', "provider:segmentation_id": vlanid}
        network = self.create_topology_network(
                                      net_name,
                                      networks_client=self.networks_client,
                                      **body)
        subnet_name = network['name'] + 'sub'
        self.create_topology_subnet(subnet_name, network,
                                    routers_client=self.routers_client,
                                    subnets_client=self.subnet_client,
                                    router_id=router['id'])
        kwargs = dict(tenant_id=network['tenant_id'],
                      security_group_rules_client=self.sec_rule_client,
                      security_groups_client=self.sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        vm1 = self.create_topology_instance(
                  "server1", [network],
                  security_groups=[{'name': self.sg['name']}],
                  clients=self.cmgr_adm)
        vm2 = self.create_topology_instance(
                  "server2", [network],
                  security_groups=[{'name': self.sg['name']}],
                  clients=self.cmgr_adm)
        ip_address = vm1['floating_ips'][0]['floating_ip_address']
        ssh_source = self._get_remote_client(ip_address, use_password=True)
        remote_ip = vm2.values()[1].values()[0][0]['addr']
        # Verify connectivity between vms
        self.check_remote_connectivity(ssh_source, remote_ip,
                                       should_connect=True)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2226016a-93cc-5099-b217-12344caa24a1')
    def test_vm_traffic_provider_network_vxlan(self):
        """
           Create a vxlan provider network and
           verify default physical network is vdnscope,
           create instances of ESX image and check traffic
        """
        router_name = data_utils.rand_name(name='tempest-rtr')
        net_name = data_utils.rand_name(name='tempest-net')
        router = self.create_topology_router(
                                     router_name,
                                     routers_client=self.routers_client)
        body = {"provider:network_type": 'vxlan',
                "admin_state_up": 'True'}
        network = self.create_topology_network(
                                       net_name,
                                       networks_client=self.networks_client,
                                       **body)
        # Verify default physical network is vdnscope, not dvs
        self.assertIn('vdnscope', network['provider:physical_network'])
        subnet_name = network['name'] + 'sub'
        self.create_topology_subnet(subnet_name, network,
                                    routers_client=self.routers_client,
                                    subnets_client=self.subnet_client,
                                    router_id=router['id'])
        kwargs = dict(tenant_id=network['tenant_id'],
                      security_group_rules_client=self.sec_rule_client,
                      security_groups_client=self.sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        vm1 = self.create_topology_instance(
                  "server1", [network],
                  security_groups=[{'name': self.sg['name']}],
                  clients=self.cmgr_adm)
        vm2 = self.create_topology_instance(
                  "server2", [network],
                  security_groups=[{'name': self.sg['name']}],
                  clients=self.cmgr_adm)
        ip_address = vm1['floating_ips'][0]['floating_ip_address']
        ssh_source = self._get_remote_client(ip_address, use_password=True)
        remote_ip = vm2.values()[1].values()[0][0]['addr']
        # Verify Connectivity between vms
        self.check_remote_connectivity(ssh_source, remote_ip,
                                       should_connect=True)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('2226016a-93cc-5099-b217-12344caa24a1')
    def test_firewall_witout_policy_added_to_router_active(self):
        """
        create two routers and two subnets[each router connected to a
        different subnet].
        create two firewalls, one connected to each router,
        remove firewall from one router and connect it to another router
        the firewall should remain ACTIVE
        """
        kwargs = {"distributed": "true",
                  "admin_state_up": "True"}
        topology_dict = self.create_topo_two_routers_two_networks(
                                                         create_instance=False,
                                                         set_gateway=True,
                                                         **kwargs)
        router_id1 = topology_dict['router_state']['id']
        router_id2 = topology_dict['router_state2']['id']
        # Create Firewall1 and add it to the router1's interface
        body = self.create_fw_v1_policy()
        fw_policy_id = body['id']
        firewall_1 = self.create_fw_v1(
            firewall_policy_id=fw_policy_id,
            router_ids=[router_id1])
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_1['id'])
        self.assertIn("ACTIVE", firewall_info['firewall']['status'])
        # Create Firewall2 and add it to the router2's interface
        body2 = self.create_fw_v1_policy()
        fw_policy_id2 = body2['id']
        firewall_2 = self.create_fw_v1(
            firewall_policy_id=fw_policy_id2,
            router_ids=[router_id2])
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_2['id'])
        self.assertIn("ACTIVE", firewall_info['firewall']['status'])
        # Delete router1 from firewall1
        kwargs = {"router_ids": []}
        self.update_fw_v1(firewall_1['id'], **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        # Add firewall2 to router1
        kwargs = {"router_ids": [router_id1]}
        self.update_fw_v1(firewall_2['id'], **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        firewall_info = self.show_fw_v1(firewall_2['id'])
        self.assertIn("ACTIVE", firewall_info['firewall']['status'])

    @decorators.idempotent_id('2226016a-93cc-5099-b217-12344caa25b1')
    def test_barbican_terminated_https_traffic(self):
        barbican_secrets = self.create_barbican_secret_conatainer(
            constants.CERT_FILE, constants.KEY_FILE)
        barbican_container = barbican_secrets['secret_container']
        topology_dict = self.create_topo_single_network(
            "test_secret", create_instance=False)
        network_state = topology_dict['network_state']
        subnet_state = topology_dict['subnet_state']
        sec_rule_client = self.sec_rule_client
        sec_client = self.sec_client
        kwargs = dict(tenant_id=network_state['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        lbaas_rules = [dict(direction='ingress', protocol='tcp',
                            port_range_min=constants.HTTP_PORT,
                            port_range_max=constants.HTTP_PORT, ),
                       dict(direction='ingress', protocol='tcp',
                            port_range_min=443, port_range_max=443, )]
        for rule in lbaas_rules:
            self.add_security_group_rule(
                self.sg,
                rule,
                ruleclient=sec_rule_client,
                secclient=sec_client,
                tenant_id=network_state['tenant_id'])
        no_of_servers = 2
        image_id = self.get_glance_image_id(["cirros", "esx"])
        for instance in range(0, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_state],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id, clients=self.cmgr_adm)
        self.poke_counters = 12
        self.hm_delay = 4
        self.hm_max_retries = 3
        self.hm_timeout = 10
        self.server_names = []
        self.loadbalancer = None
        self.vip_fip = None
        self.web_service_start_delay = 2.5
        self.start_web_servers(constants.HTTP_PORT)
        self.create_barbican_project_lbaas(
            protocol_type="TERMINATED_HTTPS",
            protocol_port="443",
            lb_algorithm="ROUND_ROBIN",
            hm_type='HTTP',
            member_count=2,
            weight=5,
            pool_protocol='HTTP',
            pool_port='80',
            vip_subnet_id=subnet_state['id'],
            barbican_container=barbican_container,
            count=0)
        self.check_lbaas_project_weight_values(HTTPS=True)

    @decorators.idempotent_id('2236016a-93cc-5099-b217-12344caa26c2')
    def test_barbican_http_https_traffic(self):
        barbican_secrets = self.create_barbican_secret_conatainer(
            constants.CERT_FILE, constants.KEY_FILE)
        barbican_container = barbican_secrets['secret_container']
        topology_dict = self.create_topo_single_network(
            "test_secret", create_instance=False)
        network_state = topology_dict['network_state']
        subnet_state = topology_dict['subnet_state']
        sec_rule_client = self.sec_rule_client
        sec_client = self.sec_client
        kwargs = dict(tenant_id=network_state['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        lbaas_rules = [dict(direction='ingress', protocol='tcp',
                            port_range_min=constants.HTTP_PORT,
                            port_range_max=constants.HTTP_PORT, ),
                       dict(direction='ingress', protocol='tcp',
                            port_range_min=443, port_range_max=443, )]
        for rule in lbaas_rules:
            self.add_security_group_rule(
                self.sg,
                rule,
                ruleclient=sec_rule_client,
                secclient=sec_client,
                tenant_id=network_state['tenant_id'])
        no_of_servers = 2
        image_id = self.get_glance_image_id(["cirros", "esx"])
        for instance in range(0, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_state],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id, clients=self.cmgr_adm)
        self.start_web_servers(constants.HTTP_PORT)
        self.poke_counters = 12
        self.hm_delay = 4
        self.hm_max_retries = 3
        self.hm_timeout = 10
        self.server_names = []
        self.loadbalancer = None
        self.vip_fip = None
        self.web_service_start_delay = 2.5
        topo_dict = self.create_barbican_project_lbaas(
            protocol_type="TERMINATED_HTTPS",
            protocol_port="443",
            lb_algorithm="ROUND_ROBIN",
            hm_type='HTTP',
            member_count=2,
            weight=5,
            pool_protocol='HTTP',
            pool_port='80',
            vip_subnet_id=subnet_state['id'],
            barbican_container=barbican_container,
            count=0)
        self.check_lbaas_project_weight_values(HTTPS=True)
        no_of_servers = 4
        self.topology_servers = {}
        for instance in range(2, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_state],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id, clients=self.cmgr_adm)
        self.start_web_servers(constants.HTTP_PORT)
        topo_dict = self.create_barbican_project_lbaas(
            protocol_type="HTTP",
            protocol_port="80",
            lb_algorithm="ROUND_ROBIN",
            hm_type='HTTP',
            member_count=4,
            weight=5,
            pool_protocol='HTTP',
            pool_port='80',
            vip_subnet_id=subnet_state['id'],
            barbican_container=barbican_container,
            lb_id=topo_dict['lb_id'],
            count=2)
        self.check_lbaas_project_weight_values(barbican_http=True)

    @decorators.idempotent_id('2326016a-93cc-5099-b217-12344caa37d3')
    def test_barbican_multiple_listeners_with_secrets(self):
        barbican_secrets = self.create_barbican_secret_conatainer(
            constants.CERT_FILE, constants.KEY_FILE)
        barbican_container = barbican_secrets['secret_container']
        topology_dict = self.create_topo_single_network(
            "test_secret", create_instance=False)
        network_state = topology_dict['network_state']
        subnet_state = topology_dict['subnet_state']
        sec_rule_client = self.sec_rule_client
        sec_client = self.sec_client
        kwargs = dict(tenant_id=network_state['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        lbaas_rules = [dict(direction='ingress', protocol='tcp',
                            port_range_min=constants.HTTP_PORT,
                            port_range_max=constants.HTTP_PORT, ),
                       dict(direction='ingress', protocol='tcp',
                            port_range_min=443, port_range_max=443, )]
        for rule in lbaas_rules:
            self.add_security_group_rule(
                self.sg,
                rule,
                ruleclient=sec_rule_client,
                secclient=sec_client,
                tenant_id=network_state['tenant_id'])
        self.vip_ip_address = ''
        self.namestart = 'lbaas-ops'
        self.poke_counters = 12
        self.hm_delay = 4
        self.hm_max_retries = 3
        self.hm_timeout = 10
        self.server_names = []
        self.loadbalancer = None
        self.vip_fip = None
        self.web_service_start_delay = 2.5
        protocol_type = "TERMINATED_HTTPS"
        protocol_port = 443
        vip_subnet_id = subnet_state['id']
        lb_name = data_utils.rand_name("tempest_lb")
        self.loadbalancer = self.load_balancers_admin_client.\
            create_load_balancer(
                                 name=lb_name,
                                 vip_subnet_id=vip_subnet_id
                                )['loadbalancer']
        lb_id = self.loadbalancer['id']
        self.addCleanup(
            self.load_balancers_admin_client.delete_load_balancer,
            lb_id)
        self.load_balancers_admin_client.wait_for_load_balancer_status(lb_id)
        for i in range(1, 20):
            listener_name = data_utils.rand_name("tempest_lb")
            self.listener = self.listeners_admin_client.create_listener(
                loadbalancer_id=lb_id,
                protocol=protocol_type,
                protocol_port=protocol_port,
                name=listener_name,
                default_tls_container_ref=barbican_container
                ["container_ref"])['listener']
            self.addCleanup(
                self.listeners_admin_client.delete_listener,
                self.listener['id'])
            self.load_balancers_admin_client.wait_for_load_balancer_status(
                lb_id)
            protocol_port = protocol_port + 1

    @decorators.idempotent_id('3226016a-93cc-5099-b217-12344caa48e5')
    def test_barbican_create_listener_with_empty_secrets(self):
        secret_name1 = data_utils.rand_name(name='tempest-cert-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "algorithm": constants.ALGORITHM,
                  "name": secret_name1}
        barbican_secret1 = self.create_barbican_secret(**kwargs)
        secret_name2 = data_utils.rand_name(name='tempest-key-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "algorithm": constants.ALGORITHM,
                  "name": secret_name2}
        barbican_secret2 = self.create_barbican_secret(**kwargs)
        container_name = data_utils.rand_name(name='tempest-container')
        kwargs = {"type": constants.CONTAINER_TYPE,
                  "name": container_name,
                  "secret_refs": [{"secret_ref":
                                   barbican_secret1['secret_ref'],
                                   "name": 'certificate'},
                                  {"secret_ref":
                                   barbican_secret2['secret_ref'],
                                   "name": 'private_key'}]}
        barbican_container = self.create_barbican_container(**kwargs)
        topology_dict = self.create_topo_single_network(
            "test_secret", create_instance=False)
        subnet_state = topology_dict['subnet_state']
        self.vip_ip_address = ''
        self.namestart = 'lbaas-ops'
        self.poke_counters = 12
        self.hm_delay = 4
        self.hm_max_retries = 3
        self.hm_timeout = 10
        self.server_names = []
        self.loadbalancer = None
        self.vip_fip = None
        self.web_service_start_delay = 2.5
        protocol_type = "TERMINATED_HTTPS"
        protocol_port = 443
        vip_subnet_id = subnet_state['id']
        lb_name = data_utils.rand_name("tempest_lb")
        self.loadbalancer = self.load_balancers_admin_client.\
            create_load_balancer(name=lb_name,
                                 vip_subnet_id=vip_subnet_id)['loadbalancer']
        lb_id = self.loadbalancer['id']
        self.addCleanup(
            self.load_balancers_admin_client.delete_load_balancer,
            lb_id)
        self.load_balancers_admin_client.wait_for_load_balancer_status(lb_id)
        listener_name = data_utils.rand_name("tempest_lb")
        self.assertRaises(
            exceptions.ServerFault,
            self.listeners_admin_client.create_listener,
            loadbalancer_id=lb_id,
            protocol=protocol_type,
            protocol_port=protocol_port,
            name=listener_name,
            default_tls_container_ref=barbican_container["container_ref"])

    @decorators.idempotent_id('2228016a-93cc-5099-b217-12344caa56f4')
    def test_barbican_check_certificate_at_edge(self):
        barbican_secrets = self.create_barbican_secret_conatainer(
            constants.CERT_FILE, constants.KEY_FILE)
        barbican_container = barbican_secrets['secret_container']
        topology_dict = self.create_topo_single_network(
            "test_secret", create_instance=False)
        network_state = topology_dict['network_state']
        subnet_state = topology_dict['subnet_state']
        sec_rule_client = self.sec_rule_client
        sec_client = self.sec_client
        kwargs = dict(tenant_id=network_state['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        lbaas_rules = [dict(direction='ingress', protocol='tcp',
                            port_range_min=constants.HTTP_PORT,
                            port_range_max=constants.HTTP_PORT, ),
                       dict(direction='ingress', protocol='tcp',
                            port_range_min=443, port_range_max=443, )]
        for rule in lbaas_rules:
            self.add_security_group_rule(
                self.sg,
                rule,
                ruleclient=sec_rule_client,
                secclient=sec_client,
                tenant_id=network_state['tenant_id'])
        no_of_servers = 2
        image_id = self.get_glance_image_id(["cirros", "esx"])
        for instance in range(0, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_state],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id, clients=self.cmgr_adm)
        self.poke_counters = 12
        self.hm_delay = 4
        self.hm_max_retries = 3
        self.hm_timeout = 10
        self.server_names = []
        self.loadbalancer = None
        self.vip_fip = None
        self.web_service_start_delay = 2.5
        self.start_web_servers(constants.HTTP_PORT)
        self.create_barbican_project_lbaas(
            protocol_type="TERMINATED_HTTPS",
            protocol_port="443",
            lb_algorithm="ROUND_ROBIN",
            hm_type='HTTP',
            member_count=2,
            weight=5,
            pool_protocol='HTTP',
            pool_port='80',
            vip_subnet_id=subnet_state['id'],
            barbican_container=barbican_container,
            count=0)
        self.check_certificate_at_edge()

    @decorators.idempotent_id('2226018n-93cc-5099-b217-12344caa87b0')
    def test_barbican_remove_listener_check_certificate_at_backend(self):
        barbican_secrets = self.create_barbican_secret_conatainer(
            constants.CERT_FILE, constants.KEY_FILE)
        barbican_container = barbican_secrets['secret_container']
        topology_dict = self.create_topo_single_network(
            "test_secret", create_instance=False)
        network_state = topology_dict['network_state']
        subnet_state = topology_dict['subnet_state']
        sec_rule_client = self.sec_rule_client
        sec_client = self.sec_client
        kwargs = dict(tenant_id=network_state['tenant_id'],
                      security_group_rules_client=sec_rule_client,
                      security_groups_client=sec_client)
        self.sg = self.create_topology_security_group(**kwargs)
        lbaas_rules = [dict(direction='ingress', protocol='tcp',
                            port_range_min=constants.HTTP_PORT,
                            port_range_max=constants.HTTP_PORT, ),
                       dict(direction='ingress', protocol='tcp',
                            port_range_min=443, port_range_max=443, )]
        for rule in lbaas_rules:
            self.add_security_group_rule(
                self.sg,
                rule,
                ruleclient=sec_rule_client,
                secclient=sec_client,
                tenant_id=network_state['tenant_id'])
        no_of_servers = 2
        image_id = self.get_glance_image_id(["cirros", "esx"])
        for instance in range(0, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_state],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id, clients=self.cmgr_adm)
        self.start_web_servers(constants.HTTP_PORT)
        self.poke_counters = 12
        self.hm_delay = 4
        self.hm_max_retries = 3
        self.hm_timeout = 10
        self.server_names = []
        self.loadbalancer = None
        self.vip_fip = None
        self.web_service_start_delay = 2.5
        topo_dict = self.create_barbican_project_lbaas(
            protocol_type="TERMINATED_HTTPS",
            protocol_port="443",
            lb_algorithm="ROUND_ROBIN",
            hm_type='HTTP',
            member_count=2,
            weight=5,
            pool_protocol='HTTP',
            pool_port='80',
            vip_subnet_id=subnet_state['id'],
            barbican_container=barbican_container,
            count=0,
            clean_up=False)
        self.check_certificate_at_edge()
        no_of_servers = 4
        self.topology_servers = {}
        for instance in range(2, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_state],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id, clients=self.cmgr_adm)
        self.start_web_servers(constants.HTTP_PORT)
        topo_dict_1 = self.create_barbican_project_lbaas(
            protocol_type="TERMINATED_HTTPS",
            protocol_port="444",
            lb_algorithm="ROUND_ROBIN",
            hm_type='HTTP',
            member_count=4,
            weight=5,
            pool_protocol='HTTP',
            pool_port='80',
            vip_subnet_id=subnet_state['id'],
            barbican_container=barbican_container,
            lb_id=topo_dict['lb_id'],
            count=2,
            clean_up=False)
        self.check_certificate_at_edge()
        for member in topo_dict_1['members']:
            self.members_admin_client.delete_member(
                topo_dict_1['pool_id'], member['id'])
            self.load_balancers_admin_client.wait_for_load_balancer_status(
                topo_dict['lb_id'])
        self.health_monitors_admin_client.delete_health_monitor(
            topo_dict_1['healthmonitor_id'])
        self.load_balancers_admin_client.wait_for_load_balancer_status(
            topo_dict['lb_id'])
        self.pools_admin_client.delete_pool(topo_dict_1['pool_id'])
        self.load_balancers_admin_client.wait_for_load_balancer_status(
            topo_dict['lb_id'])
        self.listeners_admin_client.delete_listener(topo_dict_1['listener_id'])
        self.load_balancers_admin_client.wait_for_load_balancer_status(
            topo_dict['lb_id'])
        self.check_certificate_at_edge()
        for member in topo_dict['members']:
            self.members_admin_client.delete_member(
                topo_dict['pool_id'], member['id'])
            self.load_balancers_admin_client.wait_for_load_balancer_status(
                topo_dict['lb_id'])
        self.health_monitors_admin_client.delete_health_monitor(
            topo_dict['healthmonitor_id'])
        self.load_balancers_admin_client.wait_for_load_balancer_status(
            topo_dict['lb_id'])
        self.pools_admin_client.delete_pool(topo_dict['pool_id'])
        self.load_balancers_admin_client.wait_for_load_balancer_status(
            topo_dict['lb_id'])
        self.listeners_admin_client.delete_listener(topo_dict['listener_id'])
        self.load_balancers_admin_client.wait_for_load_balancer_status(
            topo_dict['lb_id'])
        self.check_certificate_at_edge(should_present=False)

    @decorators.idempotent_id('2226818a-93cc-5099-b217-12344caa98n8')
    def test_barbican_multiple_secret_and_container(self):
        for i in range(1, 51):
            self.create_barbican_secret_conatainer(
                constants.CERT_FILE, constants.KEY_FILE)

    @decorators.idempotent_id('2226016a-99cc-5099-b217-12344caa92d9')
    def test_barbican_secret_update(self):
        cert_file = open(constants.CERT_FILE, "r")
        cert_content = cert_file.read()
        secret_name1 = data_utils.rand_name(name='tempest-cert-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "name": secret_name1}
        barbican_secret1 = self.create_barbican_secret(**kwargs)
        uuid = self._get_uuid(barbican_secret1['secret_ref'])
        self.secret_client.put_secret_payload(uuid, cert_content)

    @decorators.idempotent_id('2226026a-93cc-5099-b217-12344caa44d4')
    def test_barbican_secret_create_with_octet_stream(self):
        cert_file = open(constants.CERT_FILE, "r")
        cert_content = cert_file.read()
        secret_name1 = data_utils.rand_name(name='tempest-cert-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "algorithm": "binary",
                  "payload_content_type": "application/octet-stream",
                  "mode": constants.MODE,
                  "bit_length": constants.BIT_LENGTH,
                  "payload": cert_content,
                  "name": secret_name1}
        self.create_barbican_secret(**kwargs)

    @decorators.idempotent_id('2228016s-93cc-5099-b217-12344caa88b8')
    def test_barbican_delete_secret_container_with_invalid_uuid(self):
        secert_id = uuidutils.generate_uuid()
        self.assertRaises(exceptions.NotFound,
                          self.secret_client.delete_secret,
                          secert_id)
        container_id = uuidutils.generate_uuid()
        self.assertRaises(exceptions.NotFound,
                          self.container_client.delete_container,
                          container_id)

    @decorators.idempotent_id('2226016a-93cc-5099-b217-12344ccc79a1')
    def test_barbican_create_lbaas_listener_with_invalid_container_uuid(self):
        barbican_secrets = self.create_barbican_secret_conatainer(
            constants.CERT_FILE, constants.KEY_FILE)
        container_ref = barbican_secrets["secret_container"]['container_ref']\
            .split('/')
        container_ref.remove(container_ref[len(container_ref) - 1])
        container_ref.append(uuidutils.generate_uuid())
        container_ref = '/'.join(str(e) for e in container_ref)
        topology_dict = self.create_topo_single_network(
            "test_secret", create_instance=False)
        subnet_state = topology_dict['subnet_state']
        lb_name = data_utils.rand_name("tempest_lb")
        self.loadbalancer = self.load_balancers_admin_client.\
            create_load_balancer(name=lb_name,
                                 vip_subnet_id=subnet_state
                                 ['id'])['loadbalancer']
        lb_id = self.loadbalancer['id']
        self.addCleanup(
            self.load_balancers_admin_client.delete_load_balancer,
            self.loadbalancer['id'])
        self.load_balancers_admin_client.wait_for_load_balancer_status(
            lb_id)
        listener_name = data_utils.rand_name("tempest_lb")
        self.assertRaises(exceptions.NotFound,
                          self.listeners_admin_client.create_listener,
                          loadbalancer_id=lb_id, protocol="TERMINATED_HTTPS",
                          protocol_port="443", name=listener_name,
                          default_tls_container_ref=container_ref)

    @decorators.idempotent_id('2226016a-93cc-5099-b217-12344dff58a1')
    def test_barbican_secret_create_with_wrong_bit_length(self):
        cert_file = open(constants.CERT_FILE, "r")
        cert_content = cert_file.read()
        secret_name1 = data_utils.rand_name(name='tempest-cert-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "algorithm": constants.ALGORITHM,
                  "payload_content_type": constants.PAYLOAD_CONTENT_TYPE,
                  "mode": constants.MODE,
                  "bit_length": 6382372,
                  "payload": cert_content,
                  "name": secret_name1}
        self.assertRaises(exceptions.BadRequest,
                          self.create_barbican_secret, **kwargs
                          )

    @decorators.idempotent_id('2228126a-97cc-5099-b217-12344caa24a1')
    def test_barbican_listener_with_wrong_payload(self):
        cert_content = self._create_self_signed_certificate(1024)
        secret_name1 = data_utils.rand_name(name='tempest-cert-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "algorithm": constants.ALGORITHM,
                  "payload_content_type": constants.PAYLOAD_CONTENT_TYPE,
                  "mode": constants.MODE,
                  "bit_length": constants.BIT_LENGTH,
                  "payload": cert_content,
                  "name": secret_name1}
        barbican_secret1 = self.create_barbican_secret(**kwargs)
        secret_name2 = data_utils.rand_name(name='tempest-key-secret')
        kwargs = {"secret_type": constants.SECRET_TYPE,
                  "algorithm": constants.ALGORITHM,
                  "payload_content_type": constants.PAYLOAD_CONTENT_TYPE,
                  "mode": constants.MODE,
                  "bit_length": constants.BIT_LENGTH,
                  "payload": cert_content,
                  "name": secret_name2}
        barbican_secret2 = self.create_barbican_secret(**kwargs)
        container_name = data_utils.rand_name(name='tempest-container')
        kwargs = {"type": constants.CONTAINER_TYPE,
                  "name": container_name,
                  "secret_refs": [{"secret_ref": barbican_secret1
                                   ['secret_ref'],
                                   "name": 'certificate'},
                                  {"secret_ref": barbican_secret2
                                   ['secret_ref'],
                                   "name": 'private_key'}]}
        barbican_container = self.create_barbican_container(**kwargs)
        topology_dict = self.create_topo_single_network(
            "test_secret", create_instance=False)
        subnet_state = topology_dict['subnet_state']
        self.namestart = 'lbaas-ops'
        self.server_names = []
        self.loadbalancer = None
        protocol_type = "TERMINATED_HTTPS"
        protocol_port = 443
        vip_subnet_id = subnet_state['id']
        lb_name = data_utils.rand_name("tempest_lb")
        self.loadbalancer = self.load_balancers_admin_client.\
            create_load_balancer(name=lb_name,
                                 vip_subnet_id=vip_subnet_id)['loadbalancer']
        lb_id = self.loadbalancer['id']
        self.addCleanup(
            self.load_balancers_admin_client.delete_load_balancer,
            lb_id)
        self.load_balancers_admin_client.wait_for_load_balancer_status(lb_id)
        listener_name = data_utils.rand_name("tempest_lb")
        self.assertRaises(
            exceptions.ServerFault,
            self.listeners_admin_client.create_listener,
            loadbalancer_id=lb_id,
            protocol=protocol_type,
            protocol_port=protocol_port,
            name=listener_name,
            default_tls_container_ref=barbican_container["container_ref"])

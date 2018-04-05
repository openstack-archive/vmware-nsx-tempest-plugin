# Copyright 2018 VMware Inc
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

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsxv_client

from tempest.common import waiters
from tempest import config
from tempest.lib import decorators
from tempest import test


LOG = constants.log.getLogger(__name__)
CONF = config.CONF


class LBaasWithStaticRouteOnDhcpServerTest(feature_manager.FeatureManager):

    """Base class to support dhcp static routes on dhcp server when lbaas is
       configured using that server.

    """
    @classmethod
    def skip_checks(cls):
        super(LBaasWithStaticRouteOnDhcpServerTest, cls).skip_checks()
        cfg = CONF.network
        if not test.is_extension_enabled('lbaasv2', 'network'):
            msg = 'lbaasv2 extension is not enabled.'
            raise cls.skipException(msg)
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)
        cls.nsxv_version = cls.vsm.get_vsm_version()
        if not (cfg.project_networks_reachable or cfg.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(LBaasWithStaticRouteOnDhcpServerTest, cls).resource_setup()

    @classmethod
    def setup_credentials(cls):
        # Ask framework to not create network resources for these tests.
        cls.set_network_resources()
        super(LBaasWithStaticRouteOnDhcpServerTest, cls).setup_credentials()

    def setUp(self):
        super(LBaasWithStaticRouteOnDhcpServerTest, self).setUp()
        CONF.validation.ssh_shell_prologue = ''
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

    def tearDown(self):
        if self.vip_fip:
            LOG.debug("tearDown lbass vip fip")
            self.disassociate_floatingip(self.vip_fip, and_delete=True)
        if self.loadbalancer:
            LOG.debug("tearDown lbass")
            lb_id = self.loadbalancer['id']
            self.delete_loadbalancer_resources(lb_id)

        # make sure servers terminated before teardown network resources
        LOG.debug("tearDown lbaas servers")
        server_id_list = []
        for server_name in self.topology_servers.keys():
            fip = self.servers_details[server_name].floating_ips[0]
            self._disassociate_floating_ip(fip)
            server_id = self.servers_details[server_name].server['id']
            self.manager.servers_client.delete_server(server_id)
            server_id_list.append(server_id)
        for server_id in server_id_list:
            waiters.wait_for_server_termination(
                self.manager.servers_client, server_id)
        # delete lbaas network before handing back to framework
        super(LBaasWithStaticRouteOnDhcpServerTest, self).tearDown()
        LOG.debug("tearDown lbaas exiting...")

    def deploy_lbaas_topology(self, no_of_servers=2, image_id=None):
        router_lbaas = self.create_topology_router("router_lbaas")
        network_lbaas_1 = self.create_topology_network("network_lbaas_1")
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
        self.create_topology_subnet(
            "subnet_lbaas_1", network_lbaas_1, router_id=router_lbaas["id"])
        for instance in range(0, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_lbaas_1],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id)

    def check_static_binding_using_dhcp_121_route(self):
        subnet_id = self.topology_subnets['subnet_lbaas_1']['id']
        self.nexthop1 = self.topology_subnets['subnet_lbaas_1']['gateway_ip']
        # Update subnet with host routes
        public_net_cidr = CONF.network.public_network_cidr
        _subnet_data = \
            {'host_routes':
             [{'destination': '10.20.0.0/32',
               'nexthop': self.topology_subnets['subnet_lbaas_1']
                                               ['allocation_pools'][0]
                                               ['end']}],
             'new_host_routes': [{'destination': public_net_cidr,
                                  'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        # Update subnet with host-route info
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Connect to instance launched using ssh lib
        server = self.topology_servers["server_lbaas_0"]
        fip_data = server.get('floating_ips')[0]
        fip = fip_data['floating_ip_address']
        client = self.verify_server_ssh(
            server=server, floating_ip=fip)
        # Executes route over instance launched
        fixed_ip = fip_data['fixed_ip_address']
        # Renew lease on openstack instance
        client._renew_lease_udhcpc(fixed_ip)
        # Check routes on openstack instance
        cmd = ('/sbin/route -n')
        out_data = client.exec_command(cmd)
        self.assertIn(
            _subnet_data['new_host_routes'][0]['nexthop'], out_data)
        self.assertIn(
            _subnet_data['new_host_routes'][0]['destination'].split('/')[0],
            out_data)
        exc_edge = self.vsm.get_dhcp_edge_info(version=self.nsxv_version)
        self.assertIsNotNone(exc_edge)
        # Fetch host-route info from nsx-v
        dhcp_options_info = {}
        dhcp_options_info = exc_edge['staticBindings']['staticBindings'][0][
            'dhcpOptions']['option121']['staticRoutes']
        for destination_net in dhcp_options_info:
            dest = _subnet_data['new_host_routes'][0]['destination']
            dest_subnet = destination_net['destinationSubnet']
            dest_router = destination_net['router']
            if (dest in dest_subnet and self.nexthop1 in dest_router):
                self.assertIn(
                    dest,
                    dest_subnet,
                    "Host routes available on nsxv")
                self.assertIn(
                    self.nexthop1,
                    dest_router,
                    "Host routes available on nsxv")
        # Check lbaas traffic after routes beinga added
        self.check_project_lbaas()
        # Update subnet with static routes second time
        _subnet_data1 = \
            {'new_host_routes':
             [{'destination': '10.20.0.0/32',
               'nexthop': self.topology_subnets['subnet_lbaas_1']
                                               ['allocation_pools'][0]
                                               ['end']}]}
        new_host_routes = _subnet_data1['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "new_subnet_change_2"
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Renew lease on openstack instance
        client._renew_lease_udhcpc(fixed_ip)
        # Check routes on openstack instance
        cmd = ('/sbin/route -n')
        out_data = client.exec_command(cmd)
        self.assertIn(
            _subnet_data1['new_host_routes'][0]['nexthop'], out_data)
        # Update subnet with no host-routes
        _subnet_data1 = {'new_host_routes': []}
        new_host_routes = _subnet_data1['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "new_subnet_change_3"
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Renew lease on openstack instance
        client._renew_lease_udhcpc(fixed_ip)
        # Check routes on openstack instance
        cmd = ('/sbin/route -n')
        out_data = client.exec_command(cmd)
        self.assertIsNotNone(out_data)
        # Check Host routes on VM shouldn't be avialable
        self.assertNotIn(
            _subnet_data['new_host_routes'][0]['destination'], out_data)
        # Check Host-routes at beckend after deletion
        exc_edge = self.vsm.get_dhcp_edge_info(version=self.nsxv_version)
        self.assertIsNotNone(exc_edge)
        dhcp_options_info = []
        dhcp_options_info = exc_edge['staticBindings']['staticBindings'][0][
            'dhcpOptions']['option121']['staticRoutes']
        # Check Host Route information avaialable at beckend
        for destination_net in dhcp_options_info:
            if (_subnet_data['new_host_routes'][0]['destination']
                    not in destination_net['destinationSubnet']):
                self.assertNotIn(
                    _subnet_data['new_host_routes'][0]['destination'],
                    destination_net['destinationSubnet'],
                    "Host routes not available on nsxv")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('91b709bf-007f-2261-b43f-6315c2b6c433')
    def test_lbaas_http_traffic_roundrobin_with_http_health_type(self):
        self.deploy_lbaas_topology()
        self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='HTTP',
                                  fip_disassociate=1)
        self.check_project_lbaas()
        self.check_static_binding_using_dhcp_121_route()
        self.check_project_lbaas()

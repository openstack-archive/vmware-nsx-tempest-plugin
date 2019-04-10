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

import time

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager

from tempest.common import waiters
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test


LOG = constants.log.getLogger(__name__)
CONF = config.CONF


class LBaasRoundRobinBaseTest(feature_manager.FeatureManager):

    """Base class to support LBaaS ROUND-ROBIN test.

    It provides the methods to create loadbalancer network, and
    start web servers.

    Default lb_algorithm is ROUND_ROBIND.
    """
    @classmethod
    def skip_checks(cls):
        super(LBaasRoundRobinBaseTest, cls).skip_checks()
        cfg = CONF.network
        if not test.is_extension_enabled('lbaasv2', 'network'):
            msg = 'lbaasv2 extension is not enabled.'
            raise cls.skipException(msg)
        if not (cfg.project_networks_reachable or cfg.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(LBaasRoundRobinBaseTest, cls).resource_setup()

    @classmethod
    def setup_credentials(cls):
        # Ask framework to not create network resources for these tests.
        cls.set_network_resources()
        super(LBaasRoundRobinBaseTest, cls).setup_credentials()

    def setUp(self):
        super(LBaasRoundRobinBaseTest, self).setUp()
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
        super(LBaasRoundRobinBaseTest, self).tearDown()
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
        subnet_lbaas = self.create_topology_subnet(
            "subnet_lbaas_1", network_lbaas_1, router_id=router_lbaas["id"])
        for instance in range(0, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_lbaas_1],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id)
        return dict(router=router_lbaas, subnet=subnet_lbaas,
                    network=network_lbaas_1)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c5ac853b-6867-4b7a-8704-3844b11b1a34')
    def test_lbaas_http_traffic_roundrobin_with_ping_health_type(self):
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='PING')
        self.check_project_lbaas()

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('87b709bf-127f-4161-b43f-3915c216c44b')
    def test_lbaas_http_traffic_roundrobin_with_http_health_type(self):
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='HTTP')
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('60e9facf-b8d6-48a9-b0d2-942e5bb38f38')
    def test_lbaas_http_leastconnections_with_ping_health_type(self):
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='PING')
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('3041a103-e03d-4660-b411-2f9d5987dba8')
    def test_lbaas_http_leastconnections_with_http_health_type(self):
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='HTTP')
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('73190a30-3879-4828-a198-4d3fff4cea3a')
    def test_lbaas_http_leastconnection_with_weighted_value(self):
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='HTTP', weight=1)
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('a18347f8-9de0-49b0-8935-5fd26c135afb')
    def test_lbaas_http_leastconnection_updated_weighted_value(self):
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='HTTP')
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)
        self.update_members_weight(1)
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('5041a903-e03d-4660-e421-2f9d5987dba9')
    def test_lbaas_http_leastconnection_updated_algorithm(self):
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='HTTP')
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)
        self.update_pool_algorithm("ROUND_ROBIN")
        self.check_project_lbaas()

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('cb9f483b-a7b3-41fc-9a5f-86a8738f853b')
    def test_lbaas_http_roundrobin_with_weighted_value(self):
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN",
                                  hm_type='HTTP', weight=1)
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('de8577b6-8aee-40cc-b856-e25f83c26bdd')
    def test_lbaas_http_traffic_roundrobin_with_ping_type_on_new_members(self):
        self.deploy_lbaas_topology(constants.NO_OF_VMS_4)
        self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='PING',
                                  member_count=2)
        self.check_project_lbaas()
        self.create_addtional_lbaas_members(constants.HTTP_PORT)
        time.sleep(constants.SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS)
        self.check_project_lbaas(constants.NO_OF_VMS_4)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('86315138-3d95-4694-97ad-04a94a896201')
    def test_lbaas_http_leastconnections_with_ping_type_on_new_members(self):
        self.deploy_lbaas_topology(constants.NO_OF_VMS_4)
        self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='PING', member_count=2)
        self.check_project_lbaas()
        self.create_addtional_lbaas_members(constants.HTTP_PORT)
        time.sleep(constants.SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS)
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_4)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('28e9d22d-4da2-460e-9c5b-bd8ddc1d35b6')
    def test_lbaas_http_traffic_roundrobin_with_http_type_on_new_members(self):
        self.deploy_lbaas_topology(constants.NO_OF_VMS_4)
        self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='PING',
                                  member_count=2)
        self.check_project_lbaas()
        self.create_addtional_lbaas_members(constants.HTTP_PORT)
        time.sleep(constants.SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS)
        self.check_project_lbaas(constants.NO_OF_VMS_4)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('1839d22d-4da2-460e-9c5b-bd8ddc1d35b6')
    def test_user_not_able_to_update_lb_port(self):
        """
        Admin user shouldn't be able to update Lb internal ports
        """
        self.deploy_lbaas_topology()
        lb = self.create_project_lbaas(
            protocol_type="HTTP", protocol_port="80",
            lb_algorithm="ROUND_ROBIN", hm_type='PING')
        kwargs = {"admin_state_up": True}
        self.assertRaises(exceptions.BadRequest,
                          self.manager.ports_client.update_port(lb['vip_port'],
                                                                **kwargs))

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('98e1d22d-4da2-460e-9c5b-bd8ddc1d35b6')
    def test_delete_router_attaching_to_lb(self):
        """
        Delete tier-1 router when Lb is attached to it
        """
        lb_topo = self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        lb = self.create_project_lbaas(
            protocol_type="HTTP", protocol_port="80",
            lb_algorithm="ROUND_ROBIN", hm_type='PING')
        self.delete_lb_pool_healthmonitor(lb['pool'])
        self.assertRaises(exceptions.BadRequest, self.remove_router_interface,
                          lb_topo.get('router')['id'],
                          lb_topo.get('subnet')['id'])

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('60e9ecaf-b8d6-48a9-b0d2-942e5bb38f38')
    def test_lbaas_http_round_robin_with_session_persistence(self):
        """
        To verify the server count for LB pool with SOURCE_IP
        session persistence and ROUND_ROBIN lb-algorithm
        expected outcome is only one server responds to the
        client requests
        """
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN",
                                  hm_type='PING', persistence=True,
                                  persistence_type="SOURCE_IP")
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2,
                                               hash_persistence=True)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('60e9adda-b8d6-48a9-b0d2-942e5bb38f38')
    def test_lbaas_http_update_app_cookie_http_cookie_persistence(self):
        """
        To verify the updation of session persistence from APP_COOKIE to
        HTTP_COOKIE works fine.
        """
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN",
                                  hm_type='PING', persistence=True,
                                  persistence_type="APP_COOKIE",
                                  persistence_cookie_name="application_cookie")
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)
        pool_id = self.pools_client.list_pools()['pools'][-1]['id']
        session_persistence = {}
        session_persistence['type'] = "HTTP_COOKIE"
        self.pools_client.update_pool(pool_id=pool_id,
                                      session_persistence=session_persistence)
        get_pool = self.pools_client.list_pools()
        updated_pool = get_pool['pools'][0]['session_persistence']['type']
        self.assertEqual("HTTP_COOKIE", updated_pool)
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('60e30dda-b8d6-48a9-b0d2-942e5bb38f38')
    def test_lbaas_http_round_robin_get_statistics(self):
        """
        To verify statistics are updated on the Loadbalancer
        for every new traffic that hits on the lb.
        """
        self.deploy_lbaas_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN",
                                  hm_type='PING')
        get_lb = self.load_balancers_client.list_load_balancers()
        lb_id = get_lb['loadbalancers'][0]['id']
        stat = self.load_balancers_client.show_load_balancer_stats(lb_id)
        assert (stat['stats']['bytes_in'] == 0 and
                stat['stats']['bytes_out'] == 0)
        self.check_lbaas_project_weight_values(constants.NO_OF_VMS_2)
        stat = self.load_balancers_client.show_load_balancer_stats(lb_id)
        assert (stat['stats']['bytes_in'] >= 0 and
                stat['stats']['bytes_out'] >= 0)

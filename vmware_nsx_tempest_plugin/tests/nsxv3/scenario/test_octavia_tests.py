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

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest import test

LOG = constants.log.getLogger(__name__)
CONF = config.CONF


class OctaviaRoundRobin(feature_manager.FeatureManager):

    """Base class to support LBaaS ROUND-ROBIN test.

    It provides the methods to create loadbalancer network, and
    start web servers.

    Default lb_algorithm is ROUND_ROBIND.
    """
    @classmethod
    def setup_clients(cls):
        super(OctaviaRoundRobin, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def skip_checks(cls):
        super(OctaviaRoundRobin, cls).skip_checks()
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
        super(OctaviaRoundRobin, cls).resource_setup()

    @classmethod
    def setup_credentials(cls):
        # Ask framework to not create network resources for these tests.
        cls.set_network_resources()
        super(OctaviaRoundRobin, cls).setup_credentials()

    def setUp(self):
        super(OctaviaRoundRobin, self).setUp()
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
            self.delete_octavia_lb_resources(lb_id)

        LOG.debug("tearDown lbaas exiting...")
        super(OctaviaRoundRobin, self).tearDown()

    def deploy_octavia_topology(self, no_of_servers=2, image_id=None):
        kwargs = {'name': "router_lbaas",
                  'external_gateway_info':
                  {"network_id": CONF.network.public_network_id}}
        router_lbaas = self.cmgr_adm.routers_client.create_router(**kwargs)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.routers_client.delete_router,
                        router_lbaas['router']['id'])
        networks_client = self.cmgr_adm.networks_client
        name = "network_lbaas_1"
        network_lbaas_1 = self.\
            create_topology_network(name,
                                    networks_client=networks_client)
        sec_rule_client = self.cmgr_adm.security_group_rules_client
        sec_client = self.cmgr_adm.security_groups_client
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
            tenant_id = network_lbaas_1['tenant_id']
            self.add_security_group_rule(self.sg, rule,
                                         secclient=sec_client,
                                         ruleclient=sec_rule_client,
                                         tenant_id=tenant_id)
        body = {"network_id": network_lbaas_1['id'],
                "allocation_pools": [{"start": "2.0.0.2", "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_lbaas = subnet_client.create_subnet(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnet_client.delete_subnet,
                        subnet_lbaas['subnet']['id'])
        self.cmgr_adm.routers_client.\
            add_router_interface(router_lbaas['router']['id'],
                                 subnet_id=subnet_lbaas['subnet']['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.cmgr_adm.routers_client.remove_router_interface,
                        router_lbaas['router']['id'],
                        subnet_id=subnet_lbaas['subnet']['id'])
        for instance in range(0, no_of_servers):
            self.create_topology_instance(
                "server_lbaas_%s" % instance, [network_lbaas_1],
                security_groups=[{'name': self.sg['name']}],
                image_id=image_id, clients=self.cmgr_adm)
        return dict(router=router_lbaas, subnet=subnet_lbaas,
                    network=network_lbaas_1)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c5ac8546-6867-4b7a-8704-3844b11b1a34')
    def test_create_verify_octavia_lb_with_vip_subnet_id(self):
        """
        This testcase creates an octavia Loadbalancer with vip-subnet-ip
        option, and verifies the traffic on the loadbalancer vip
        """
        diction = self.deploy_octavia_topology()
        if not CONF.nsxv3.ens:
            self.start_web_servers(constants.HTTP_PORT)
        subnet_id = diction['subnet']['subnet']['id']
        self.create_project_octavia(protocol_type="HTTP", protocol_port="80",
                                    lb_algorithm="ROUND_ROBIN",
                                    vip_subnet_id=subnet_id)
        self.check_project_lbaas()

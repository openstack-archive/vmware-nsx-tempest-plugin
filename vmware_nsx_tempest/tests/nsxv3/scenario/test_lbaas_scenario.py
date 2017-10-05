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
import shlex
import subprocess
import tempfile
import time
import urllib3

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services.lbaas import health_monitors_client
from vmware_nsx_tempest.services.lbaas import listeners_client
from vmware_nsx_tempest.services.lbaas import load_balancers_client
from vmware_nsx_tempest.services.lbaas import members_client
from vmware_nsx_tempest.services.lbaas import pools_client

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
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
        cls.create_lbaas_clients(cls.manager)

    @classmethod
    def create_lbaas_clients(cls, mgr):
        cls.load_balancers_client = load_balancers_client.get_client(mgr)
        cls.listeners_client = listeners_client.get_client(mgr)
        cls.pools_client = pools_client.get_client(mgr)
        cls.members_client = members_client.get_client(mgr)
        cls.health_monitors_client = health_monitors_client.get_client(mgr)

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

    def delete_loadbalancer_resources(self, lb_id):
        lb_client = self.load_balancers_client
        statuses = lb_client.show_load_balancer_status_tree(lb_id)
        statuses = statuses.get('statuses', statuses)
        lb = statuses.get('loadbalancer')
        for listener in lb.get('listeners', []):
            for policy in listener.get('l7policies'):
                test_utils.call_and_ignore_notfound_exc(
                    self.l7policies_client.delete_policy,
                    policy.get('id'))
            for pool in listener.get('pools'):
                self.delete_lb_pool_resources(lb_id, pool)
            test_utils.call_and_ignore_notfound_exc(
                self.listeners_client.delete_listener,
                listener.get('id'))
            self.wait_for_load_balancer_status(lb_id)
        # delete pools not attached to listener, but loadbalancer
        for pool in lb.get('pools', []):
            self.delete_lb_pool_resources(lb_id, pool)
        test_utils.call_and_ignore_notfound_exc(
            lb_client.delete_load_balancer, lb_id)
        self.load_balancers_client.wait_for_load_balancer_status(
            lb_id, is_delete_op=True)
        lbs = lb_client.list_load_balancers()['loadbalancers']
        self.assertEqual(0, len(lbs))

    def delete_lb_pool_resources(self, lb_id, pool):
        pool_id = pool.get('id')
        hm = pool.get('healthmonitor')
        if hm:
            test_utils.call_and_ignore_notfound_exc(
                self.health_monitors_client.delete_health_monitor,
                pool.get('healthmonitor').get('id'))
            self.wait_for_load_balancer_status(lb_id)
        test_utils.call_and_ignore_notfound_exc(
            self.pools_client.delete_pool, pool.get('id'))
        self.wait_for_load_balancer_status(lb_id)
        for member in pool.get('members', []):
            test_utils.call_and_ignore_notfound_exc(
                self.members_client.delete_member,
                pool_id, member.get('id'))
            self.wait_for_load_balancer_status(lb_id)

    def wait_for_load_balancer_status(self, lb_id):
        # Wait for load balancer become ONLINE and ACTIVE
        self.load_balancers_client.wait_for_load_balancer_status(lb_id)

    def copy_file_to_host(self, file_from, dest, host, username, pkey):
        dest = "%s@%s:%s" % (username, host, dest)
        cmd = "scp -v -o UserKnownHostsFile=/dev/null " \
              "-o StrictHostKeyChecking=no " \
              "-i %(pkey)s %(file1)s %(dest)s" % {'pkey': pkey,
                                                  'file1': file_from,
                                                  'dest': dest}
        args = shlex.split(cmd.encode('utf-8'))
        subprocess_args = {'stdout': subprocess.PIPE,
                           'stderr': subprocess.STDOUT}
        proc = subprocess.Popen(args, **subprocess_args)
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raise exceptions.SSHExecCommandFailed(cmd,
                                                  proc.returncode,
                                                  stdout,
                                                  stderr)
        return stdout

    def start_web_server(self, protocol_port):
        """start server's web service which return its server_name."""
        for server_name in self.topology_servers.keys():
            server = self.servers_details[server_name].server
            fip_data = self.servers_details[server_name].floating_ips[0]
            fip = fip_data['floating_ip_address']
            ssh_client = self.verify_server_ssh(
                server=server, floating_ip=fip)
            private_key = self.get_server_key(server)
            resp = ('echo -ne "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n'
                    'Connection: close\r\nContent-Type: text/html; '
                    'charset=UTF-8\r\n\r\n%s"; cat >/dev/null')
            with tempfile.NamedTemporaryFile() as script:
                script.write(resp % (len(server_name), server_name))
                script.flush()
                with tempfile.NamedTemporaryFile() as key:
                    key.write(private_key)
                    key.flush()
                    self.copy_file_to_host(script.name,
                                           "/tmp/script",
                                           fip, "cirros", key.name)

        # Start netcat
            start_server = ('while true; do '
                            'sudo nc -ll -p %(port)s -e sh /tmp/%(script)s; '
                            'done > /dev/null &')
            cmd = start_server % {'port': constants.HTTP_PORT,
                                  'script': 'script'}
            ssh_client.exec_command(cmd)

    def send_request(self, web_ip):
        try:
            url_path = "http://{0}/".format(web_ip)
            # lbaas servers use nc, might be slower to response
            http = urllib3.PoolManager(retries=10)
            resp = http.request('GET', url_path)
            return resp.data.strip()
        except Exception:
            return None

    def deploy_lbaas_topology_1(self, no_of_servers=2):
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
                security_groups=[{'name': self.sg['name']}])

    def create_project_lbaas(self, protocol_type, protocol_port, lb_algorithm,
                             hm_type, member_count=2):
        count = 0
        vip_subnet_id = self.topology_subnets["subnet_lbaas_1"]['id']
        lb_name = data_utils.rand_name(self.namestart)
        self.loadbalancer = self.load_balancers_client.create_load_balancer(
            name=lb_name, vip_subnet_id=vip_subnet_id)['loadbalancer']
        lb_id = self.loadbalancer['id']
        self.wait_for_load_balancer_status(lb_id)

        self.listener = self.listeners_client.create_listener(
            loadbalancer_id=lb_id, protocol=protocol_type,
            protocol_port=protocol_port, name=lb_name)['listener']
        self.wait_for_load_balancer_status(lb_id)

        self.pool = self.pools_client.create_pool(
            listener_id=self.listener['id'],
            lb_algorithm=lb_algorithm, protocol=protocol_type,
            name=lb_name)['pool']
        self.wait_for_load_balancer_status(lb_id)
        pool_id = self.pool['id']

        self.healthmonitor = (
            self.health_monitors_client.create_health_monitor(
                pool_id=pool_id, type=hm_type,
                delay=self.hm_delay, max_retries=self.hm_max_retries,
                timeout=self.hm_timeout))
        self.wait_for_load_balancer_status(lb_id)

        self.members = []
        for server_name in self.topology_servers.keys():
            if count < len(self.topology_servers.keys()) / 2:
                fip_data = self.servers_details[server_name].floating_ips[0]
                fixed_ip_address = fip_data['fixed_ip_address']
                self._disassociate_floating_ip(fip_data)
                member = self.members_client.create_member(
                    pool_id, subnet_id=vip_subnet_id,
                    address=fixed_ip_address,
                    protocol_port=protocol_port)
                self.wait_for_load_balancer_status(lb_id)
                self.members.append(member)
                self.server_names.append(server_name)
                count += 1
            else:
                break

        self.ports_client.update_port(
            self.loadbalancer['vip_port_id'],
            security_groups=[self.sg['id']])
        # create lbaas public interface
        vip_fip = \
            self.create_floatingip(self.loadbalancer,
                                   port_id=self.loadbalancer['vip_port_id'])
        self.vip_ip_address = vip_fip['floating_ip_address']
        return self.vip_ip_address

    def create_addtional_members(self, protocol_port):
        for server_name in self.topology_servers.keys():
            if server_name in self.server_names:
                continue
            fip_data = self.servers_details[server_name].floating_ips[0]
            fixed_ip_address = fip_data['fixed_ip_address']
            self._disassociate_floating_ip(fip_data)
            pool_id = self.pool['id']
            vip_subnet_id = self.topology_subnets["subnet_lbaas_1"]['id']
            lb_id = self.loadbalancer['id']
            self.members_client.create_member(
                pool_id, subnet_id=vip_subnet_id,
                address=fixed_ip_address,
                protocol_port=protocol_port)
            self.wait_for_load_balancer_status(lb_id)

    def do_http_request(self, start_path='', send_counts=None):
        self.http_cnt = {}
        for x in range(send_counts):
            resp = self.send_request(self.vip_ip_address)
            self.count_response(resp)
        return self.http_cnt

    def check_project_lbaas1(self, no_vms):
        for count in range(1, 10):
            self.do_http_request(send_counts=self.poke_counters)
        # ROUND_ROUBIN, so equal counts
        no_of_vms = len(self.http_cnt)
        self.assertEqual(no_vms, no_of_vms)

    def check_project_lbaas(self, count=2):
        i = 0
        self.do_http_request(send_counts=self.poke_counters)
        # ROUND_ROUBIN, so equal counts
        no_of_vms = len(self.http_cnt)
        for server_name in self.topology_servers.keys():
            if i < count:
                i += 1
                self.assertEqual(self.poke_counters / no_of_vms,
                                 self.http_cnt[server_name])
            else:
                break

    def count_response(self, response):
        if response in self.http_cnt:
            self.http_cnt[response] += 1
        else:
            self.http_cnt[response] = 1

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c5ac853b-6867-4b7a-8704-3844b11b1a34')
    def test_lbaas_http_traffic_roundrobin_with_ping_health_type(self):
        self.deploy_lbaas_topology_1()
        self.start_web_server(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='PING')
        self.check_project_lbaas()

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('87b709bf-127f-4161-b43f-3915c216c44b')
    def test_lbaas_http_traffic_roundrobin_with_http_health_type(self):
        self.deploy_lbaas_topology_1()
        self.start_web_server(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='HTTP')
        self.check_project_lbaas1(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('60e9facf-b8d6-48a9-b0d2-942e5bb38f38')
    def test_lbaas_http_leastconnections_with_ping_health_type(self):
        self.deploy_lbaas_topology_1()
        self.start_web_server(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='PING')
        self.check_project_lbaas1(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('3041a103-e03d-4660-b411-2f9d5987dba8')
    def test_lbaas_http_leastconnections_with_http_health_type(self):
        self.deploy_lbaas_topology_1()
        self.start_web_server(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='HTTP')
        self.check_project_lbaas1(constants.NO_OF_VMS_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('de8577b6-8aee-40cc-b856-e25f83c26bdd')
    def test_lbaas_http_traffic_roundrobin_with_ping_type_on_new_members(self):
        self.deploy_lbaas_topology_1(constants.NO_OF_VMS_4)
        self.start_web_server(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='PING',
                                  member_count=2)
        self.check_project_lbaas()
        self.create_addtional_members(constants.HTTP_PORT)
        time.sleep(constants.SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS)
        self.check_project_lbaas(constants.NO_OF_VMS_4)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('86315138-3d95-4694-97ad-04a94a896201')
    def test_lbaas_http_leastconnections_with_ping_type_on_new_members(self):
        self.deploy_lbaas_topology_1(constants.NO_OF_VMS_4)
        self.start_web_server(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="LEAST_CONNECTIONS",
                                  hm_type='PING', member_count=2)
        self.check_project_lbaas()
        self.create_addtional_members(constants.HTTP_PORT)
        time.sleep(constants.SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS)
        self.check_project_lbaas1(constants.NO_OF_VMS_4)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('28e9d22d-4da2-460e-9c5b-bd8ddc1d35b6')
    def test_lbaas_http_traffic_roundrobin_with_http_type_on_new_members(self):
        self.deploy_lbaas_topology_1(constants.NO_OF_VMS_4)
        self.start_web_server(constants.HTTP_PORT)
        self.create_project_lbaas(protocol_type="HTTP", protocol_port="80",
                                  lb_algorithm="ROUND_ROBIN", hm_type='PING',
                                  member_count=2)
        self.check_project_lbaas()
        self.create_addtional_members(constants.HTTP_PORT)
        time.sleep(constants.SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS)
        self.check_project_lbaas(constants.NO_OF_VMS_4)

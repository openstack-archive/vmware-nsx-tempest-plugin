# Copyright 2017 VMware Inc
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

from neutron_lib import constants as nl_constants

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from vmware_nsx_tempest._i18n import _
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import traffic_manager
from vmware_nsx_tempest.services import designate_base
from vmware_nsx_tempest.services import fwaas_client as FWAASC
from vmware_nsx_tempest.services.lbaas import health_monitors_client
from vmware_nsx_tempest.services.lbaas import listeners_client
from vmware_nsx_tempest.services.lbaas import load_balancers_client
from vmware_nsx_tempest.services.lbaas import members_client
from vmware_nsx_tempest.services.lbaas import pools_client
from vmware_nsx_tempest.services import nsx_client
from vmware_nsx_tempest.services import openstack_network_clients

LOG = constants.log.getLogger(__name__)

CONF = config.CONF

RULE_TYPE_BANDWIDTH_LIMIT = "bandwidth_limit"
RULE_TYPE_DSCP_MARK = "dscp_marking"


# It includes feature related function such CRUD Mdproxy, L2GW or QoS
class FeatureManager(traffic_manager.IperfManager,
                     designate_base.DnsClientBase):
    @classmethod
    def setup_clients(cls):
        """Create various client connections. Such as NSXv3 and L2 Gateway.

        """
        super(FeatureManager, cls).setup_clients()
        try:
            manager = getattr(cls.os_admin, "manager", cls.os_admin)
            net_client = getattr(manager, "networks_client")
            _params = manager.default_params_withy_timeout_values.copy()
        except AttributeError as attribute_err:
            LOG.warning(
                "Failed to locate the attribute, Error: %(err_msg)s",
                {"err_msg": attribute_err.__str__()})
            _params = {}
        cls.l2gw_client = openstack_network_clients.L2GatewayClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        cls.nsx_client = nsx_client.NSXClient(
            CONF.network.backend,
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)
        cls.l2gwc_client = openstack_network_clients.L2GatewayConnectionClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        cls.load_balancers_client = \
            load_balancers_client.get_client(cls.os_primary)
        cls.listeners_client = listeners_client.get_client(cls.os_primary)
        cls.pools_client = pools_client.get_client(cls.os_primary)
        cls.members_client = members_client.get_client(cls.os_primary)
        cls.health_monitors_client = \
            health_monitors_client.get_client(cls.os_primary)
        cls.fwaas_v2_client = openstack_network_clients.FwaasV2Client(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        cls.fwaasv1_client = FWAASC.get_client(cls.manager)
        cls.vpnaas_client = openstack_network_clients.VPNClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        cls.qos_policy_client = openstack_network_clients.QosPoliciesClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        cls.qos_bw_client = openstack_network_clients.QosBWLimitClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        cls.qos_dscp_client = openstack_network_clients.QosDscpClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        net_client.service = 'dns'
        cls.zones_v2_client = openstack_network_clients.ZonesV2Client(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)

    #
    # FwaasV2 base class
    #
    def create_firewall_rule(self, **kwargs):
        fw_rule = self.fwaas_v2_client.create_firewall_v2_rule(**kwargs)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.fwaas_v2_client.delete_firewall_v2_rule,
            fw_rule["firewall_rule"]["id"])
        return fw_rule

    def create_firewall_policy(self, **kwargs):
        fw_policy = self.fwaas_v2_client.create_firewall_v2_policy(**kwargs)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.fwaas_v2_client.delete_firewall_v2_policy,
            fw_policy["firewall_policy"]["id"])
        return fw_policy

    def create_firewall_group(self, **kwargs):
        fw_group = self.fwaas_v2_client.create_firewall_v2_group(**kwargs)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.fwaas_v2_client.delete_firewall_v2_group,
            fw_group["firewall_group"]["id"])
        return fw_group

    def update_firewall_group(self, group_id, **kwargs):
        fw_group = self.fwaas_v2_client.update_firewall_v2_group(group_id,
                                                                 **kwargs)
        return fw_group

    def update_firewall_policy(self, policy_id, **kwargs):
        return self.fwaas_v2_client.update_firewall_v2_policy(policy_id,
                                                              **kwargs)

    def update_firewall_rule(self, rule_id, **kwargs):
        return self.fwaas_v2_client.update_firewall_v2_rule(rule_id,
                                                            **kwargs)

    def show_firewall_group(self, group_id):
        fw_group = self.fwaas_v2_client.show_firewall_v2_group(group_id)
        return fw_group

    def show_firewall_rule(self, rule_id):
        fw_rule = self.fwaas_v2_client.show_firewall_v2_rule(rule_id)
        return fw_rule

    def show_firewall_policy(self, policy_id):
        fw_policy = self.fwaas_v2_client.show_firewall_v2_policy(policy_id)
        return fw_policy

    #
    # FwaasV1 base class
    #
    def _create_firewall_rule_name(self, body):
        firewall_rule_name = body['firewall_rule']['name']
        firewall_rule_name = "Fwaas-" + firewall_rule_name
        return firewall_rule_name

    def _delete_rule_if_exists(self, rule_id):
        # delete rule, if it exists
        try:
            self.fwaasv1_client.delete_firewall_rule(rule_id)
        # if rule is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _delete_firewall_if_exists(self, fw_id):
        # delete firewall, if it exists
        try:
            self.fwaasv1_client.delete_firewall(fw_id)
        # if firewall is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass
        self.fwaasv1_client.wait_for_resource_deletion(fw_id)

    def create_fw_v1_rule(self, **kwargs):
        body = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            **kwargs)
        fw_rule = body['firewall_rule']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.fwaasv1_client.delete_firewall_rule,
                        fw_rule['id'])
        return fw_rule

    def create_fw_v1_policy(self, **kwargs):
        body = self.fwaasv1_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"),
            **kwargs)
        fw_policy = body['firewall_policy']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.fwaasv1_client.delete_firewall_policy,
                        fw_policy['id'])
        return fw_policy

    def insert_fw_v1_rule_in_policy(self, firewall_policy_id, firewall_rule_id,
                                    insert_after, insert_before):
        self.fwaasv1_client.insert_fw_v1_rule_in_policy(firewall_policy_id,
                                                        firewall_rule_id,
                                                        insert_after,
                                                        insert_before)

    def delete_fw_v1_and_wait(self, firewall_id):
        self.fwaasv1_client.delete_firewall(firewall_id)
        self._wait_firewall_while(firewall_id, [nl_constants.PENDING_DELETE],
                                  not_found_ok=True)

    def _delete_policy_if_exists(self, policy_id):
        # delete policy, if it exists
        try:
            self.fwaasv1_client.delete_firewall_policy(policy_id)
        # if policy is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def create_fw_v1(self, **kwargs):
        body = self.fwaasv1_client.create_firewall(
            name=data_utils.rand_name("fw"),
            **kwargs)
        fw = body['firewall']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_firewall_and_wait,
                        fw['id'])
        return fw

    def update_fw_v1(self, firewall_id, **kwargs):
        body = self.fwaasv1_client.update_firewall(firewall_id, **kwargs)
        return body

    def show_fw_v1(self, firewall_id):
        body = self.fwaasv1_client.show_firewall(firewall_id)
        return body

    def _wait_fw_v1_while(self, firewall_id, statuses, not_found_ok=False):
        start = int(time.time())
        if not_found_ok:
            expected_exceptions = (lib_exc.NotFound)
        else:
            expected_exceptions = ()
        while True:
            try:
                fw = self.fwaasv1_client.show_firewall(firewall_id)
            except expected_exceptions:
                break
            status = fw['firewall']['status']
            if status not in statuses:
                break
            if int(time.time()) - start >= self.fwaasv1_client.build_timeout:
                msg = ("Firewall %(firewall)s failed to reach "
                       "non PENDING status (current %(status)s)") % {
                    "firewall": firewall_id,
                    "status": status,
                }
                raise lib_exc.TimeoutException(msg)
            time.sleep(constants.NSX_BACKEND_VERY_SMALL_TIME_INTERVAL)

    def _wait_fw_v1_ready(self, firewall_id):
        self._wait_firewall_while(firewall_id,
                                  [nl_constants.PENDING_CREATE,
                                   nl_constants.PENDING_UPDATE])

    def _wait_fw_v1_until_ready(self, fw_id):
        target_states = ('ACTIVE', 'CREATED')

        def _wait():
            firewall = self.fwaasv1_client.show_firewall(fw_id)
            firewall = firewall['firewall']
            return firewall['status'] in target_states
        if not test_utils.call_until_true(_wait, CONF.network.build_timeout,
                                          CONF.network.build_interval):
            m = ("Timed out waiting for firewall %s to reach %s state(s)" %
                 (fw_id, target_states))
            raise lib_exc.TimeoutException(m)

    def create_fw_v1_basic_topo(self, router_type, protocol_name,
                                policy=None):
        rtr_kwargs = {"router_type": "exclusive",
                      "admin_state_up": "True"}
        router = self.create_topology_router("fire-1", **rtr_kwargs)
        body = self.fwaasv1_client.create_fw_v1_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol=protocol_name)
        fw_rule_id1 = body['firewall_rule']['id']
        self._create_firewall_rule_name(body)
        self.addCleanup(self._delete_rule_if_exists, fw_rule_id1)
        # Create firewall policy
        if not policy:
            body = self.fwaasv1_client.create_fw_v1_policy(
                name=data_utils.rand_name("fw-policy"))
            fw_policy_id = body['firewall_policy']['id']
            self.addCleanup(self._delete_policy_if_exists, fw_policy_id)
            # Insert rule to firewall policy
            self.fwaasv1_client.insert_firewall_rule_in_policy(
                fw_policy_id, fw_rule_id1, '', '')
        else:
            fw_policy_id = policy
        # Create firewall
        firewall_1 = self.fwaasv1_client.create_fw_v1(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router['id']])
        created_firewall = firewall_1['firewall']
        self.addCleanup(self._delete_firewall_if_exists,
                        created_firewall['id'])
        # Wait for the firewall resource to become ready
        self._wait_fw_v1_until_ready(created_firewall['id'])

    #
    # L2Gateway base class. To get basics of L2GW.
    #
    def create_l2gw(self, l2gw_name, l2gw_param):
        """Creates L2GW and returns the response.

        :param l2gw_name: name of the L2GW
        :param l2gw_param: L2GW parameters

        :return: response of L2GW create API

        """
        LOG.info("l2gw name: %(name)s, l2gw_param: %(devices)s ",
                 {"name": l2gw_name, "devices": l2gw_param})
        devices = []
        for device_dict in l2gw_param:
            interface = [{"name": device_dict["iname"],
                          "segmentation_id": device_dict[
                              "vlans"]}] if "vlans" in device_dict else [
                {"name": device_dict["iname"]}]
            device = {"device_name": device_dict["dname"],
                      "interfaces": interface}
            devices.append(device)
        l2gw_request_body = {"devices": devices}
        LOG.info(" l2gw_request_body: %s", l2gw_request_body)
        rsp = self.l2gw_client.create_l2_gateway(
            name=l2gw_name, **l2gw_request_body)
        LOG.info(" l2gw response: %s", rsp)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.l2gw_client.delete_l2_gateway, rsp[constants.L2GW]["id"])
        return rsp, devices

    def delete_l2gw(self, l2gw_id):
        """Delete L2gw.

        :param l2gw_id: L2GW id to delete l2gw.

        :return: response of the l2gw delete API.

        """
        LOG.info("L2GW id: %(id)s to be deleted.", {"id": l2gw_id})
        rsp = self.l2gw_client.delete_l2_gateway(l2gw_id)
        LOG.info("response : %(rsp)s", {"rsp": rsp})
        return rsp

    def update_l2gw(self, l2gw_id, l2gw_new_name, devices):
        """Update existing L2GW.

        :param l2gw_id: L2GW id to update its parameters.
        :param l2gw_new_name: name of the L2GW.
        :param devices: L2GW parameters.

        :return: Response of the L2GW update API.

        """
        rsp = self.l2gw_client.update_l2_gateway(l2gw_id,
                                                 name=l2gw_new_name, **devices)
        return rsp

    def nsx_bridge_cluster_info(self):
        """Collect the device and interface name of the nsx brdige cluster.

        :return: nsx bridge id and display name.

        """
        response = self.nsx_client.get_bridge_cluster_info()
        if len(response) == 0:
            raise RuntimeError(_("NSX bridge cluster information is null"))
        return [(x.get("id"), x.get("display_name")) for x in response]

    def create_l2gw_connection(self, l2gwc_param):
        """Creates L2GWC and return the response.

        :param l2gwc_param: L2GWC parameters.

        :return: response of L2GWC create API.

        """
        LOG.info("l2gwc param: %(param)s ", {"param": l2gwc_param})
        l2gwc_request_body = {"l2_gateway_id": l2gwc_param["l2_gateway_id"],
                              "network_id": l2gwc_param["network_id"]}
        if "segmentation_id" in l2gwc_param:
            l2gwc_request_body["segmentation_id"] = l2gwc_param[
                "segmentation_id"]
        LOG.info("l2gwc_request_body: %s", l2gwc_request_body)
        rsp = self.l2gwc_client.create_l2_gateway_connection(
            **l2gwc_request_body)
        LOG.info("l2gwc response: %s", rsp)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.l2gwc_client.delete_l2_gateway_connection,
            rsp[constants.L2GWC]["id"])
        return rsp

    def delete_l2gw_connection(self, l2gwc_id):
        """Delete L2GWC and returns the response.

        :param l2gwc_id: L2GWC id to delete L2GWC.

        :return: response of the l2gwc delete API.

        """
        LOG.info("L2GW connection id: %(id)s to be deleted",
                 {"id": l2gwc_id})
        rsp = self.l2gwc_client.delete_l2_gateway_connection(l2gwc_id)
        LOG.info("response : %(rsp)s", {"rsp": rsp})
        return rsp

    #
    # LBAAS section.
    #
    def delete_loadbalancer_resources(self, lb_id):
        """Deletion of lbaas resources.

        :param lb_id: Load Balancer ID.

        """
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
        """Deletion of lbaas pool resources.

        :param lb_id: Load Balancer ID.
        :param pool: pool information.

        """
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

    def start_web_servers(self, protocol_port):
        """Start web server.

        :param protocol_port: Port number.

        """
        for server_name in self.topology_servers.keys():
            server = self.servers_details[server_name].server
            self.start_web_server(protocol_port, server, server_name)

    def _wait_firewall_while(self, fw_group_id, statuses, not_found_ok=False):
        if not_found_ok:
            expected_exceptions = (lib_exc.NotFound)
        else:
            expected_exceptions = ()
        while True:
            try:
                fw = self.show_firewall_group(fw_group_id)
            except expected_exceptions:
                break
            status = fw['firewall_group']['status']
            if status not in statuses:
                break

    def _wait_firewall_ready(self, fw_group_id):
        time.sleep(constants.NSX_BACKEND_VERY_SMALL_TIME_INTERVAL)
        self._wait_firewall_while(fw_group_id,
                                  [nl_constants.PENDING_CREATE,
                                   nl_constants.PENDING_UPDATE])

    def wait_for_load_balancer_status(self, lb_id):
        # Wait for load balancer become ONLINE and ACTIVE
        self.load_balancers_client.wait_for_load_balancer_status(lb_id)

    def create_addtional_lbaas_members(self, protocol_port):
        """Create Additional members in pool.

        :param protocol_port: Port number.

        """
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

    def check_lbaas_project_weight_values(self, count=2):
        vip = self.vip_ip_address
        time.sleep(constants.SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS)
        self.do_http_request(vip=vip, send_counts=self.poke_counters)
        # ROUND_ROUBIN, so equal counts
        if CONF.nsxv3.ens:
            vms = len(self.topology_servers.keys())
            if vms:
                self.assertEqual(self.http_cnt["Welcome vm"] / 2, 3 * vms,
                                 "LB fails with weighted values")
            else:
                pass
        else:
            no_of_vms = len(self.http_cnt)
            if no_of_vms:
                if (self.http_cnt['server_lbaas_0'] <
                        (self.poke_counters / no_of_vms)):
                    self.assertGreater(self.http_cnt['server_lbaas_1'],
                                       self.poke_counters / no_of_vms)
                elif (self.http_cnt['server_lbaas_0'] >
                      (self.poke_counters / no_of_vms)):
                    self.assertLess(self.http_cnt['server_lbaas_1'],
                                    self.poke_counters / no_of_vms)
                else:
                    self.assertEqual(self.http_cnt['server_lbaas_1'],
                                     self.poke_counters / no_of_vms,
                                     "LB fails with weighted values")

    def check_project_lbaas(self, count=2):
        i = 0
        time.sleep(constants.SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS)
        vip = self.vip_ip_address
        self.do_http_request(vip=vip, send_counts=self.poke_counters)
        # ROUND_ROUBIN, so equal counts
        no_of_vms = len(self.http_cnt)
        if CONF.nsxv3.ens:
            vms = len(self.topology_servers.keys())
            if self.http_cnt["Welcome vm"] == self.poke_counters:
                self.assertEqual(self.http_cnt["Welcome vm"] / vms,
                                 3 * vms)
        else:
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

    def update_members_weight(self, weight):
        for server in self.members:
            self.members_client.update_member(
                self.pool['id'], server['member']['id'], weight=weight)
            weight += weight

    def update_pool_algorithm(self, algo):
        self.pools_client.update_pool(self.pool['id'],
                                      lb_algorithm=algo)

    def create_project_lbaas(self, protocol_type, protocol_port, lb_algorithm,
                             hm_type, member_count=2, max_vms=None,
                             weight=None, fip_disassociate=None):
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
            if count < member_count:
                fip_data = self.servers_details[server_name].floating_ips[0]
                fixed_ip_address = fip_data['fixed_ip_address']
                if fip_disassociate is None:
                    self._disassociate_floating_ip(fip_data)
                if weight:
                    weight += count
                    member = self.members_client.create_member(
                        pool_id, subnet_id=vip_subnet_id,
                        address=fixed_ip_address,
                        protocol_port=protocol_port,
                        weight=weight)
                else:
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
        if not CONF.nsxv3.ens:
            self.ports_client.update_port(
                self.loadbalancer['vip_port_id'],
                security_groups=[self.sg['id']])
        # create lbaas public interface
        vip_fip = \
            self.create_floatingip(self.loadbalancer,
                                   port_id=self.loadbalancer['vip_port_id'])
        self.vip_ip_address = vip_fip['floating_ip_address']
        return self.vip_ip_address

    def get_router_port(self, client):
        """List ports using admin creds """
        ports_list = client.list_ports()
        for port in ports_list['ports']:
            port_info = client.show_port(port['id'])
            if port_info['port']['device_owner'] == "network:router_interface":
                return port_info['port']['id']
        return None

    # Vlan backed Tier-1 router operations
    def check_downlink_port_created(self, router_op, subnet, port_id):
        tag_hit = 0
        backend_rtr_id = ''
        all_routers = self.nsx.get_logical_routers()
        for router in all_routers:
            if router_op['name'] in router.get('display_name'):
                backend_rtr_id = router['id']
                rtr = {'id': backend_rtr_id}
                break
        if backend_rtr_id:
            logical_rtr_ports = self.nsx.get_logical_router_ports(rtr)
            for ports in logical_rtr_ports:
                for rtr_tag in ports.get('tags'):
                    if rtr_tag['scope'] == "os-neutron-rport-id" and \
                            rtr_tag['tag'] == port_id:
                        tag_hit += 1
                        continue
                    if rtr_tag['scope'] == "os-subnet-id" and subnet['id'] == \
                            rtr_tag['tag']:
                        tag_hit += 1
                        ports_info = ports
                        break
            if tag_hit == 2:
                if ports_info.get('resource_type') \
                        == 'LogicalRouterDownLinkPort':
                    ip_address = ports_info.get('subnets')[
                        0].get('ip_addresses')
                    if ip_address:
                        if not self.\
                            cmgr_adm.subnets_client.show_subnet(
                                subnet['id']).get('subnet')[
                                'gateway_ip'] == ip_address[0]:
                            raise RuntimeError(
                                "Router centralized port ip doesn't "
                                "match with openstack subnet "
                                "gatewayip")
                        else:
                            pass
            else:
                raise RuntimeError(
                    "Router_port_id and subnet_id doesn't match at "
                    "the backend")
        else:
            raise RuntimeError("Router not created at the backend properly")

    def check_centralized_port_created(self, router_op, subnet, port_id):
        tag_hit = 0
        backend_rtr_id = ''
        all_routers = self.nsx.get_logical_routers()
        for router in all_routers:
            if router_op['name'] in router.get('display_name'):
                backend_rtr_id = router['id']
                rtr = {'id': backend_rtr_id}
                break
        if backend_rtr_id:
            logical_rtr_ports = self.nsx.get_logical_router_ports(rtr)
            for ports in logical_rtr_ports:
                for rtr_tag in ports.get('tags'):
                    if rtr_tag['scope'] == "os-neutron-rport-id" and \
                            rtr_tag['tag'] == port_id:
                        tag_hit += 1
                        continue
                    if rtr_tag['scope'] == "os-subnet-id" and subnet['id'] == \
                            rtr_tag['tag']:
                        tag_hit += 1
                        ports_info = ports
                        break
            if tag_hit == 2:
                if ports_info.get(
                        'resource_type') \
                        == 'LogicalRouterCentralizedServicePort':
                    ip_address = ports_info.get('subnets')[
                        0].get('ip_addresses')
                    if ip_address:
                        if not self.cmgr_adm.subnets_client.\
                                show_subnet(subnet['id']).\
                                get('subnet')[
                                'gateway_ip'] == ip_address[0]:
                            raise RuntimeError(
                                "Router centralized port ip doesn't "
                                "match with openstack subnet "
                                "gatewayip")
                    else:
                        pass
            else:
                raise RuntimeError(
                    "Router_port_id and subnet_id doesn't match at "
                    "the backend")
        else:
            raise RuntimeError("Router not created at the backend properly")

    #
    # QoS base class. To get basics of QoS.
    #
    def get_qos_policy_id(self, policy_id_or_name):
        policies = self.qos_policy_client.list_policies(name=policy_id_or_name)
        policy_list = policies['policies']
        if len(policy_list) > 0:
            return policy_list[0]['id']
        return policy_id_or_name

    def create_qos_policy(self, name, description, shared, **kwargs):
        result = self.qos_policy_client.create_policy(
            name=name,
            description=description,
            shared=shared,
            **kwargs
        )
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.qos_policy_client.delete_policy,
                        result['policy']['id'])
        return result.get('policy', result)

    def delete_qos_policy(self, policy_id):
        result = self.qos_policy_client.delete_policy(policy_id)
        return result.get('policy', result)

    def list_qos_policies(self, **filters):
        result = self.qos_policy_client.list_policies(**filters)
        return result.get('policies', result)

    def update_qos_policy(self, policy_id, **kwargs):
        result = self.qos_policy_client.update_policy(policy_id, **kwargs)
        return result.get('policy', result)

    def show_qos_policy(self, policy_id, **fields):
        result = self.qos_policy_client.show_policy(policy_id, **fields)
        return result.get('policy', result)

    #
    # QoS bandwidth_limit
    #
    def create_bandwidth_limit_rule(self, policy_id,
                                    max_kbps, max_burst_kbps,
                                    **kwargs):
        result = self.qos_bw_client.create_bandwidth_limit_rule(
            policy_id,
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps,
            **kwargs)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.qos_bw_client.delete_bandwidth_limit_rule,
                        result['bandwidth_limit_rule']['id'], policy_id)
        return result.get('bandwidth_limit_rule', result)

    def delete_bandwidth_limit_rule(self, rule_id, policy_id):
        result = self.qos_bw_client.delete_bandwidth_limit_rule(
            rule_id, policy_id)
        return result.get('bandwidth_limit_rule', result)

    def update_bandwidth_limit_rule(self, rule_id, policy_id_or_name,
                                    **kwargs):
        policy_id = self.get_qos_policy_id(policy_id_or_name)
        result = self.qos_bw_client.update_bandwidth_limit_rule(
            rule_id, policy_id, **kwargs)
        return result.get('bandwidth_limit_rule', result)

    def list_bandwidth_limit_rules(self, policy_id, **filters):
        result = self.qos_bw_client.list_bandwidth_limit_rules(
            policy_id, **filters)
        return result.get('bandwidth_limit_rules', result)

    def show_bandwidth_limit_rule(self, rule_id, policy_id,
                                  **fields):
        result = self.qos_bw_client.show_bandwidth_limit_rule(
            rule_id, policy_id)
        return result.get('bandwidth_limit_rule', result)

    #
    # QoS DSCP Marking Rule
    #
    def create_dscp_marking_rule(self, policy_id, dscp_mark,
                                 **kwargs):
        policy_id = self.get_qos_policy_id(policy_id)
        kwargs['dscp_mark'] = dscp_mark
        result = self.qos_dscp_client.create_dscp_marking_rule(
            policy_id, **kwargs)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.qos_dscp_client.delete_dscp_marking_rule,
                        result['dscp_marking_rule']['id'], policy_id)
        return result.get('dscp_marking_rule', result)

    def delete_dscp_marking_rule(self, rule_id, policy_id_or_name):
        policy_id = self.get_qos_policy_id(policy_id_or_name)
        result = self.qos_dscp_client.delete_dscp_marking_rule(rule_id,
                                                               policy_id)
        return result.get('dscp_marking_rule', result)

    def update_dscp_marking_rule(self, rule_id, policy_id_or_name,
                                 **kwargs):
        policy_id = self.get_qos_policy_id(policy_id_or_name)
        result = self.qos_dscp_client.update_dscp_marking_rule(
            rule_id, policy_id, **kwargs)
        return result.get('dscp_marking_rule', result)

    def list_dscp_marking_rules(self, policy_id_or_name, **filters):
        policy_id = self.get_qos_policy_id(policy_id_or_name)
        result = self.qos_dscp_client.list_dscp_marking_rules(
            policy_id, **filters)
        return result.get('dscp_marking_rules', result)

    def show_dscp_marking_rule(self, rule_id, policy_id_or_name, **fields):
        policy_id = self.get_qos_policy_id(policy_id_or_name)
        result = self.qos_dscp_client.show_dscp_marking_rule(
            rule_id, policy_id, **fields)
        return result.get('dscp_marking_rule', result)

    def list_rule_types(self):
        result = self.types_client.list_rule_types()
        return result.get('rule_types', result)

    #
    # Designate Zone
    #
    def rand_zone_name(name='', prefix=None, suffix='.com.'):
        """Generate a random zone name
        :param str name: The name that you want to include
        :param prefix: the exact text to start the string. Defaults to "rand"
        :param suffix: the exact text to end the string
        :return: a random zone name e.g. example.org.
        :rtype: string
        """
        name = 'tempest'
        name = data_utils.rand_name(name=name, prefix=prefix)
        zone_name = name + suffix
        return zone_name

    def rand_email(self, zone_name):
        """Generate a random zone name
        :return: a random zone name e.g. example.org.
        :rtype: string
        """
        email_id = 'example@%s' % str(zone_name).rstrip('.')
        return email_id

    def create_zone(self, name=None, email=None, description=None,
                    wait_until=False):
        """Create a zone with the specified parameters.
        :param name: The name of the zone.
            Default: Random Value
        :param email: The email for the zone.
            Default: Random Value
        :param ttl: The ttl for the zone.
            Default: Random Value
        :param description: A description of the zone.
            Default: Random Value
        :param wait_until: Block until the zone reaches the desired status
        :return: A tuple with the server response and the created zone.
        """
        if name is None:
            name = self.rand_zone_name()
        zone = {
            'name': name,
            'email': email or self.rand_email(name),
            'description': description or data_utils.rand_name('test-zone'),
        }
        _, body = self.zones_v2_client.create_zone(wait_until, **zone)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_zone, body['id'])
        # Create Zone should Return a HTTP 202
        return body

    def delete_zone(self, uuid):
        """Deletes a zone having the specified UUID.
        :param uuid: The unique identifier of the zone.
        :return: A tuple with the server response and the response body.
        """
        _, body = self.zones_v2_client.delete_zone(uuid)
        return body

    def show_zone(self, uuid):
        """Gets a specific zone.
        :param uuid: Unique identifier of the zone in UUID format.
        :return: Serialized zone as a dictionary.
        """
        return self.zones_v2_client.show_zone(uuid)

    def list_zones(self):
        """Gets a list of zones.
        :return: Serialized zones as a list.
        """
        return self.zones_v2_client.list_zones()

    def update_zone(self, uuid, email=None, ttl=None,
                    description=None, wait_until=False):
        """Update a zone with the specified parameters.
        :param uuid: The unique identifier of the zone.
        :param email: The email for the zone.
            Default: Random Value
        :param ttl: The ttl for the zone.
            Default: Random Value
        :param description: A description of the zone.
            Default: Random Value
        :param wait_until: Block until the zone reaches the desiered status
        :return: A tuple with the server response and the updated zone.
        """
        zone = {
            'email': email or self.rand_email(),
            'ttl': ttl or self.rand_ttl(),
            'description': description or self.rand_name('test-zone'),
        }
        _, body = self.zones_v2_client.update_zone(uuid, wait_until, **zone)
        return body

    def list_record_set_zone(self, uuid):
        """list recordsets of a zone.
        :param uuid: The unique identifier of the zone.
        """
        body = self.zones_v2_client.list_recordset_zone(uuid)
        return body

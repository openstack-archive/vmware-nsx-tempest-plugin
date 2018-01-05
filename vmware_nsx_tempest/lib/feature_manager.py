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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from vmware_nsx_tempest._i18n import _
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import traffic_manager
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
class FeatureManager(traffic_manager.IperfManager):
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
                             weight=None):
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
        self.ports_client.update_port(
            self.loadbalancer['vip_port_id'],
            security_groups=[self.sg['id']])
        # create lbaas public interface
        vip_fip = \
            self.create_floatingip(self.loadbalancer,
                                   port_id=self.loadbalancer['vip_port_id'])
        self.vip_ip_address = vip_fip['floating_ip_address']
        return self.vip_ip_address

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

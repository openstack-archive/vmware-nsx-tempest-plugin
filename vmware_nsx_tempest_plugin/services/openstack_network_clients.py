# Copyright 2017 VMware, Inc.
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

import json
import six
import time

from oslo_log import log
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common import rest_client
from tempest.lib.services.network import base
from tempest.lib import exceptions

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.common import waiters
from vmware_nsx_tempest_plugin.services import designate_base

LOG = log.getLogger(__name__)
CONF = config.CONF


class L2GatewayClient(base.BaseNetworkClient):
    """
    Request resources via API for L2GatewayClient
        l2 gateway create request
        l2 gateway update request
        l2 gateway show request
        l2 gateway delete request
        l2 gateway list all request
    """

    def create_l2_gateway(self, **kwargs):
        uri = constants.L2_GWS_BASE_URI
        post_data = {constants.L2GW: kwargs}
        LOG.info("URI : %(uri)s, posting data : %(post_data)s",
                 {"uri": uri, "post_data": post_data})
        return self.create_resource(uri, post_data)

    def update_l2_gateway(self, l2_gateway_id, **kwargs):
        uri = constants.L2_GWS_BASE_URI + "/" + l2_gateway_id
        post_data = {constants.L2GW: kwargs}
        constants.LOG.info(
            "URI : %(uri)s, posting data : %(post_data)s",
            {"uri": uri, "post_data": post_data})
        return self.update_resource(uri, post_data)

    def show_l2_gateway(self, l2_gateway_id, **fields):
        uri = constants.L2_GWS_BASE_URI + "/" + l2_gateway_id
        LOG.info("URI : %(uri)s", {"uri": uri})
        return self.show_resource(uri, **fields)

    def delete_l2_gateway(self, l2_gateway_id):
        uri = constants.L2_GWS_BASE_URI + "/" + l2_gateway_id
        LOG.info("URI : %(uri)s", {"uri": uri})
        return self.delete_resource(uri)

    def list_l2_gateways(self, **filters):
        uri = constants.L2_GWS_BASE_URI
        LOG.info("URI : %(uri)s", {"uri": uri})
        return self.list_resources(uri, **filters)


class L2GatewayConnectionClient(base.BaseNetworkClient):
    """
    Request resources via API for L2GatewayClient
        l2 gateway connection create request
        l2 gateway connection update request
        l2 gateway connection show request
        l2 gateway connection delete request
        l2 gateway connection list all request
    """
    resource = 'l2_gateway_connection'
    resource_plural = 'l2_gateway_connections'
    path = 'l2-gateway-connections'
    resource_base_path = '/%s' % path
    resource_object_path = '/%s/%%s' % path

    def create_l2_gateway_connection(self, **kwargs):
        uri = self.resource_base_path
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def update_l2_gateway_connection(self, l2_gateway_id, **kwargs):
        uri = self.resource_object_path % l2_gateway_id
        post_data = {self.resource: kwargs}
        return self.update_resource(uri, post_data)

    def show_l2_gateway_connection(self, l2_gateway_id, **fields):
        uri = self.resource_object_path % l2_gateway_id
        return self.show_resource(uri, **fields)

    def delete_l2_gateway_connection(self, l2_gateway_id):
        uri = self.resource_object_path % l2_gateway_id
        return self.delete_resource(uri)

    def list_l2_gateway_connections(self, **filters):
        uri = self.resource_base_path
        return self.list_resources(uri, **filters)


class VPNClient(base.BaseNetworkClient):
    """
    Request resources via API for VPNaaS
        vpn service reate request
        vpn service update request
        vpn ike policy create request
        vpn ike policy update request
        vpn ipsec policy create request
        vpn ipsec policy update request
        vpn site conection create request
        vpn site connection  update request
        l2 gateway connection list all request
    """
    endpoint_groups_path = "/vpn/endpoint-groups"
    endpoint_group_path = "/vpn/endpoint-groups/%s"
    vpnservices_path = "/vpn/vpnservices"
    vpnservice_path = "/vpn/vpnservices/%s"
    ipsecpolicies_path = "/vpn/ipsecpolicies"
    ipsecpolicy_path = "/vpn/ipsecpolicies/%s"
    ikepolicies_path = "/vpn/ikepolicies"
    ikepolicy_path = "/vpn/ikepolicies/%s"
    ipsec_site_connections_path = "/vpn/ipsec-site-connections"
    ipsec_site_connection_path = "/vpn/ipsec-site-connections/%s"

    def list_vpnservices(self, **filters):
        """Fetches a list of all configured VPNServices for a tenant."""
        return self.list_resources(self.vpnservices_path, **filters)

    def create_vpnservice(self, **kwargs):
        """Creates a new VPNService."""
        return self.create_resource(self.vpnservices_path, kwargs)

    def update_vpnservice(self, vpnservice_id, **kwargs):
        """Updates a VPNService."""
        uri = self.vpnservice_path % vpnservice_id
        return self.update_resource(uri, kwargs)

    def update_ipsec_site_connections(self, endpoint_id, **kwargs):
        """Updates a VPN endpoint group."""
        uri = self.ipsec_site_connection_path % endpoint_id
        return self.update_resource(uri, kwargs)

    def update_ikepolicy(self, ikepolicy_id, **kwargs):
        """Updates an IKEPolicy."""
        uri = self.ikepolicy_path % ikepolicy_id
        return self.update_resource(uri, kwargs)

    def update_ipsecpolicy(self, ipsecpolicy_id, **kwargs):
        uri = self.ipsecpolicy_path % ipsecpolicy_id
        return self.update_resource(uri, kwargs)

    def show_ikepolicy(self, ikepolicy_id):
        """Fetches information of a specific IKEPolicy."""
        uri = self.ikepolicy_path % ikepolicy_id
        return self.show_resource(uri)

    def show_vpnservice(self, vpnservice_id):
        """Fetches information of a specific VPNService."""
        uri = self.vpnservice_path % (vpnservice_id)
        return self.show_resource(uri)

    def show_ipsecpolicy(self, ipsecpolicy_id):
        uri = self.ipsecpolicy_path % ipsecpolicy_id
        return self.show_resource(uri)

    def show_ipsec_site_connections(self, endpoint_id):
        """Updates a VPN endpoint group."""
        uri = self.ipsec_site_connection_path % endpoint_id
        return self.show_resource(uri)

    def delete_vpnservice(self, vpnservice_id):
        """Deletes the specified VPNService."""
        uri = self.vpnservice_path % (vpnservice_id)
        self.delete_resource(uri)

    def delete_ikepolicy(self, ikepolicy_id):
        """Deletes the specified IKEPolicy."""
        uri = self.ikepolicy_path % ikepolicy_id
        self.delete_resource(uri)

    def delete_ipsecpolicy(self, ipsecpolicy_id):
        """Deletes the specified IPsecPolicy."""
        uri = self.ipsecpolicy_path % (ipsecpolicy_id)
        self.delete_resource(uri)

    def list_ipsec_site_connections(self, retrieve_all=True, **_params):
        """Fetches all configured IPsecSiteConnections for a tenant."""
        return self.list('ipsec_site_connections',
                         self.ipsec_site_connections_path,
                         retrieve_all,
                         **_params)

    def show_ipsec_site_connection(self, ipsecsite_conn, **_params):
        """Fetches information of a specific IPsecSiteConnection."""
        return self.get(
            self.ipsec_site_connection_path % (ipsecsite_conn), params=_params
        )

    def delete_ipsec_site_connection(self, ipsecsite_conn):
        """Deletes the specified IPsecSiteConnection."""
        uri = self.ipsec_site_connection_path % (ipsecsite_conn)
        return self.delete_resource(uri)

    def list_ikepolicies(self, retrieve_all=True, **_params):
        """Fetches a list of all configured IKEPolicies for a tenant."""
        return self.list('ikepolicies', self.ikepolicies_path, retrieve_all,
                         **_params)

    def create_ikepolicy(self, **kwargs):
        """Creates a new VPNService."""
        return self.create_resource(self.ikepolicies_path, kwargs)

    def create_ipsecpolicy(self, **kwargs):
        return self.create_resource(self.ipsecpolicies_path, kwargs)

    def create_ipsec_site_connection(self, **kwargs):
        """Creates a new VPN endpoint group."""
        return self.create_resource(self.ipsec_site_connections_path, kwargs)

    def list_ipsecpolicies(self, retrieve_all=True, **_params):
        """Fetches a list of all configured IPsecPolicies for a tenant."""
        return self.list('ipsecpolicies',
                         self.ipsecpolicies_path,
                         retrieve_all,
                         **_params)


class FwaasV2Client(base.BaseNetworkClient):
    """
    Request resources via API for FwaasV2Client
        fwaasv2 create rule
        fwaasv2 update rule
        fwaasv2 delete rule
        fwaasv2 show rule
        fwaasv2 create policy
        fwaasv2 update policy
        fwaasv2 delete policy
        fwaasv2 show policy
        fwaasv2 create group
        fwaasv2 update group
        fwaasv2 delete group
        fwaasv2 show group
    """
    resource_rule = 'firewall_rule'
    resource_policy = 'firewall_policy'
    resource_group = 'firewall_group'
    rule_path = 'fwaas/firewall_rules'
    policy_path = '/fwaas/firewall_policies'
    group_path = '/fwaas/firewall_groups'
    resource_rule_base_path = '/%s' % rule_path
    resource_policy_base_path = '/%s' % policy_path
    resource_group_base_path = '/%s' % group_path
    resource_rule_object_path = '/%s/%%s' % rule_path
    resource_policy_object_path = '/%s/%%s' % policy_path
    resource_group_object_path = '/%s/%%s' % group_path

    def create_firewall_v2_rule(self, **kwargs):
        uri = self.resource_rule_base_path
        post_data = {self.resource_rule: kwargs}
        return self.create_resource(uri, post_data)

    def update_firewall_v2_rule(self, fw_rule_id, **kwargs):
        uri = self.resource_rule_object_path % fw_rule_id
        post_data = {self.resource_rule: kwargs}
        return self.update_resource(uri, post_data)

    def show_firewall_v2_rule(self, firewall_rule_id):
        uri = self.resource_rule_object_path % firewall_rule_id
        return self.show_resource(uri)

    def delete_firewall_v2_rule(self, firewall_rule_id):
        uri = self.resource_rule_object_path % firewall_rule_id
        return self.delete_resource(uri)

    def create_firewall_v2_policy(self, **kwargs):
        uri = self.resource_policy_base_path
        post_data = {self.resource_policy: kwargs}
        return self.create_resource(uri, post_data)

    def update_firewall_v2_policy(self, fw_policy_id, **kwargs):
        uri = self.resource_policy_object_path % fw_policy_id
        post_data = {self.resource_policy: kwargs}
        return self.update_resource(uri, post_data)

    def show_firewall_v2_policy(self, firewall_policy_id):
        uri = self.resource_policy_object_path % firewall_policy_id
        return self.show_resource(uri)

    def delete_firewall_v2_policy(self, policy_id):
        uri = self.resource_policy_object_path % policy_id
        return self.delete_resource(uri)

    def create_firewall_v2_group(self, **kwargs):
        uri = self.resource_group_base_path
        post_data = {self.resource_group: kwargs}
        return self.create_resource(uri, post_data)

    def update_firewall_v2_group(self, fw_group_id, **kwargs):
        uri = self.resource_group_object_path % fw_group_id
        post_data = {self.resource_group: kwargs}
        return self.update_resource(uri, post_data)

    def show_firewall_v2_group(self, fw_group_id):
        uri = self.resource_group_object_path % fw_group_id
        return self.show_resource(uri)

    def delete_firewall_v2_group(self, group_id):
        uri = self.resource_group_object_path % group_id
        return self.delete_resource(uri)


class QosBWLimitClient(base.BaseNetworkClient):
    """
    Request resources via API for QosBandwidthLimitClient
        Qos bandwidth-limit create request
        Qos bandwidth-limit update request
        Qos bandwidth-limit show request
        Qos bandwidth-limit delete request
        Qos bandwidth-limit list all request
    """
    resource = 'bandwidth_limit_rule'
    resource_plural = 'bandwidth_limit_rules'
    path = 'qos/policies'
    resource_base_path = '/%s/%%s/bandwidth_limit_rules' % path
    resource_object_path = '/%s/%%s/bandwidth_limit_rules/%%s' % path

    def create_bandwidth_limit_rule(self, policy_id, **kwargs):
        uri = self.resource_base_path % policy_id
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def update_bandwidth_limit_rule(self, rule_id, policy_id, **kwargs):
        uri = self.resource_object_path % (policy_id, rule_id)
        post_data = {self.resource: kwargs}
        return self.update_resource(uri, post_data)

    def show_bandwidth_limit_rule(self, rule_id, policy_id, **fields):
        uri = self.resource_object_path % (policy_id, rule_id)
        return self.show_resource(uri, **fields)

    def delete_bandwidth_limit_rule(self, rule_id, policy_id):
        uri = self.resource_object_path % (policy_id, rule_id)
        return self.delete_resource(uri)

    def list_bandwidth_limit_rules(self, policy_id, **filters):
        uri = self.resource_base_path % policy_id
        return self.list_resources(uri, **filters)


class QosDscpClient(base.BaseNetworkClient):
    """
    Request resources via API for QosBandwidthLimitClient
        Qos dscp-marking create request
        Qos dscp-marking update request
        Qos dscp-marking show request
        Qos dscp-marking delete request
        Qos dscp-marking list all request
    """
    resource = 'dscp_marking_rule'
    resource_plural = 'dscp_marking_rules'
    path = 'qos/policies'
    resource_base_path = '/%s/%%s/dscp_marking_rules' % path
    resource_object_path = '/%s/%%s/dscp_marking_rules/%%s' % path

    def create_dscp_marking_rule(self, policy_id, **kwargs):
        uri = self.resource_base_path % policy_id
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def update_dscp_marking_rule(self, rule_id, policy_id, **kwargs):
        uri = self.resource_object_path % (policy_id, rule_id)
        post_data = {self.resource: kwargs}
        return self.update_resource(uri, post_data)

    def show_dscp_marking_rule(self, rule_id, policy_id, **fields):
        uri = self.resource_object_path % (policy_id, rule_id)
        return self.show_resource(uri, **fields)

    def delete_dscp_marking_rule(self, rule_id, policy_id):
        uri = self.resource_object_path % (policy_id, rule_id)
        return self.delete_resource(uri)

    def list_dscp_marking_rules(self, policy_id, **filters):
        uri = self.resource_base_path % policy_id
        return self.list_resources(uri, **filters)


class QosPoliciesClient(base.BaseNetworkClient):
    """
    Request resources via API for QosPolicyClient
        Qos policy create request
        Qos policy update request
        Qos policy show request
        Qos policy delete request
        Qos policy list all request
    """
    resource = 'policy'
    resource_plural = 'policies'
    path = 'qos/policies'
    resource_base_path = '/%s' % path
    resource_object_path = '/%s/%%s' % path

    def create_policy(self, **kwargs):
        uri = self.resource_base_path
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def update_policy(self, policy_id, **kwargs):
        uri = self.resource_object_path % policy_id
        post_data = {self.resource: kwargs}
        return self.update_resource(uri, post_data)

    def show_policy(self, policy_id, **fields):
        uri = self.resource_object_path % policy_id
        return self.show_resource(uri, **fields)

    def delete_policy(self, policy_id):
        uri = self.resource_object_path % policy_id
        return self.delete_resource(uri)

    def list_policies(self, **filters):
        uri = self.resource_base_path
        return self.list_resources(uri, **filters)


class ZonesV2Client(designate_base.DnsClientBase):
    """
    Request resources via API for ZonesV2Client
        zonesv2 create zone
        zonesv2 update zone
        zonesv2 delete zone
        zonesv2 show zone
        zonesv2 list zones
    """
    resource = 'zone'
    resource_plural = 'policies'
    path = 'zones'
    resource_base_path = '/v2/%s' % path

    def create_zone(self, wait_until, **zone):
        resp, body = self._create_request(self.resource_base_path, zone)
        self.expected_success(202, resp.status)
        if wait_until:
            waiters.wait_for_zone_status_active(self, body['id'], wait_until)
        return resp, body

    def update_zone(self, zone_id, wait_until, **zone):
        resp, body = self._update_request(self.resource_base_path,
                                          zone_id, zone)
        # Update Zone should Return a HTTP 202
        self.expected_success(202, resp.status)
        if wait_until:
            waiters.wait_for_zone_status_active(self, body['id'], wait_until)
        return resp, body

    def show_zone(self, zone_id):
        return self._show_request(self.resource_base_path, zone_id)

    def delete_zone(self, zone_id):
        resp, body = self._delete_request(self.resource_base_path, zone_id)
        # Delete Zone should Return a HTTP 202
        self.expected_success(202, resp.status)
        return resp, body

    def list_zones(self):
        return self._list_request(self.resource_base_path)

    def list_recordset_zone(self, zone_id):
        request = self.resource_base_path + '/' + zone_id + '/recordsets'
        resp, body = self._list_request(request)
        return resp, body


class DesignatePtrClient(designate_base.DnsClientBase):
    """
    Request resources via API for Designate PTR RecordSet Client
        PTR recordset show request
    """
    path = "v2/reverse/floatingips/"

    def show_ptr_record(self, ptr_id):
        """
        Show FloatingIP PTR record
        """
        return self._show_request(self.path, ptr_id)

    def set_fip_ptr_record(self, ptr_id, **ptrd):
        """
        Set FloatingIP PTR record
        """
        resp, body = self._update_request(self.path, ptr_id, ptrd)
        return resp, body


class SecretClient(rest_client.RestClient):
    """
    Request resources via API for BarbicanContainerClient
        Barbican Container create request
        Barbican Container update request
        Barbican Container show request
        Barbican Container delete request
        Barbican Container list all request
        Add acl user rule to Barbican Container
    """

    def create_secret(self, **kwargs):
        if 'name' not in kwargs:
            kwargs['name'] = data_utils.rand_name("tempest-sec")

        if 'payload' in kwargs and type(kwargs['payload']) is six.binary_type:
            kwargs['payload'] = kwargs['payload'].decode('utf-8')

        post_body = kwargs
        body = json.dumps(post_body)
        resp, body = self.post("v1/secrets", body)
        self.expected_success(201, resp.status)
        return self._parse_resp(body)

    def delete_secret(self, secret_id):
        resp, body = self.delete("v1/secrets/%s" % secret_id)
        self.expected_success(204, resp.status)
        return body

    def list_secrets(self, **kwargs):
        uri = "v1/secrets"
        if kwargs is not None:
            uri = '{base}?'.format(base=uri)

            for key in kwargs.keys():
                uri = '{base}&{name}={value}'.format(
                    base=uri,
                    name=key,
                    value=kwargs[key]
                )
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def put_secret_payload(self, secret_id, payload):
        content_headers = {
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "base64"
        }
        resp, body = self.put("v1/secrets/%s" % secret_id,
                              payload,
                              headers=content_headers)
        self.expected_success(204, resp.status)
        return body

    def add_acl_user_secret(self, secret_id, user_id):
        kwargs = {"read":
                  {"project-access": True,
                   "users": [user_id]
                   }
                  }
        resp, body = self.put("v1/secrets/%s/acl" % secret_id,
                              json.dumps(kwargs))
        self.expected_success(200, resp.status)
        return body


class ContainerClient(rest_client.RestClient):
    """
    Request resources via API for BarbicanContainerClient
        Barbican Container create request
        Barbican Container update request
        Barbican Container show request
        Barbican Container delete request
        Barbican Container list all request
        Add acl user rule to Barbican Container
    """

    def list_containers(self):
        uri = "v1/containers"
        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def get_container(self, container_id):
        uri = "v1/containers/%s" % container_id

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def create_container(self, **kwargs):
        uri = "v1/containers"

        response, body = self.post(uri, json.dumps(kwargs))
        self.expected_success(201, response.status)
        return json.loads(body.decode("utf-8"))

    def delete_container(self, container_id):
        uri = "v1/containers/%s" % container_id

        response, _ = self.delete(uri)
        self.expected_success(204, response.status)
        return

    def add_acl_user_containers(self, secret_id, user_id):
        kwargs = {"read":
                  {"project-access": True,
                   "users": [user_id]
                   }
                  }
        resp, body = self.put("v1/containers/%s/acl" % secret_id,
                              json.dumps(kwargs))
        self.expected_success(200, resp.status)
        return body


class OctaviaLB_Client(base.BaseNetworkClient):
    """
    The Client takes care of
        Creating LB,
        Deleting LB,
        Returning the status
        Listing the status tree.
    """
    LB_NOTFOUND = "loadbalancer {lb_id} not found"
    resource = 'loadbalancer'
    resource_plural = 'loadbalancers'
    path = 'lbaas/loadbalancers'
    resource_base_path = '/%s' % path
    resource_object_path = '/%s/%%s' % path
    resource_object_status_path = '/%s/%%s/statuses' % path
    resource_object_stats_path = '/%s/%%s/stats' % path

    def create_octavia_load_balancer(self, **kwargs):
        uri = self.resource_base_path
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def show_octavia_load_balancer(self, load_balancer_id, **fields):
        uri = self.resource_object_path % load_balancer_id
        return self.show_resource(uri, **fields)

    def delete_octavia_load_balancer(self, load_balancer_id):
        uri = self.resource_object_path % load_balancer_id
        return self.delete_resource(uri)

    def show_octavia_lb_status_tree(self, load_balancer_id, **fields):
        uri = self.resource_object_status_path % load_balancer_id
        return self.show_resource(uri, **fields)

    def list_octavia_load_balancers(self, **filters):
        uri = self.resource_base_path
        return self.list_resources(uri, **filters)

    def wait_for_load_balancer_status(self, load_balancer_id,
                                      provisioning_status='ACTIVE',
                                      operating_status='ONLINE',
                                      is_delete_op=False):
        """
        This method is helpful to get the info of
        Loadbalancer's status as the octavia process is async
        we need to check the status of lb to be ACTIVE before
        moving ahead.
        """
        LB_NOTFOUND = "loadbalancer {lb_id} not found"
        interval_time = self.build_interval
        timeout = self.build_timeout
        end_time = time.time() + 2 * timeout
        lb = None
        while time.time() < end_time:
            try:
                lb = self.show_octavia_load_balancer(load_balancer_id)
                if not lb:
                    if is_delete_op:
                        break
                    else:
                        raise Exception(
                            LB_NOTFOUND.format(lb_id=load_balancer_id))
                lb = lb.get(self.resource, lb)
                if (lb.get('provisioning_status') == provisioning_status and
                        lb.get('operating_status') == operating_status):
                    break
                time.sleep(interval_time)
            except exceptions.NotFound as e:
                if is_delete_op:
                    break
                else:
                    raise e
        else:
            if is_delete_op:
                raise exceptions.TimeoutException(
                    ("load balancer {lb_id} is still active"
                     "after {timeout} seconds").format(
                        lb_id=load_balancer_id,
                        timeout=timeout))
            else:
                raise exceptions.TimeoutException(
                    ("Wait for load balancer ran for {timeout} seconds and "
                     "did not observe {lb_id} reach {provisioning_status} "
                     "provisioning status and {operating_status} "
                     "operating status.").format(
                        timeout=timeout,
                        lb_id=load_balancer_id,
                        provisioning_status=provisioning_status,
                        operating_status=operating_status))
        return lb


class OctaviaListenersClient(base.BaseNetworkClient):
    """
    The Client is responsible for
        Creating Listener
        Deleting Listener
    """
    resource = 'listener'
    resource_plural = 'listeners'
    path = 'lbaas/listeners'
    resource_base_path = '/%s' % path
    resource_object_path = '/%s/%%s' % path

    def create_octavia_listener(self, **kwargs):
        uri = self.resource_base_path
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def delete_octavia_listener(self, listener_id):
        uri = self.resource_object_path % listener_id
        return self.delete_resource(uri)


class OctaviaPoolsClient(base.BaseNetworkClient):
    """
    The client is responsible for
        Creating pool
        Deleting pool
    """
    resource = 'pool'
    resource_plural = 'pools'
    path = 'lbaas/pools'
    resource_base_path = '/%s' % path
    resource_object_path = '/%s/%%s' % path

    def create_octavia_pool(self, **kwargs):
        uri = self.resource_base_path
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def delete_octavia_pool(self, pool_id):
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        uri = self.resource_object_path % pool_id
        return self.delete_resource(uri)


class OctaviaMembersClient(base.BaseNetworkClient):
    """
    The Client is responsible for
        Creating members for the pool
        Deleting members from the pool
    """
    resource = 'member'
    resource_plural = 'members'
    path = 'lbaas/members'
    resource_base_path = '/lbaas/pools/%s/members'
    resource_object_path = '/lbaas/pools/%s/members/%s'

    def create_octavia_member(self, pool_id, **kwargs):
        uri = self.resource_base_path % pool_id
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def delete_octavia_member(self, pool_id, member_id):
        uri = self.resource_object_path % (pool_id, member_id)
        return self.delete_resource(uri)

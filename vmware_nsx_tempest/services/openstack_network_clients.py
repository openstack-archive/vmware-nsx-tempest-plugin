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
from oslo_log import log

from tempest import config
from tempest.lib.services.network import base

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.common import waiters
from vmware_nsx_tempest.services import designate_base

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
        request = self.resource_base_path + '/'+ zone_id + '/recordsets' 
        resp, body = self._list_request(request)
        return resp, body

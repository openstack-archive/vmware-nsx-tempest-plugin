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

from tempest.lib.services.network import base

from vmware_nsx_tempest.common import constants

LOG = log.getLogger(__name__)


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

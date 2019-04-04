# Copyright 2019 VMware Inc
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

import base64
from copy import deepcopy
import time

import requests
import six.moves.urllib.parse as urlparse

from oslo_log import log as logging
from oslo_serialization import jsonutils

from vmware_nsx_tempest_plugin.common import constants

requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)


class NSXPClient(object):
    """Base NSXP REST client"""
    API_VERSION = "v1"

    def __init__(self, host, username, password, *args, **kwargs):
        self.host = host
        self.username = username
        self.password = password
        self.version = None
        self.endpoint = None
        self.content_type = "application/json"
        self.accept_type = "application/json"
        self.verify = False
        self.secure = True
        self.interface = "json"
        self.url = None
        self.headers_non_super_admin = self.__set_headers()
        self.headers = deepcopy(self.headers_non_super_admin)
        self.headers_super_admin = self.__set_headers(super_admin=True)
        self.api_version = NSXPClient.API_VERSION

    def __set_endpoint(self, endpoint):
        self.endpoint = endpoint

    def get_endpoint(self):
        return self.endpoint

    def __set_content_type(self, content_type):
        self.content_type = content_type

    def get_content_type(self):
        return self.content_type

    def __set_accept_type(self, accept_type):
        self.accept_type = accept_type

    def get_accept_type(self):
        return self.accept_type

    def __set_api_version(self, api_version):
        self.api_version = api_version

    def get_api_version(self):
        return self.api_version

    def __set_url(self, api=None, secure=None, host=None, endpoint=None):
        api = self.api_version if api is None else api
        secure = self.secure if secure is None else secure
        host = self.host if host is None else host
        endpoint = self.endpoint if endpoint is None else endpoint
        http_type = 'https' if secure else 'http'
        self.url = '%s://%s/policy/api/%s/infra/%s' % \
            (http_type, host, api, endpoint)

    def get_url(self):
        return self.url

    def __set_headers(self, content=None, accept=None, super_admin=False):
        content_type = self.content_type if content is None else content
        accept_type = self.accept_type if accept is None else accept
        auth_cred = self.username + ":" + self.password
        auth = base64.b64encode(auth_cred)
        headers = {}
        headers['Authorization'] = "Basic %s" % auth
        headers['Content-Type'] = content_type
        headers['Accept'] = accept_type
        if super_admin:
            headers['X-Allow-Overwrite'] = 'true'
        return headers

    def get(self, endpoint=None, params=None, cursor=None):
        """
        Basic query method for json API request
        """
        self.__set_url(endpoint=endpoint)
        if cursor:
            op = "&" if urlparse.urlparse(self.url).query else "?"
            self.url += op + "cursor=" + cursor
        response = requests.get(self.url, headers=self.headers,
                                verify=self.verify, params=params)
        return response

    def put(self, endpoint=None, body=None):
        """
        Basic put API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.put(self.url, headers=self.headers,
                                verify=self.verify, data=jsonutils.dumps(body))
        return response

    def ca_put_request(self, component, comp_id, body):
        """
        NSX-T API Put request for certificate Management
        """
        endpoint = ("%s/%s" % (component, comp_id))
        response = self.put(endpoint=endpoint, body=body)
        return response

    def delete(self, endpoint=None, params=None):
        """
        Basic delete API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.delete(self.url, headers=self.headers,
                                   verify=self.verify, params=params)
        return response

    def ca_delete_request(self, component=None, comp_id=None):
        """
        NSX-T API delete request for certificate Management
        """
        endpoint = ("%s/%s" % (component, comp_id))
        response = self.delete(endpoint=endpoint)
        return response

    def delete_super_admin(self, endpoint=None, params=None):
        """
        Basic delete API method for NSX super admin on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.delete(self.url, headers=self.headers_super_admin,
                                   verify=self.verify, params=params)
        return response

    def post(self, endpoint=None, body=None):
        """
        Basic post API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.post(self.url, headers=self.headers,
                                 verify=self.verify,
                                 data=jsonutils.dumps(body))
        return response

    def get_logical_resources(self, endpoint):
        """
        Get logical resources based on the endpoint

        Getting the logical resource based on the end point. Parse the response
        for the cursor. If cursor is present, query url for multiple pages to
        get all the logical resources.
        """
        results = []
        response = self.get(endpoint=endpoint)
        res_json = response.json()
        cursor = res_json.get("cursor")
        if res_json.get("results"):
            results.extend(res_json["results"])
        while cursor:
            page = self.get(endpoint=endpoint, cursor=cursor).json()
            results.extend(page.get("results", []))
            cursor = page.get("cursor")
        return results

    def get_os_resources(self, resources):
        """
        Get all logical resources created by OpenStack
        """
        os_resources = [r for r in resources if 'tags' in r
                        for tag in r['tags']
                        if 'os-project-id' in tag.values()]
        return os_resources

    def get_nsx_resource_by_name(self, nsx_resources, nsx_name):
        """
        Get the NSX component created from OpenStack by name.

        The name should be converted from os_name to nsx_name.
        If found exact one match return it, otherwise report error.
        """
        nsx_resource = [n for n in nsx_resources if
                        n['display_name'] == nsx_name]
        if len(nsx_resource) == 0:
            LOG.warning("Backend nsx resource %s NOT found!", nsx_name)
            return None
        if len(nsx_resource) > 1:
            LOG.error("More than 1 nsx resources found: %s!",
                      nsx_resource)
            return None
        else:
            LOG.info("Found nsgroup: %s", nsx_resource[0])
            return nsx_resource[0]

    def get_transport_zones(self):
        """
        Retrieve all transport zones
        """
        return self.get_logical_resources("/transport-zones")

    def get_logical_routers(self, tier=None):
        """
        Retrieve all the logical routers based on router type. If tier
        is None, it will return all logical routers.
        """
        if tier:
            endpoint = "tier-%ss" % tier
        else:
            endpoint = "tier-1s"
        return self.get_logical_resources(endpoint)

    def get_logical_router(self, os_name, os_uuid):
        """
        Get the logical router based on the os_name and os_uuid provided.
        The name of the logical router shoud follow
            <os_router_name>_<starting_5_uuid>...<trailing_5_uuid>
        Return the logical router if found, otherwise return None.
        """
        if not os_name or not os_uuid:
            LOG.error("Name and uuid of OS router should be present "
                      "in order to query backend logical router created")
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        lrouters = self.get_logical_routers()
        return self.get_nsx_resource_by_name(lrouters, nsx_name)

    def get_ns_groups(self, tenant_id):
        """
        Retrieve all NSGroups on NSX backend
        """
        return self.get_logical_resources("domains/%s/groups" % tenant_id)

    def get_firewall_sections(self, tenant_id=None):
        """
        Retrieve all firewall sections
        """
        return self.get_logical_resources("domains/%s/security-policies" %
                                          tenant_id)

    def get_firewall_section(self, os_name, os_uuid, os_tenant_id=None):
        """
        Get the firewall section by os_name and os_uuid
        """
        if not os_name or not os_uuid:
            LOG.error("Name and uuid of OS security group should be "
                      "present in order to query backend FW section "
                      "created")
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        nsx_firewall_time_counter = 0
        nsx_dfw_section = None
        # wait till timeout or till dfw section
        while nsx_firewall_time_counter < \
                constants.NSX_FIREWALL_REALIZED_TIMEOUT and \
                not nsx_dfw_section:
            nsx_firewall_time_counter += 1
            fw_sections = self.get_firewall_sections(tenant_id=os_tenant_id)
            nsx_dfw_section = self.get_nsx_resource_by_name(fw_sections,
                                                            nsx_name)
            time.sleep(constants.ONE_SEC)
        return nsx_dfw_section

    def get_firewall_section_rules(self, fw_section, tenant_id=None):
        """
        Retrieve all fw rules for a given fw section
        """
        endpoint = "domains/%s/security-policies/%s/rules" % \
            (tenant_id, fw_section['id'])
        return self.get_logical_resources(endpoint)

    def get_firewall_section_rule(self, fw_section, os_uuid,
                                  os_tenant_id=None):
        """
        Get the firewall section rule based on the name
        """
        fw_rules = self.get_firewall_section_rules(fw_section, os_tenant_id)
        nsx_name = os_uuid
        return self.get_nsx_resource_by_name(fw_rules, nsx_name)

    def get_ns_group(self, os_name, os_uuid, os_tenant_id=None):
        """
        Get the NSGroup based on the name provided.
        The name of the nsgroup should follow
            <os_sg_name> - <os_sg_uuid>
        Return nsgroup if found, otherwise return None
        """
        if not os_name or not os_uuid:
            LOG.error("Name and uuid of OS security group should be "
                      "present in order to query backend nsgroup created")
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        nsgroups = self.get_ns_groups(tenant_id=os_tenant_id)
        return self.get_nsx_resource_by_name(nsgroups, nsx_name)

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        return self.get_logical_resources("segments")

    def get_logical_switch(self, os_name, os_uuid):
        """
        Get the logical switch based on the name and uuid provided.

        The name of the logical switch should follow
            <os_network_name>_<first 5 os uuid>...<last 5 os uuid>
        Return logical switch if found, otherwise return None
        """
        if not os_name or not os_uuid:
            LOG.error("Name and uuid of OpenStack L2 network need to be "
                      "present in order to query backend logical switch!")
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        lswitches = self.get_logical_switches()
        return self.get_nsx_resource_by_name(lswitches, nsx_name)

    def get_logical_router_nat_rules(self, lrouter):
        """
        Get all user defined NAT rules of the specific logical router
        """
        if not lrouter:
            LOG.error("Logical router needs to be present in order "
                      "to get the NAT rules")
            return None
        endpoint = "tier-1s/%s/nat/USER/nat-rules" % lrouter['id']
        return self.get_logical_resources(endpoint)

    def get_logical_router_advertisement(self, lrouter):
        """Get logical router advertisement"""
        if not lrouter:
            LOG.error("Logical router needs to be present in order "
                      "to get router advertisement!")
            return None
        endpoint = "/logical-routers/%s/routing/advertisement" % lrouter['id']
        response = self.get(endpoint)
        return response.json()

    def get_qos_profiles(self):
        """
        Get all user defined qos-profiles
        """
        endpoint = "qos-profiles"
        return self.get_logical_resources(endpoint)

    def get_qos_profile(self, os_name, os_uuid):
        """
        Get the qos-profile based on the name and uuid provided.

        The name of the qos-profile should follow
            <os_network_name>_<first 5 os uuid>...<last 5 os uuid>
        Return qos-profile if found, otherwise return None
        """
        if not os_name or not os_uuid:
            LOG.error("Name and uuid of Openstack qos-profile need to be "
                      "present in order to query backend qos-profile!")
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        qos_profile = self.get_qos_profiles()
        return self.get_nsx_resource_by_name(qos_profile, nsx_name)

    def get_logical_ports(self, nsx_network):
        """
        Retrieve all logical ports of segments on NSX backend
        """
        return self.get_logical_resources(
            "segments/%s/ports" % nsx_network['id'])

    def get_logical_port(self, os_name, nsx_network):
        """
        Get the logical port based on the os_name provided.
        The name of the logical port shoud match the os_name.
        Return the logical port if found, otherwise return None.
        """
        if not os_name:
            LOG.error("Name of OS port should be present "
                      "in order to query backend logical port created")
            return None
        lports = self.get_logical_ports(nsx_network)
        return self.get_nsx_resource_by_name(lports, os_name)

    def get_port_qos_profile_binding_map(self, segment_id, port_id):
        """
        Get the qos profile associated with the port.

        Return qos profile id if found, otherwise return None
        """
        if not segment_id or not port_id:
            LOG.error("segment id and port id need to be "
                      "present in order to query backend port QoS Profiles!")
            return None
        endpoint = "segments/%s/ports/%s/port-qos-profile-binding-maps" % (
            segment_id, port_id)
        response = self.get(endpoint)


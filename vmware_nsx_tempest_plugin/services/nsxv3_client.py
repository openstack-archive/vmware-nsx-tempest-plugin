# Copyright 2016 VMware Inc
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


class NSXV3Client(object):
    """Base NSXv3 REST client"""
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
        self.api_version = NSXV3Client.API_VERSION

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
        self.url = '%s://%s/api/%s%s' % (http_type, host, api, endpoint)

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
        endpoint = ("/%s/%s" % (component, comp_id))
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
        endpoint = ("/%s/%s" % (component, comp_id))
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

    def get_transport_zones(self):
        """
        Retrieve all transport zones
        """
        return self.get_logical_resources("/transport-zones")

    def get_logical_ports(self):
        """
        Retrieve all logical ports on NSX backend
        """
        return self.get_logical_resources("/logical-ports")

    def get_logical_port(self, os_name):
        """
        Get the logical port based on the os_name provided.
        The name of the logical port shoud match the os_name.
        Return the logical port if found, otherwise return None.
        """
        if not os_name:
            LOG.error("Name of OS port should be present "
                      "in order to query backend logical port created")
            return None
        lports = self.get_logical_ports()
        return self.get_nsx_resource_by_name(lports, os_name)

    def get_logical_port_info(self, lport):
        """
        Retrieve attributes of a given logical port
        """
        lport_uri = "/logical-ports/%s" % lport

        response = self.get(endpoint=lport_uri)
        res_json = response.json()
        return res_json

    def get_switching_profile(self, switch_profile):
        """
        Retrieve attributes of a given nsx switching profile
        """
        sw_profile_uri = "/switching-profiles/%s" % switch_profile
        response = self.get(endpoint=sw_profile_uri)
        res_json = response.json()
        return res_json

    def get_os_logical_ports(self):
        """
        Retrieve all logical ports created from OpenStack
        """
        lports = self.get_logical_ports()
        return self.get_os_resources(lports)

    def update_logical_port_attachment(self, lports):
        """
        Update the logical port attachment

        In order to delete logical ports, we need to detach
        the VIF attachment on the ports first.
        """
        for p in lports:
            p['attachment'] = None
            endpoint = "/logical-ports/%s" % p['id']
            response = self.put(endpoint=endpoint, body=p)
            if response.status_code != requests.codes.ok:
                LOG.error("Failed to update lport %s", p['id'])

    def cleanup_os_logical_ports(self):
        """
        Delete all logical ports created by OpenStack
        """
        lports = self.get_logical_ports()
        os_lports = self.get_os_resources(lports)
        LOG.info("Number of OS Logical Ports to be deleted: %s",
                 len(os_lports))
        # logical port vif detachment
        self.update_logical_port_attachment(os_lports)
        for p in os_lports:
            endpoint = '/logical-ports/%s' % p['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                LOG.info("Successfully deleted logical port %s", p['id'])
            else:
                LOG.error("Failed to delete lport %(port_id)s, response "
                          "code %(code)s",
                          {'port_id': p['id'], 'code': response.status_code})

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

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        return self.get_logical_resources("/logical-switches")

    def get_logical_switch_profiles(self):
        """
        Retrieve all switching profiles on NSX backend
        """
        return self.get_logical_resources("/switching-profiles")

    def get_switching_profiles(self):
        """
        Retrieve all switching profiles on NSX backend
        """
        return self.get_logical_resources("/switching-profiles")

    def get_bridge_cluster_info(self):
        """
        Get bridge cluster information.

        :return: returns bridge cluster id and bridge cluster name.
        """
        return self.get_logical_resources("/bridge-clusters")

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

    def get_lswitch_ports(self, ls_id):
        """
        Return all the logical ports that belong to this lswitch
        """
        lports = self.get_logical_ports()
        return [p for p in lports if p['logical_switch_id'] is ls_id]

    def get_firewall_sections(self):
        """
        Retrieve all firewall sections
        """
        return self.get_logical_resources("/firewall/sections")

    def get_firewall_section(self, os_name, os_uuid):
        """
        Get the firewall section by os_name and os_uuid
        """
        if not os_name or not os_uuid:
            LOG.error("Name and uuid of OS security group should be "
                      "present in order to query backend FW section "
                      "created")
            return None
        nsx_name = os_name + " - " + os_uuid
        nsx_firewall_time_counter = 0
        nsx_dfw_section = None
        # wait till timeout or till dfw section
        while nsx_firewall_time_counter < \
                constants.NSX_FIREWALL_REALIZED_TIMEOUT and \
                not nsx_dfw_section:
            nsx_firewall_time_counter += 1
            fw_sections = self.get_firewall_sections()
            nsx_dfw_section = self.get_nsx_resource_by_name(fw_sections,
                                                            nsx_name)
            time.sleep(constants.ONE_SEC)
        return nsx_dfw_section

    def get_firewall_section_rules(self, fw_section):
        """
        Retrieve all fw rules for a given fw section
        """
        endpoint = "/firewall/sections/%s/rules" % fw_section['id']
        return self.get_logical_resources(endpoint)

    def get_firewall_section_rule(self, fw_section, os_uuid):
        """
        Get the firewall section rule based on the name
        """
        fw_rules = self.get_firewall_section_rules(fw_section)
        nsx_name = os_uuid
        return self.get_nsx_resource_by_name(fw_rules, nsx_name)

    def get_ns_groups(self):
        """
        Retrieve all NSGroups on NSX backend
        """
        return self.get_logical_resources("/ns-groups")

    def get_neutron_ns_group_id(self):
        """
        Retrieve NSGroup Id
        """
        nsx_nsgroup = self.get_ns_groups()
        for group in nsx_nsgroup:
            if group['display_name'] == 'neutron_excluded_port_nsgroup':
                nsgroup_id = group['id']
                return nsgroup_id

    def get_ns_group_port_members(self, ns_group_id):
        """
        Retrieve NSGroup port members
        """
        endpoint = "/ns-groups/%s/effective-logical-port-members" % ns_group_id
        response = self.get(endpoint=endpoint)
        res_json = response.json()
        return res_json

    def get_ns_group(self, os_name, os_uuid):
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
        nsx_name = os_name + " - " + os_uuid
        nsgroups = self.get_ns_groups()
        return self.get_nsx_resource_by_name(nsgroups, nsx_name)

    def get_logical_routers(self, tier=None):
        """
        Retrieve all the logical routers based on router type. If tier
        is None, it will return all logical routers.
        """
        if tier:
            endpoint = "/logical-routers?router_type=%s" % tier
        else:
            endpoint = "/logical-routers"
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

    def get_logical_router_ports(self, lrouter):
        """
        Get all logical ports attached to lrouter
        """
        endpoint = "/logical-router-ports?logical_router_id=%s" % lrouter['id']
        return self.get_logical_resources(endpoint)

    def get_logical_router_nat_rules(self, lrouter):
        """
        Get all user defined NAT rules of the specific logical router
        """
        if not lrouter:
            LOG.error("Logical router needs to be present in order "
                      "to get the NAT rules")
            return None
        endpoint = "/logical-routers/%s/nat/rules" % lrouter['id']
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

    def get_logical_dhcp_servers(self):
        """
        Get all logical DHCP servers on NSX backend
        """
        return self.get_logical_resources("/dhcp/servers")

    def get_logical_dhcp_server(self, os_name, os_uuid):
        """
        Get the logical dhcp server based on the name and uuid provided.

        The name of the logical dhcp server should follow
            <os_network_name>_<first 5 os uuid>...<last 5 os uuid>
        Return logical dhcp server if found, otherwise return None
        """
        if not os_name or not os_uuid:
            LOG.error("Name and uuid of OpenStack L2 network need to be "
                      "present in order to query backend logical dhcp "
                      "server!")
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        dhcp_servers = self.get_logical_dhcp_servers()
        return self.get_nsx_resource_by_name(dhcp_servers, nsx_name)

    def get_dpd_profiles(self):
        endpoint = "/vpn/ipsec/dpd-profiles"
        return self.get_logical_resources(endpoint)

    def get_ike_profiles(self):
        endpoint = "/vpn/ipsec/ike-profiles"
        return self.get_logical_resources(endpoint)

    def get_ipsec_profiles(self):
        endpoint = "/vpn/ipsec/sessions"
        return self.get_logical_resources(endpoint)

    def get_vpn_services(self):
        endpoint = "/vpn/ipsec/services"
        return self.get_logical_resources(endpoint)

    def get_tunnel_profiles(self):
        endpoint = "/vpn/ipsec/tunnel-profiles"
        return self.get_logical_resources(endpoint)

    def get_peer_endpoints(self):
        endpoint = "/vpn/ipsec/peer-endpoints"
        return self.get_logical_resources(endpoint)

    def get_local_endpoints(self):
        endpoint = "/vpn/ipsec/local-endpoints"
        return self.get_logical_resources(endpoint)

    def get_dhcp_server_static_bindings(self, dhcp_server):
        """
        Get all DHCP static bindings of a logical DHCP server
        """
        endpoint = "/dhcp/servers/%s/static-bindings" % dhcp_server
        return self.get_logical_resources(endpoint)

    def get_md_proxies(self):
        """
        Get md proxies.

        :return: returns list of md proxies information.
        """
        return self.get_logical_resources("/md-proxies")

    def get_nsx_certificate(self):
        """
        Get all certificates registered with backend
        """
        endpoint = "/trust-management/certificates/"
        response = self.get(endpoint)
        return response.json()

    def get_audit_log(self, pattern):
        """
        Obtain audit log from mgmt plane
        log_age_limit include logs not past the age limit in days
        log_filter audit logs should meet the filter cond
        log_filter_type type of log filter
        :return log message relevant to the object id
        """
        body = {}
        endpoint = "/administration/audit-logs?page_size=100"
        body['log_age_limit'] = 1
        body['log_filter'] = pattern
        body['log_filter_type'] = "TEXT"
        response = self.post(endpoint, body)
        return response.json()

    def get_openstack_client_certificate(self):
        """
        Get self signed openstack client certificate
        """
        cert_response = self.get_nsx_certificate()
        i_err = "No certificates in the backend"
        k_err = "Argument does not exist in the certificate"
        #check for empty certificates
        try:
            cert_response['results'][0]
        except Exception:
            LOG.exception(i_err)
            raise
        #check if openstack certificate is enabled
        for cert in cert_response['results']:
            try:
                cert['used_by'][0]['service_types']
                cert["_create_user"]
            except Exception:
                LOG.exception(k_err)
                raise
            if (cert['used_by'][0]['service_types'][0] ==
                'Client Authentication' and cert["_create_user"] == "admin"
                and "'com.vmware.nsx.openstack'"
                in cert['used_by'][0]['node_id']):
                LOG.info('Client certificate created')
                return cert
        LOG.error("Client Certificate not created")
        return None

    def delete_md_proxy(self, uuid):
        """
        Delete md proxies.
        """
        return self.delete_logical_resources("/md-proxies/%s" % uuid)

    def delete_logical_resources(self, endpoint):
        """
        Delete logical resources based on the endpoint.
        """
        response = self.delete(endpoint=endpoint)
        return response.json()

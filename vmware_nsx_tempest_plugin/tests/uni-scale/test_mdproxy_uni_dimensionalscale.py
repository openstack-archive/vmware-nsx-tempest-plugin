# Copyright 2018 VMware Inc
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

import re
import time

from tempest import config
from tempest.lib import decorators

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client
from vmware_nsx_tempest_plugin.services import nsxv_client

from oslo_log import log as logging

CONF = config.CONF
LOG = logging.getLogger(__name__)


class MDUnidimensionalScaleTest(feature_manager.FeatureManager):

    """Test Uni Dimesional Case for
       Max no of Logical-switches attached to Md proxy
       Login to one of the vm and check does mdproxy works or not

    """
    @classmethod
    def setup_clients(cls):
        super(MDUnidimensionalScaleTest, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(MDUnidimensionalScaleTest, cls).resource_setup()
        if CONF.network.backend == "nsxv3":
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        elif CONF.network.backend == "nsxv":
            manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                                   CONF.nsxv.manager_uri).group(0)
            cls.vsm = nsxv_client.VSMClient(
                manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _create_vm_topo(self, network):
        router_mdproxy = self.create_topology_router("router_mdproxy")
        self.create_topology_subnet(
            "subnet_web", network, router_id=router_mdproxy["id"])
        self.create_topology_instance(
            "server_mdproxy_1", [network])

    def _verify_md(self, md_url, expected_value="",
                   sub_result=None, ssh_client=None):
        cmd = "curl " + md_url
        self.exec_cmd_on_server_using_fip(
            cmd, ssh_client=ssh_client, sub_result=sub_result,
            expected_value=expected_value)

    def _get_ssh_client(self):
        ssh_client = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_1"],
            use_password=True)
        return ssh_client

    def _create_scale_logical_switch_with_mdproxy(self, scale):
        # Create networks based on scale number
        md_proxies = self.nsx.get_md_proxies()['results']
        proxy_id = md_proxies[0].get('id')
        for i in range(scale):
            name = 'uniscale-md-%s-net' % i
            network = self.create_topology_network(network_name=name,
                                                   net_name_enhance=False)
            # Check if scale no is less than 2000 then just check md
            # proxy on logical switch
            if i % 100 == 0 and scale < 2001:
                nsx_switches = self.nsx.get_logical_switches()['results']
                scale_switches = [ls for ls in nsx_switches
                                  if name in ls['display_name']]
                self.assertIsNotNone(len(scale_switches))
                switch_id = scale_switches[0].get('id')
                time.sleep(constants.NSX_BACKEND_VERY_SMALL_TIME_INTERVAL)
                # Check md proxy status on logcial switch
                proxy_status = self.nsx.get_mdproxy_logical_switch_status(
                    proxy_id, switch_id)
                # check md proxy shouldn't be none
                self.assertIsNotNone(len(proxy_status))
                # Check md proxy status should be UP
                self.assertEqual(proxy_status["proxy_status"], 'UP')
            # Check if scale no is greater than 2000 then just check md
            # proxy on logical switch and also on some random vm
            elif i % 1000 == 0 and scale > 2001:
                nsx_switches = self.nsx.get_logical_switches()['results']
                scale_switches = [ls for ls in nsx_switches
                                  if name in ls['display_name']]
                self.assertIsNotNone(len(scale_switches))
                switch_id = scale_switches[0].get('id')
                time.sleep(constants.NSX_BACKEND_VERY_SMALL_TIME_INTERVAL)
                # Check md proxy status on logcial switch
                proxy_status = self.nsx.get_mdproxy_logical_switch_status(
                    proxy_id, switch_id)
                # check md proxy shouldn't be none
                self.assertIsNotNone(len(proxy_status))
                # Check md proxy status should be UP
                self.assertEqual(proxy_status["proxy_status"], "UP")
                # Create vm topology
                self._create_vm_topo(network)
                # Create ssh_client to check md proxy on vm
                ssh_client = self._get_ssh_client()
                fixed_ip = \
                    self.topology_servers["server_mdproxy_1"]["floating_ips"][
                        0]["fixed_ip_address"]
                fip = self.topology_servers["server_mdproxy_1"][
                    "floating_ips"][0]["floating_ip_address"]

                # check public ip in Metadata.
                md_url_pubic_ipv4 = constants.MD_BASE_URL + \
                    "latest/meta-data/public-ipv4"
                self._verify_md(md_url=md_url_pubic_ipv4, expected_value=fip,
                                ssh_client=ssh_client)
                # Check local IPv4 in Metadata.
                md_url_local_ipv4 = constants.MD_BASE_URL + \
                    "latest/meta-data/local-ipv4"
                self._verify_md(
                    md_url=md_url_local_ipv4, expected_value=fixed_ip,
                    ssh_client=ssh_client)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c2b264a2-daab-451f-ad3b-12313a390f47')
    def test_create_1k_logical_dhcp_server(self):
        self._create_scale_logical_switch_with_mdproxy(1000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('5ba22b0f-4593-4509-8998-45402ce63406')
    def test_create_2k_logical_dhcp_server(self):
        self._create_scale_logical_switch_with_mdproxy(2000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('ddf3d789-838a-428a-b4fe-765214f0e956')
    def test_create_5k_logical_dhcp_server(self):
        self._create_scale_logical_switch_with_mdproxy(5000)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('ed5441be-a700-45fa-bec1-321100acbb73')
    def test_create_10k_logical_dhcp_server(self):
        self._create_scale_logical_switch_with_mdproxy(10000)

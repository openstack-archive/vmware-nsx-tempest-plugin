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
from oslo_log import log as logging

from tempest import config
from tempest import exceptions
from tempest.lib.common.utils import test_utils

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import appliance_manager

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TrafficManager(appliance_manager.ApplianceManager):
    def check_server_internal_ips_using_floating_ip(
            self, floating_ip, server, address_list, should_connect=True):
        ip_address = floating_ip['floating_ip_address']
        private_key = self.get_server_key(server)
        ssh_source = self.get_remote_client(
            ip_address, private_key=private_key)
        for remote_ip in address_list:
            self.check_remote_connectivity(ssh_source, remote_ip,
                                           should_succeed=should_connect)

    def check_network_internal_connectivity(
            self, network, floating_ip, server, should_connect=True):
        """via ssh check VM internal connectivity:

        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes

        """
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = self.get_internal_ips(server, network, device="network")
        self.check_server_internal_ips_using_floating_ip(
            floating_ip, server, internal_ips, should_connect)

    def check_vm_internal_connectivity(
            self, network, floating_ip, server, should_connect=True):
        # test internal connectivity to the other VM on the same network
        compute_ips = self.get_internal_ips(server, network, device="compute")
        self.check_server_internal_ips_using_floating_ip(
            floating_ip, server, compute_ips, should_connect)

    def using_floating_ip_check_server_and_project_network_connectivity(
            self, server_details, network=None):
        if not network:
            network = server_details.networks[0]
        floating_ip = server_details.floating_ip
        server = server_details.server
        self.check_network_internal_connectivity(network, floating_ip, server)
        self.check_vm_internal_connectivity(network, floating_ip, server)

    def check_cross_network_connectivity(
            self, network1, floating_ip_on_network2, server_on_network2,
            should_connect=False):
        # test internal connectivity to the other VM on the same network
        remote_ips = self.get_internal_ips(server_on_network2, network1,
            device="compute")
        self.check_server_internal_ips_using_floating_ip(
            floating_ip_on_network2, server_on_network2, remote_ips,
            should_connect)

    def verify_server_ssh(self, server, floating_ip=None):
        keypair = self.get_server_key(server)
        if not floating_ip:
            floating_ip = server["floating_ip"]["floating_ip_address"]
        if not floating_ip:
            LOG.error("Without floating ip, failed to verify SSH connectivity")
            raise
        ssh_client = self.get_remote_client(
            ip_address=floating_ip, username=self.ssh_user,
            private_key=keypair)
        return ssh_client

    def exec_cmd_on_server_using_fip(self, cmd, ssh_client=None,
                                    sub_result=None, expected_value=None):
        if not ssh_client:
            ssh_client = self.ssh_client

        def exec_cmd_and_verify_output():
            exec_cmd_retried = 0
            import time
            while exec_cmd_retried < \
                    constants.MAX_NO_OF_TIMES_EXECUTION_OVER_SSH:
                result = ssh_client.exec_command(cmd)
                self.assertIsNotNone(result)
                if not result == "":
                    break
                    exec_cmd_retried += 1
                time.sleep(constants.INTERVAL_BETWEEN_EXEC_RETRY_ON_SSH)
                LOG.info("Tried %s times!!!", exec_cmd_retried)
            if sub_result:
                msg = ("Failed sub result is not in result Subresult: %r "
                       "Result: %r" % (sub_result, result))
                self.assertIn(sub_result, result, msg)
            if expected_value:
                msg = ("Failed expected_value is not in result expected_value:"
                       " %r Result: %r" % (expected_value, result))
                self.assertEqual(expected_value, result, msg)
            return result
        if not test_utils.call_until_true(exec_cmd_and_verify_output,
                                          CONF.compute.build_timeout,
                                          CONF.compute.build_interval):
            raise exceptions.TimeoutException("Timed out while waiting to "
                                              "execute cmd %s on server. " %
                                              cmd)
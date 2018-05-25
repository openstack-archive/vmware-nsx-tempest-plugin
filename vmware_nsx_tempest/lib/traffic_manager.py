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

import os
import shlex
import subprocess
import tempfile
import time
import urllib3

from oslo_log import log as logging

from tempest.common.utils.linux import remote_client
from tempest.common import waiters
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
        ssh_source = self._get_remote_client(
            ip_address, private_key=private_key)
        for remote_ip in address_list:
            self.check_remote_connectivity(ssh_source, remote_ip,
                                           should_succeed=should_connect)

    def wait_server_status(self, client, server_id, state='ACTIVE'):
        if client is None:
            servers_client = self.servers_client
        else:
            servers_client = client
        waiters.wait_for_server_status(servers_client, server_id,
                                       state)
        time.sleep(60)

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
            self, server_details, floating_ip=None, network=None):
        if not network:
            network = server_details.networks[0]
        if not floating_ip:
            floating_ip = server_details.floating_ips[0]
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

    def _get_remote_client(self, ip_address, username=None, private_key=None,
                           use_password=False):
        """Get a SSH client to a remote server

        @param ip_address the server floating or fixed IP address to use
                          for ssh validation
        @param username name of the Linux account on the remote server
        @param private_key the SSH private key to use
        @return a RemoteClient object
        """

        if username is None:
            username = CONF.validation.image_ssh_user
        # Set this with 'keypair' or others to log in with keypair or
        # username/password.
        if CONF.nsxv3.ens or use_password:
            password = CONF.validation.image_ssh_password
            private_key = None
        else:
            password = None
            if private_key is None:
                private_key = self.keypair['private_key']

        linux_client = remote_client.RemoteClient(ip_address, username,
                                                  pkey=private_key,
                                                  password=password)
        try:
            linux_client.validate_authentication()
        except Exception as e:
            message = ('Initializing SSH connection to %(ip)s failed. '
                       'Error: %(error)s' % {'ip': ip_address,
                                             'error': e})
            caller = test_utils.find_test_caller()
            if caller:
                message = '(%s) %s' % (caller, message)
            LOG.exception(message)
            self._log_console_output()
            raise

        return linux_client

    def verify_server_ssh(self, server, floating_ip=None, use_password=False):
        private_key = self.get_server_key(server)
        if not floating_ip:
            floating_ip = server["floating_ips"][0]["floating_ip_address"]
        if not floating_ip:
            LOG.error("Without floating ip, failed to verify SSH connectivity")
            raise
        if CONF.nsxv3.ens or use_password:
            private_key = None
        else:
            private_key = private_key
        ssh_client = self._get_remote_client(
            ip_address=floating_ip, username=self.ssh_user,
            private_key=private_key, use_password=use_password)
        return ssh_client

    def scp_file_to_instance_using_fip(self, src_file, dst_folder, dst_host,
                                       username, pkey):
        dst_folder = "%s@%s:%s" % (username, dst_host, dst_folder)
        cmd = "scp -v -o UserKnownHostsFile=/dev/null " \
              "-o StrictHostKeyChecking=no " \
              "-i %(pkey)s %(file1)s %(dst_folder)s" % {'pkey': pkey,
                                                        'file1': src_file,
                                                        'dst_folder':
                                                        dst_folder}
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

    def query_webserver(self, web_ip):
        try:
            url_path = "http://{0}/".format(web_ip)
            # lbaas servers use nc, might be slower to response
            http = urllib3.PoolManager(retries=10)
            resp = http.request('GET', url_path)
            return resp.data.strip()
        except Exception:
            return None

    def query_ens(self, web_ip):
        wget = "curl http://{0}/".format(web_ip)
        resp = os.popen(wget).read().rstrip()
        if "vm" in resp:
            self.count_response(resp)
        return self.http_cnt

    def do_http_request(self, vip, start_path='', send_counts=None):
        # http_cnt stores no of requests made for each members
        self.http_cnt = {}
        if not CONF.nsxv3.ens:
            for x in range(send_counts):
                resp = self.query_webserver(vip)
                self.count_response(resp)
        else:
            for x in range(send_counts):
                self.http_cnt = self.query_ens(vip)
        # count_response counts the no of requests made for each members
        return self.http_cnt

    def start_web_server(self, protocol_port, server, server_name=None):
        """start server's web service which return its server_name."""
        fip_data = server.get('floating_ips')[0]
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
                self.scp_file_to_instance_using_fip(script.name,
                                                    "/tmp/script",
                                                    fip, "cirros",
                                                    key.name)
        # Start netcat
        start_server = ('while true; do '
                        'sudo nc -ll -p %(port)s -e sh /tmp/%(script)s; '
                        'done > /dev/null &')
        cmd = start_server % {'port': constants.HTTP_PORT,
                              'script': 'script'}
        ssh_client.exec_command(cmd)

    def exec_cmd_on_server_using_fip(self, cmd, ssh_client=None,
                                     sub_result=None, expected_value=None):
        if not ssh_client:
            ssh_client = self.ssh_client

        def exec_cmd_and_verify_output():
            exec_cmd_retried = 0
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


class IperfManager(TrafficManager):

    traffic = 'tcp'

    def set_iperf_server(self, ssh_source, traffic_type):
        # set up iperf server on VM
        LOG.info("Check if iperf is installed")
        cmd = ('iperf -v 2>&1 || true')
        response = ssh_source.exec_command(cmd)
        if "command not found" in response:
            raise Exception('IPERF not installed')
        LOG.info("Setting up iperf server")
        if traffic_type == 'udp':
            self.traffic = 'udp'
            cmd = ('iperf -p 49162 -s -u > /dev/null 2>&1 &')
        else:
            cmd = ('iperf -p 49162 -s  > /dev/null 2>&1 &')
        ssh_source.exec_command(cmd)

    def set_iperf_client(self, ssh_source, destination_ip,
                         traffic_send_rate='1', traffic_duration='1'):
        """set up iperf client"""

        if self.traffic == 'udp':
            cmd = ('iperf -p 49162 -c %s -b %sM -t 1 -u | grep %%'
                   % (unicode(destination_ip), unicode(traffic_send_rate)))
        else:
            cmd = ('iperf -p 49162 -c %s -b %sM -t 1 '
                   % (unicode(destination_ip), unicode(traffic_send_rate)))
        output = ssh_source.exec_command(cmd)
        if output is None or float(output.split()[7]) < 0:
            LOG.error('Incorrect IPERF output %s' % output)
            return -1
        else:
            return output.split()[7]

    def kill_iperf_process(self, ssh_source):
        """To kill iperf process on server"""
        cmd = ('ps -ef | grep iperf ')
        output = ssh_source.exec_command(cmd)
        for line in output.splitlines():
            if 'iperf -p 49162 -s' in line:
                LOG.info("Killing iperf process")
                iperf_process_id = line.split()[1]
                cmd = ('kill %s' % (unicode(iperf_process_id)))
                ssh_source.exec_command(cmd)

    def kill_tcpdump_process(self, ssh_source):
        """To kill tcpdump process"""
        cmd = ('ps -ef | grep tcpdump')
        output = ssh_source.exec_command(cmd)
        for line in output.splitlines():
            if 'tcpdump -ni eth0 -w' in line:
                LOG.info("Killing TCPDUMP process")
                tcpdump_process_id = line.split()[1]
                cmd = ('kill %s' % (unicode(tcpdump_process_id)))
                ssh_source.exec_command(cmd)

    def use_iperf_send_traffic(
            self, src_server, dst_server, send_rate=None, traffic_type=None):
        """To send iperf traffic between src server and dst server
        and capture the received traffic at the destination
        """
        src_ssh_source = self._get_remote_client(
            ip_address=src_server["floating_ips"][0]["floating_ip_address"],
            use_password=True)
        dst_ssh_source = self._get_remote_client(
            ip_address=dst_server["floating_ips"][0]["floating_ip_address"],
            use_password=True)
        # set up iperf server on destination VM
        self.set_iperf_server(dst_ssh_source, traffic_type)
        # set up iperf client on source VM
        dst_fixed_ip = dst_server['floating_ips'][0]['fixed_ip_address']
        traffic_send_rate = send_rate
        # To make sure connection established properly
        try:
            bandwidth_value = self.set_iperf_client(
                src_ssh_source, dst_fixed_ip, traffic_send_rate, traffic_type)
        except BaseException:
            self.kill_iperf_process(dst_ssh_source)
            return ''
        # kill the iperf process on destination VM
        self.kill_iperf_process(dst_ssh_source)
        return bandwidth_value

    def capture_iperf_traffic_dscp(
            self, src_server, dst_server,
            send_dscp, interface, traffic_type):
        """To send iperf traffic between src server and dst server
        capture the dscp value of ip packet received
        """
        src_ssh_source = self._get_remote_client(
            ip_address=src_server["floating_ips"][0]["floating_ip_address"],
            use_password=True)
        dst_ssh_source = self._get_remote_client(
            ip_address=dst_server["floating_ips"][0]["floating_ip_address"],
            use_password=True)
        timestamp = time.strftime("%Y-%m-%d_%H:%M:%S")
        dscp_filename = 'dscp_' + timestamp + '.pcap'
        # To capture packets from interface
        cmd = ('echo \"%s\" | sudo -S tcpdump -ni %s'
               ' -w %s > /dev/null 2>&1 &'
               % (CONF.validation.image_ssh_password,
                  interface, dscp_filename))
        dst_ssh_source.exec_command(cmd)
        # set up iperf server on destination VM
        self.set_iperf_server(dst_ssh_source, traffic_type)
        # set up iperf client on source VM
        dst_fixed_ip = dst_server['floating_ips'][0]['fixed_ip_address']
        self.set_iperf_client(src_ssh_source,
                              dst_fixed_ip)
        # Kill iperf process on destination VM
        self.kill_iperf_process(dst_ssh_source)
        # kill tcpdump process on destination VM
        self.kill_tcpdump_process(src_ssh_source)
        # To copy pcap (packet capture) file from destination VM to external VM
        cmd = ('sshpass -p  \"%s\" scp -o StrictHostKeyChecking=no'
               ' %s@%s:/home/%s/%s .'
               % (CONF.validation.image_ssh_password,
                  CONF.validation.image_ssh_user,
                  dst_server['floating_ips'][0]['floating_ip_address'],
                  CONF.validation.image_ssh_user, dscp_filename))
        try:
            subprocess.check_call(cmd, shell=True, executable='/bin/bash',
                                  stderr=subprocess.STDOUT)
        except Exception as e:
            message = ('Failed to copy file from VM.'
                       'Error: %(error)s' % {'error': e})
            LOG.exception(message)
            raise
        return dscp_filename

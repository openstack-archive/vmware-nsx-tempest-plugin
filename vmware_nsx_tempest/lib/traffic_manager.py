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

from vmware_nsx_tempest.lib import appliance_manager


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

    def use_iperf_send_traffic(
            self, src_server, dst_server, send_rate, traffic_type=None):
        """To send iperf traffic between src server and dst server
        for udp traffic specify -u option, default is tcp for iperf traffic
        """
        src_ip_address = src_server['floating_ip']['floating_ip_address']
        src_private_key = self.get_server_key(src_server)
        src_ssh_source = self.get_remote_client(src_ip_address,
            private_key=src_private_key)
        dst_ip_address = dst_server['floating_ip']['floating_ip_address']
        dst_private_key = self.get_server_key(dst_server)
        dst_ssh_source = self.get_remote_client(dst_ip_address,
            private_key=dst_private_key)
        # set up iperf server on destination VM
        if traffic_type == 'udp':
            cmd = ('iperf -p 49162 -s -u > /dev/null 2>&1 &')
        else:
            cmd = ('iperf -p 49162 -s  > /dev/null 2>&1 &')
        dst_ssh_source.exec_command(cmd)
        # set up iperf client on source VM
        dst_internal_ip_address = dst_server['floating_ip']['fixed_ip_address']
        if traffic_type == 'udp':
            cmd = ('iperf -p 49162 -c %s -b %sM -t 1 -u | grep %%'
                   % (unicode(dst_internal_ip_address), unicode(send_rate)))
        else:
            cmd = ('iperf -p 49162 -c %s -b %sM -t 1 | grep %%'
                   % (unicode(dst_internal_ip_address), unicode(send_rate)))
        output = src_ssh_source.exec_command(cmd)
        bandwidth_value = output.split()[7]
        # kill the iperf process on destination VM
        cmd = ('ps -ef | grep iperf ')
        output = dst_ssh_source.exec_command(cmd)
        for line in output.splitlines():
            if 'iperf -p 49162 -s -u' not in line:
                continue
            else:
                iperf_process_id = line.split()[1]
                cmd = ('kill %s' % (unicode(iperf_process_id)))
                dst_ssh_source.exec_command(cmd)
        return bandwidth_value

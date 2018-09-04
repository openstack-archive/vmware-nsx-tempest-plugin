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

from tempest.common import utils
from tempest import config
from tempest.lib import decorators

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestMDProxy(feature_manager.FeatureManager):

    """Test MDProxy.

    Adding test cases to test MDProxy in different scenarios such as
    testing it over multiple created networks, verify MDProxy realization
    with nsxv3 backend, test MDProxy with isolated network and so on.
    """

    @classmethod
    def skip_checks(cls):
        super(TestMDProxy, cls).skip_checks()
        if not CONF.nsxv3.native_dhcp_metadata:
            msg = " native_dhcp_metadata is not enabled under nsxv3 config" \
                  ", skipping all the MDProxy tests!!!"
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        cls.admin_mgr = cls.get_client_manager('admin')
        super(TestMDProxy, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestMDProxy, cls).setup_clients()
        cls.nsx = nsxv3_client.NSXV3Client(
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)

    def _verify_md(self, md_url, expected_value="",
                   sub_result=None, ssh_client=None):
        cmd = "curl " + md_url
        self.exec_cmd_on_server_using_fip(
            cmd, ssh_client=ssh_client, sub_result=sub_result,
            expected_value=expected_value)

    def verify_metadata_in_detail(self, instance, ssh_client, floatingip,
                                  fixed_ip):
        # Check floating IPv4 in Metadata.
        md_url_pubic_ipv4 = constants.MD_BASE_URL + \
            "latest/meta-data/public-ipv4"
        instance_name = instance["name"].replace("_", "-")
        self._verify_md(md_url=md_url_pubic_ipv4, expected_value=floatingip,
                        ssh_client=ssh_client)
        # Check hostname in Metadata.
        md_url_hostname = constants.MD_BASE_URL + "latest/meta-data/hostname"
        self._verify_md(md_url=md_url_hostname,
                        expected_value=instance_name + ".novalocal",
                        ssh_client=ssh_client)
        # Check local IPv4 in Metadata.
        md_url_local_ipv4 = constants.MD_BASE_URL + \
            "latest/meta-data/local-ipv4"
        self._verify_md(md_url=md_url_local_ipv4, expected_value=fixed_ip,
                        ssh_client=ssh_client)
        # Check hostname in Metadata of 2009-04-04 folder.
        md_url_hostname = constants.MD_BASE_URL + \
            "2009-04-04/meta-data/hostname"
        self._verify_md(md_url=md_url_hostname,
                        expected_value=instance_name + ".novalocal",
                        ssh_client=ssh_client)
        # Check hostname in Metadata of 1.0 folder.
        md_url_hostname = constants.MD_BASE_URL + "1.0/meta-data/hostname"
        self._verify_md(md_url=md_url_hostname,
                        expected_value=instance_name + ".novalocal",
                        ssh_client=ssh_client)

    def verify_md_proxy_logical_ports_on_backend(self, tenant_id, network_id):
        md_counter = 0
        logical_ports = self.nsx.get_os_logical_ports()
        for port_index in range(len(logical_ports)):
            if "attachment" in logical_ports[port_index]:
                if logical_ports[port_index]["attachment"][
                        "attachment_type"] == "METADATA_PROXY":
                    if logical_ports[port_index][
                            "tags"][0]["tag"] == network_id:
                        msg = "MDproxy logical port does not "\
                              "have proper tenant "\
                              "id!!!"
                        self.assertEqual(
                            tenant_id, logical_ports[port_index]["tags"][1][
                                "tag"], msg)
                        md_counter += 1
                    msg1 = "Admin state of MDProxy logical port is DOWN!!!"
                    msg2 = "LS name does not start with mdproxy!!!"
                    msg3 = "MDproxy logical port does not have any auto tag!!!"
                    msg4 = "MDproxy logical port does not have scope tag as " \
                        "os-neutron-net-id!!!"
                    msg5 = "MDproxy logical port does not have scope tag as " \
                        "os-project-id!!!"
                    msg6 = "MDproxy logical port does not have scope tag as " \
                        "os-project-name!!!"
                    msg7 = "MDproxy logical port does not have scope tag as " \
                        "os-api-version!!!"
                    self.assertEqual(
                        "UP", logical_ports[port_index]["admin_state"], msg1)
                    self.assertIn("mdproxy-",
                                  logical_ports[port_index]["display_name"],
                                  msg2)
                    self.assertNotEqual(
                        0,
                        len(logical_ports[port_index]["tags"]),
                        msg3)
                    self.assertEqual(
                        "os-neutron-net-id",
                        logical_ports[port_index]["tags"][0]["scope"],
                        msg4)
                    self.assertEqual(
                        "os-project-id",
                        logical_ports[port_index]["tags"][1]["scope"],
                        msg5)
                    self.assertEqual(
                        "os-project-name",
                        logical_ports[port_index]["tags"][2]["scope"],
                        msg6)
                    self.assertEqual(
                        "os-api-version",
                        logical_ports[port_index]["tags"][3]["scope"],
                        msg7)
        self.assertNotEqual(0, md_counter, "No logical port found for MD "
                                           "proxy!!!")

    def deploy_mdproxy_topology(self, glance_image_id=None):
        router_mdproxy = self.create_topology_router("router_mdproxy")
        network_mdproxy = self.create_topology_network("network_mdproxy")
        self.create_topology_subnet(
            "subnet_web", network_mdproxy, router_id=router_mdproxy["id"])
        self.create_topology_instance(
            "server_mdproxy_1", [network_mdproxy], image_id=glance_image_id)

    def deploy_mdproxy_topology_2(self):
        network_mdproxy = self.create_topology_network("network_mdproxy")
        self.create_topology_subnet(
            "subnet_web", network_mdproxy)
        self.create_topology_instance(
            "server_mdproxy_1", [network_mdproxy], create_floating_ip=False)

    def deploy_mdproxy_topology_3(self):
        router_mdproxy = self.create_topology_router("router_mdproxy")
        network_mdproxy_1 = self.create_topology_network("network_mdproxy_1")
        self.create_topology_subnet(
            "subnet_web_1", network_mdproxy_1, router_id=router_mdproxy["id"])
        self.create_topology_instance(
            "server_mdproxy_1", [network_mdproxy_1])
        network_mdproxy_2 = self.create_topology_network("network_mdproxy_2")
        self.create_topology_subnet("subnet_web_2", network_mdproxy_2,
                                    router_id=router_mdproxy["id"])
        self.create_topology_instance("server_mdproxy_2", [network_mdproxy_2])

    def metadata_test_on_various_glance_image(self, image_id):
        self.deploy_mdproxy_topology(glance_image_id=image_id)
        # Verify ssh, detailed metadata and verify backend data
        ssh_client = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_1"],
            use_password=True)
        fixed_ip = \
            self.topology_servers["server_mdproxy_1"]["floating_ips"][0][
                "fixed_ip_address"]
        fip = self.topology_servers["server_mdproxy_1"]["floating_ips"][0][
            "floating_ip_address"]
        self.verify_metadata_in_detail(
            instance=self.topology_servers["server_mdproxy_1"],
            ssh_client=ssh_client, floatingip=fip, fixed_ip=fixed_ip)
        tenant_id = self.topology_networks["network_mdproxy"]["tenant_id"]
        network_id = self.topology_networks["network_mdproxy"]["id"]
        self.verify_md_proxy_logical_ports_on_backend(tenant_id, network_id)

    @decorators.idempotent_id("e9a93161-d852-414d-aa55-36d465ea45df")
    @utils.services("compute", "network")
    def test_mdproxy_ping(self):
        self.deploy_mdproxy_topology()
        # Verify ssh connection and basic mdproxy data.
        ssh_client = self.verify_server_ssh(server=self.topology_servers[
            "server_mdproxy_1"])
        md_url_pubic_ipv4 = constants.MD_BASE_URL + \
            "latest/meta-data/public-ipv4"
        fip = self.topology_servers["server_mdproxy_1"][
            "floating_ips"][0]["floating_ip_address"]
        self._verify_md(md_url=md_url_pubic_ipv4, expected_value=fip,
                        ssh_client=ssh_client)

    @decorators.idempotent_id("743f34a6-58b8-4288-a07f-7bee21c55051")
    @utils.services("compute", "network")
    def test_mdproxy_verify_backend(self):
        self.deploy_mdproxy_topology()
        # Verify ssh, detailed metadata and verify backend data
        ssh_client = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_1"])
        fixed_ip = self.topology_servers["server_mdproxy_1"]["floating_ips"][
            0]["fixed_ip_address"]
        fip = self.topology_servers["server_mdproxy_1"]["floating_ips"][0][
            "floating_ip_address"]
        self.verify_metadata_in_detail(
            instance=self.topology_servers["server_mdproxy_1"],
            ssh_client=ssh_client, floatingip=fip, fixed_ip=fixed_ip)
        tenant_id = self.topology_networks["network_mdproxy"]["tenant_id"]
        network_id = self.topology_networks["network_mdproxy"]["id"]
        self.verify_md_proxy_logical_ports_on_backend(tenant_id, network_id)

    @decorators.skip_because(bug="2004971")
    @decorators.idempotent_id("fce2acc8-b850-40fe-bf02-958dd3cd4343")
    @utils.services("compute", "network")
    def test_mdproxy_with_server_on_two_ls(self):
        router_mdproxy = self.create_topology_router("router_mdproxy")
        network_mdproxy = self.create_topology_network("network_mdproxy")
        self.create_topology_subnet("subnet_web", network_mdproxy,
                                    router_id=router_mdproxy["id"])
        network2_mdproxy = self.create_topology_network("network2_mdproxy")
        self.create_topology_subnet("subnet2_web", network2_mdproxy,
                                    router_id=router_mdproxy["id"])
        # Instance has 2 network ports.
        self.create_topology_instance(
            "server_mdproxy_1", [network_mdproxy, network2_mdproxy])
        floating_ip_1 = self.topology_servers["server_mdproxy_1"][
            "floating_ips"][0]["floating_ip_address"]
        fixed_ip_1 = self.topology_servers["server_mdproxy_1"][
            "floating_ips"][0]["fixed_ip_address"]
        ssh_client1 = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_1"],
            floating_ip=floating_ip_1)
        floating_ip_2 = self.topology_servers["server_mdproxy_1"][
            "floating_ips"][1]["floating_ip_address"]
        self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_1"],
            floating_ip=floating_ip_2)
        self.verify_metadata_in_detail(
            instance=self.topology_servers["server_mdproxy_1"],
            ssh_client=ssh_client1, floatingip=floating_ip_1,
            fixed_ip=fixed_ip_1)

    @decorators.idempotent_id("67332752-1295-42cb-a8c3-99210fb6b00b")
    @utils.services("compute", "network")
    def test_mdproxy_isolated_network(self):
        # Deploy topology without tier1 router
        self.deploy_mdproxy_topology_2()
        tenant_id = self.topology_networks["network_mdproxy"]["tenant_id"]
        network_id = self.topology_networks["network_mdproxy"]["id"]
        # Verify MDProxy logical ports on Backend
        self.verify_md_proxy_logical_ports_on_backend(tenant_id, network_id)

    @decorators.idempotent_id("cc8d2ab8-0bea-4e32-bf80-c9c46a7612b7")
    @decorators.attr(type=["negative"])
    @utils.services("compute", "network")
    def test_mdproxy_delete_when_ls_bounded(self):
        self.deploy_mdproxy_topology_2()
        md_proxy_uuid = self.nsx.get_md_proxies()[0]["id"]
        result = self.nsx.delete_md_proxy(md_proxy_uuid)
        # Delete mdproxy server when it is still attached to LS
        self.assertEqual(str(result["error_code"]),
                         constants.MD_ERROR_CODE_WHEN_LS_BOUNDED)

    @decorators.idempotent_id("501fc3ea-696b-4e9e-b383-293ab94e2545")
    @utils.services("compute", "network")
    def test_mdproxy_with_multiple_ports_on_network(self):
        self.deploy_mdproxy_topology()
        # Boot 2nd vm on same network
        network = self.topology_networks["network_mdproxy"]
        self.create_topology_instance(
            "server_mdproxy_2", [network])
        # Verify Metadata from vm1
        ssh_client_1 = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_1"])
        fixed_ip_1 = self.topology_servers["server_mdproxy_1"][
            "floating_ips"][0][
            "fixed_ip_address"]
        fip_1 = self.topology_servers["server_mdproxy_1"]["floating_ips"][0][
            "floating_ip_address"]
        self.verify_metadata_in_detail(
            instance=self.topology_servers["server_mdproxy_1"],
            ssh_client=ssh_client_1, floatingip=fip_1, fixed_ip=fixed_ip_1)
        # Verify Metadata from vm2
        ssh_client_2 = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_2"])
        fixed_ip_2 = self.topology_servers["server_mdproxy_2"][
            "floating_ips"][0][
            "fixed_ip_address"]
        fip_2 = self.topology_servers["server_mdproxy_2"]["floating_ips"][0][
            "floating_ip_address"]
        self.verify_metadata_in_detail(
            instance=self.topology_servers["server_mdproxy_2"],
            ssh_client=ssh_client_2, floatingip=fip_2, fixed_ip=fixed_ip_2)
        # Verify Metadata on backend
        tenant_id = self.topology_networks["network_mdproxy"]["tenant_id"]
        network_id = self.topology_networks["network_mdproxy"]["id"]
        self.verify_md_proxy_logical_ports_on_backend(tenant_id, network_id)

    @decorators.idempotent_id("eae21afc-50ea-42e5-9c49-2ee38cee9f06")
    @utils.services("compute", "network")
    def test_mdproxy_with_multiple_metadata_ports(self):
        self.deploy_mdproxy_topology_3()
        # Verify 1st instance on the network1
        ssh_client_1 = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_1"])
        fixed_ip_1 = self.topology_servers["server_mdproxy_1"][
            "floating_ips"][0][
            "fixed_ip_address"]
        fip_1 = self.topology_servers["server_mdproxy_1"]["floating_ips"][0][
            "floating_ip_address"]
        self.verify_metadata_in_detail(
            instance=self.topology_servers["server_mdproxy_1"],
            ssh_client=ssh_client_1, floatingip=fip_1, fixed_ip=fixed_ip_1)
        # Verify 2nd instance on the network2
        ssh_client_2 = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_2"])
        fixed_ip_2 = self.topology_servers["server_mdproxy_2"][
            "floating_ips"][0][
            "fixed_ip_address"]
        fip_2 = self.topology_servers["server_mdproxy_2"]["floating_ips"][0][
            "floating_ip_address"]
        self.verify_metadata_in_detail(
            instance=self.topology_servers["server_mdproxy_2"],
            ssh_client=ssh_client_2, floatingip=fip_2, fixed_ip=fixed_ip_2)

    @decorators.idempotent_id("29d44d7c-6ea1-4b30-a6c3-a2695c2486fe")
    @decorators.attr(type=["negative"])
    @utils.services("compute", "network")
    def test_mdproxy_with_incorrect_password(self):
        self.deploy_mdproxy_topology()
        ssh_client = self.verify_server_ssh(
            server=self.topology_servers["server_mdproxy_1"])
        md_url_pubic_ipv4 = constants.MD_BASE_URL + \
            "latest/meta-data/public-ipv4"
        # Query metadata and query should fail
        self._verify_md(md_url=md_url_pubic_ipv4, expected_value="",
                        ssh_client=ssh_client, sub_result="403 Forbidden")

    @decorators.skip_because(bug="2004971")
    @decorators.idempotent_id("74e5d545-3ccc-46c8-9bda-16ccf8730a5b")
    @utils.services("compute", "network")
    def test_mdproxy_with_cirros_kvm_server_image(self):
        image_id = self.get_glance_image_id(["cirros", "kvm"])
        self.metadata_test_on_various_glance_image(image_id)

    @decorators.skip_because(bug="2004971")
    @decorators.idempotent_id("35babffc-f098-4705-82b7-ab96a6f4fdd8")
    @utils.services("compute", "network")
    def test_mdproxy_with_debian_esx_server_image(self):
        image_id = self.get_glance_image_id(["debian", "esx"])
        self.metadata_test_on_various_glance_image(image_id)

    @decorators.skip_because(bug="2004971")
    @decorators.idempotent_id("71ba325f-083b-4247-9192-a9f54d3ecfd2")
    @utils.services("compute", "network")
    def test_mdproxy_with_debian_kvm_server_image(self):
        image_id = self.get_glance_image_id(["debian", "kvm"])
        self.metadata_test_on_various_glance_image(image_id)

    @decorators.skip_because(bug="2004971")
    @decorators.idempotent_id("dfed6074-c4a1-4bf7-a805-80a191ea7875")
    @utils.services("compute", "network")
    def test_mdproxy_with_xenial_esx_server_image(self):
        image_id = self.get_glance_image_id(["xenial", "esx"])
        self.metadata_test_on_various_glance_image(image_id)

    @decorators.skip_because(bug="2004971")
    @decorators.idempotent_id("55829b7f-1535-41d8-833f-b20ac0ee48e0")
    @utils.services("compute", "network")
    def test_mdproxy_with_xenial_kvm_server_image(self):
        image_id = self.get_glance_image_id(["xenial", "kvm"])
        self.metadata_test_on_various_glance_image(image_id)

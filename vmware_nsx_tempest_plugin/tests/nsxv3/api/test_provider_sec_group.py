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
import time

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from tempest import test
from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.services import nsxv3_client

CONF = config.CONF
PROVIDER_SECURITY_GRP = 'provider-sec-group'
LOG = constants.log.getLogger(__name__)


class ProviderSecurityGroupTest(base.BaseAdminNetworkTest):
    """Test Provider Security Group

    1. Only Admin can create provider security group.
    2. Tenants can not create provider security-group.
    3. Check Provider sec group at beckend in firewall section
    4. Check the priority of provider sec groups at beckend
    5. Check non-admin tenant can't create provider security group
    6. Check multiple rules under provider sec group
    """

    @classmethod
    def skip_checks(cls):
        super(ProviderSecurityGroupTest, cls).skip_checks()
        if not test.is_extension_enabled('provider-security-group', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(ProviderSecurityGroupTest, cls).setup_clients()
        cls.cmgr_pri = cls.get_client_manager('primary')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(ProviderSecurityGroupTest, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)
        cls.network = cls.create_network()

    def delete_security_group(self, sg_client, sg_id):
        sg_client.delete_security_group(sg_id)

    def create_security_provider_group(self, cmgr=None,
                                       project_id=None, provider=False):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg_dict = dict(name=data_utils.rand_name(PROVIDER_SECURITY_GRP))
        if project_id:
            sg_dict['tenant_id'] = project_id
        if provider:
            sg_dict['provider'] = True
        sg = sg_client.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_security_group,
                        sg_client, sg.get('id'))
        return sg

    def update_security_provider_group(self, security_group_id,
                                       new_policy_id, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg = sg_client.update_security_group(security_group_id,
                                             policy=new_policy_id)
        return sg.get('security_group', sg)

    def create_security_group_rule(self, security_group_id,
                                   cmgr=None, project_id=None,
                                   protocol=None):
        cmgr = cmgr or self.cmgr_adm
        sgr_client = cmgr.security_group_rules_client
        sgr_dict = dict(security_group_id=security_group_id,
                        direction='ingress', protocol=protocol)
        if project_id:
            sgr_dict['tenant_id'] = project_id
        sgr = sgr_client.create_security_group_rule(**sgr_dict)
        return sgr.get('security_group_rule', sgr)

    def show_security_provider_group(self, security_group_id, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg = sg_client.show_security_group(security_group_id)
        return sg.get('security_group', sg)

    def _wait_till_firewall_gets_realize(self, secgroup, dfw_error_msg=""):
        nsx_firewall_time_counter = 0
        nsx_dfw_section = None
        # wait till timeout or till dfw section
        while nsx_firewall_time_counter < \
                constants.NSX_FIREWALL_REALIZED_TIMEOUT and \
                not nsx_dfw_section:
            nsx_firewall_time_counter += 1
            nsx_nsgroup = self.nsx.get_ns_group(secgroup['name'],
                                                secgroup['id'])
            nsx_dfw_section = self.nsx.get_firewall_section(secgroup['name'],
                                                            secgroup['id'])
            time.sleep(constants.ONE_SEC)
        self.assertIsNotNone(nsx_nsgroup)
        self.assertIsNotNone(nsx_dfw_section, dfw_error_msg)
        return nsx_nsgroup, nsx_dfw_section

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('4fc39f02-4fb1-4e5c-bf64-b98dd7f514f7')
    def test_provider_security_group_at_beckend(self):
        sg = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg_id = sg.get('id')
        sg_name = sg.get('name')
        sg_rule = self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                                  protocol='icmp')
        sg_rule.get('id')
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        self.assertNotEmpty(self.nsx.get_firewall_section(sg_name, sg_id))

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2c8d013d-4c0b-4d2b-b77c-779351a789ce')
    def test_provider_security_group_crud(self):
        sg_desc = "crud provider-security-group"
        sg_client = self.cmgr_adm.security_groups_client
        sg = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg_id = sg.get('id')
        show_sec_group = sg_client.show_security_group(sg_id)
        self.assertEqual(True, show_sec_group['security_group']['provider'],
                         "Provider security group created")
        sg_show = sg_client.update_security_group(sg_id, description=sg_desc)
        self.assertEqual(sg_desc, sg_show['security_group'].get('description'))
        self.delete_security_group(sg_client, sg_id)
        sg_list = sg_client.list_security_groups(id=sg_id)
        sg_list = sg_list.get('security_groups', sg_list)
        self.assertEqual(len(sg_list), 0)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2bc5452f-5673-4dbe-afb3-fb40bf0916a5')
    def test_admin_can_create_provider_security_group_for_tenant(self):
        project_id = self.cmgr_alt.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id,
                                                 provider=True)
        self.assertEqual(True, sg.get('provider'))

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('6ff79516-1e94-4463-9b8c-a524aa806040')
    def test_tenant_provider_sec_group_with_no_rules(self):
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        self.assertEmpty(sg.get('security_group_rules'))

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('a92c8e1e-ce2c-40be-8449-d326690e078e')
    def test_admin_can_create_security_group_rule(self):
        sg_client = self.cmgr_adm.security_groups_client
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        sg_id = sg.get('id')
        self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                        protocol='icmp')
        show_sec_group = sg_client.show_security_group(sg_id)
        self.assertEqual('ingress',
                         show_sec_group['security_group']
                         ['security_group_rules']
                         [0]['direction'])
        self.assertEqual('icmp',
                         show_sec_group['security_group']
                         ['security_group_rules']
                         [0]['protocol'])

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('8e43bd57-e478-490c-8064-4211f2c3eb6c')
    def test_provider_security_group_rule_at_beckend(self):
        sg = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg_id = sg.get('id')
        sg_name = sg.get('name')
        sg_rule = self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                                  protocol='icmp')
        sg_rule.get('id')
        dfw_error_msg = "Firewall section not found for %s!" % sg_name
        self._wait_till_firewall_gets_realize(sg, dfw_error_msg)
        firewall_section = self.nsx.get_firewall_section(sg_name, sg_id)
        output = self.nsx.get_firewall_section_rules(firewall_section)
        self.assertEqual('DROP', output[0]['action'])

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('cf754eba-304f-441c-8402-0dba706fcf62')
    def test_provider_security_group_at_port_level(self):
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        sg_id = sg.get('id')
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "admin_state_up": 'true'}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        ss = port_client.show_port(port_id['port']['id'])
        self.assertEqual([sg_id], ss['port']['provider_security_groups'])
        kwargs = {"provider_security_groups": []}
        port_client.update_port(port_id['port']['id'], **kwargs)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('6271addb-0c60-4548-90f3-5002f4be1985')
    def test_port_with_mac_learning_enabled_psg_and_psec_disabled(self):
        self.create_security_provider_group(self.cmgr_adm,
                                            provider=True)
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "port_security_enabled": "False",
                "security_groups": [],
                "mac_learning_enabled": "True"}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        self.assertEqual(port_id['port']['provider_security_groups'], [])
        self.assertEqual(port_id['port']['security_groups'], [])
        self.assertEqual(port_id['port']['mac_learning_enabled'], True)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('3eaf45af-4505-4dbb-a26f-70bb2d56e2da')
    def test_port_with_mac_learning_psg_and_psec_enabled_disabled(self):
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        sg_id = sg.get('id')
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id']}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        sec_group = port_id['port']['security_groups'][0]
        body = {"port_security_enabled": "True",
                "security_groups": [sec_group],
                "mac_learning_enabled": "False"}
        port_id = port_client.update_port(port_id['port']['id'], **body)
        self.assertEqual(port_id['port']['provider_security_groups'], [sg_id])
        self.assertEqual(port_id['port']['security_groups'], [sec_group])
        body = {"port_security_enabled": "false",
                "security_groups": [],
                "provider_security_groups": [],
                "mac_learning_enabled": "True"}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.update_port(port_id['port']['id'], **body)
        self.assertEqual(port_id['port']['provider_security_groups'], [])
        self.assertEqual(port_id['port']['security_groups'], [])
        self.assertEqual(port_id['port']['mac_learning_enabled'], True)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('c99fe3e9-0d05-4e65-8495-34e8ba534459')
    def test_port_with_mac_learning_enabled_disabled_with_psec_psg(self):
        self.create_security_provider_group(self.cmgr_adm,
                                            provider=True)
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network',
                'port_security_enabled': 'false'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "mac_learning_enabled": "True"}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        self.assertEqual(port_id['port']['provider_security_groups'], [])
        self.assertEqual(port_id['port']['mac_learning_enabled'], True)
        kwargs = {"mac_learning_enabled": "False"}
        port_client.update_port(port_id['port']['id'], **kwargs)
        kwargs = {"mac_learning_enabled": "True"}
        port_client.update_port(port_id['port']['id'], **kwargs)
        self.assertEqual(port_id['port']['mac_learning_enabled'], True)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('d521dd57-66dd-4541-b37d-95cbdf68ae82')
    def test_psg_with_psec_disabled_on_net(self):
        self.create_security_provider_group(self.cmgr_adm,
                                            provider=True)
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network', 'port_security_enabled': 'false'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "provider_security_groups": []}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        self.assertEqual(port_id['port']['provider_security_groups'], [])

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f261e83e-bc3c-4f8c-9b01-cdf86e98cdc8')
    def test_psg_with_psec_disabled_on_net_psg_enabled_on_port(self):
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        sg_id = sg.get('id')
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network',
                'port_security_enabled': 'false'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id']}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        self.assertEqual(port_id['port']['provider_security_groups'], [])
        body = {"provider_security_groups": ["%s" % sg_id]}
        self.assertRaises(exceptions.BadRequest,
                          port_client.update_port, port_id['port']['id'],
                          **body)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f3316650-0725-481b-9140-9a21cc4f0cd6')
    def test_psg_updated_port_level_when_psec_disabled_on_port(self):
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "admin_state_up": 'true'}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        kwargs = {"port_security_enabled": 'false', "security_groups": []}
        port_client.update_port(port_id['port']['id'], **kwargs)
        sg_id = sg.get('id')
        body = {"provider_security_groups": ["%s" % sg_id]}
        self.assertRaises(exceptions.BadRequest,
                          port_client.update_port, port_id['port']['id'],
                          **body)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2c44a134-f013-46b7-a2ec-14c7c38a4d8c')
    def test_multiple_provider_security_group_only_on_newton(self):
        sg = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg_id = sg.get('id')
        self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                        protocol='icmp')
        self.assertRaises(exceptions.BadRequest,
                          self.create_security_provider_group,
                          self.cmgr_adm, provider=True)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f45fc910-db83-4e0c-8ab6-178783626ad3')
    def test_multiple_provider_security_group_on_ocata_plus(self):
        # Ocata plus allows more than 1 provider security group
        sg1 = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg1_id = sg1.get('id')
        # create icmp rule
        self.create_security_group_rule(sg1_id, cmgr=self.cmgr_adm,
                                        protocol='icmp')
        sg2 = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg3 = self.create_security_provider_group(self.cmgr_adm, provider=True)
        self.assertNotEqual(sg1.get('id'), sg2.get('id'))
        self.assertNotEqual(sg2.get('id'), sg3.get('id'))

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('275abe9f-4f01-46e5-bde0-0b6840290d3b')
    def test_provider_sec_group_with_multiple_rules(self):
        project_id = self.cmgr_adm.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id)
        sg_rule1 = self.create_security_group_rule(sg.get('id'),
                                                   cmgr=self.cmgr_adm,
                                                   project_id=project_id,
                                                   protocol='icmp')
        sg_rule1_id = sg_rule1.get('id')
        sg_rule2 = self.create_security_group_rule(sg.get('id'),
                                                   cmgr=self.cmgr_adm,
                                                   project_id=project_id,
                                                   protocol='tcp')
        sg_rule2_id = sg_rule2.get('id')
        self.assertNotEqual(sg_rule1_id, sg_rule2_id)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('5d25370e-da6a-44a7-8565-7b1c2fc39fdc')
    def test_clear_provider_sec_group_from_port(self):
        project_id = self.cmgr_adm.networks_client.tenant_id
        self.create_security_provider_group(self.cmgr_adm,
                                            project_id=project_id,
                                            provider=True)
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "provider_security_groups": []}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        ss = port_client.show_port(port_id['port']['id'])
        self.assertEmpty(ss['port']['provider_security_groups'])
        kwargs = {"provider_security_groups": []}
        port_client.update_port(port_id['port']['id'], **kwargs)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('dfc6bb8e-ba7b-4ce5-b6ee-0d0830d7e152')
    def test_check_security_group_precedence_at_beckend(self):
        project_id = self.cmgr_adm.networks_client.tenant_id
        provider_sg = \
            self.create_security_provider_group(self.cmgr_adm,
                                                project_id=project_id,
                                                provider=True)
        provider_sg_name = provider_sg.get('name')
        self.create_security_provider_group(self.cmgr_adm,
                                            project_id=project_id,
                                            provider=False)
        # Wait till provider sec gets realize in NSX.
        nsx_firewall_time_counter = 0
        provider_sec = False
        while nsx_firewall_time_counter < \
                constants.NSX_FIREWALL_REALIZED_TIMEOUT and not provider_sec:
            nsx_firewall_time_counter += 1
            firewall_sections = self.nsx.get_firewall_sections()
            for section in firewall_sections:
                if provider_sg_name in section['display_name']:
                    provider_sec = True
                    break
            time.sleep(constants.ONE_SEC)
        for section in firewall_sections:
            # when execute tempest in parallel fashion,
            # we create provider security group for other tests,
            # NSX will return all provider security group from DFW.
            if section['applied_tos'][0]['target_type'] == "LogicalRouter":
                continue
            if PROVIDER_SECURITY_GRP in section['display_name'] and \
                    provider_sg_name not in section['display_name']:
                pass
            else:
                # check the sec name
                break
        msg = "Provider group does not have highest priority " \
              "over default security group"
        self.assertIn(provider_sg_name, section['display_name'], msg)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('37d8fbfc-eb3f-40c8-a146-70f5df937a2e')
    def test_tenant_cannot_delete_admin_provider_security_group(self):
        project_id = self.cmgr_adm.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id,
                                                 provider=True)
        sg_id = sg.get('id')
        sg_client = self.cmgr_alt.security_groups_client
        try:
            self.delete_security_group(sg_client, sg_id)
        except Exception:
            LOG.info("Non Admin tenant can't see admin "
                     "provider security group")
            pass

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('1bbebba3-780c-4e95-a95a-e52f577a6c1d')
    def test_tenant_cannot_create_provider_sec_group(self):
        project_id = self.cmgr_alt.networks_client.tenant_id
        self.assertRaises(exceptions.Forbidden,
                          self.create_security_provider_group,
                          self.cmgr_alt, project_id=project_id,
                          provider=True)
        LOG.info("Non-Admin Tenant cannot create provider sec group")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('0d021bb2-9e21-422c-a509-6ac27803b2a2')
    def test_update_port_with_psg(self):
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "provider_security_groups": []}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        ss = port_client.show_port(port_id['port']['id'])
        self.assertEmpty(ss['port']['provider_security_groups'],
                         "Provider security group is not set on port")
        project_id = self.cmgr_adm.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id,
                                                 provider=True)
        sg_id = sg.get('id')
        body = {"provider_security_groups": ["%s" % sg_id]}
        port_client.update_port(port_id['port']['id'], **body)
        ss = port_client.show_port(port_id['port']['id'])
        self.assertEqual([sg_id], ss['port']['provider_security_groups'],
                         "PSG assigned to port is accurate")
        kwargs = {"provider_security_groups": []}
        port_client.update_port(port_id['port']['id'], **kwargs)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2922a7fb-75fb-4d9f-9fdb-4b017c191aba')
    def test_update_port_with_psg_using_different_tenant(self):
        net_client = self.cmgr_alt.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_alt.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "provider_security_groups": []}
        port_client = self.cmgr_alt.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        ss = port_client.show_port(port_id['port']['id'])
        self.assertEmpty(ss['port']['provider_security_groups'],
                         "Provider security group is not set on port")
        project_id = self.cmgr_adm.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id,
                                                 provider=True)
        sg_id = sg.get('id')
        body = {"provider_security_groups": ["%s" % sg_id]}
        self.assertRaises(exceptions.NotFound,
                          port_client.update_port,
                          port_id['port']['id'], **body)
        kwargs = {"provider_security_groups": []}
        port_client.update_port(port_id['port']['id'], **kwargs)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('cef8d816-e5fa-45a5-a5a5-f1f2ed8fb49f')
    def test_tenant_cannot_create_provider_sec_group_for_other_tenant(self):
        tenant_cmgr = self.cmgr_alt
        project_id = tenant_cmgr.networks_client.tenant_id
        self.assertRaises(exceptions.BadRequest,
                          self.create_security_provider_group, self.cmgr_pri,
                          project_id=project_id,
                          provider=True)

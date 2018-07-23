# Copyright 2018 VMware Inc
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


from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest.lib import exceptions as lib_exc
from tempest import test

from vmware_nsx_tempest_plugin.common import constants
from vmware_nsx_tempest_plugin.lib import feature_manager
from vmware_nsx_tempest_plugin.services import nsxv3_client


from oslo_log import log as logging


CONF = config.CONF
CONF.validation.auth_method = 'None'

LOG = logging.getLogger(__name__)


class TestVpnOps(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestVpnOps, cls).skip_checks()
        if not test.is_extension_enabled('vpnaas', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        cls.admin_mgr = cls.get_client_manager('admin')
        super(TestVpnOps, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestVpnOps, cls).setup_clients()
        cls.nsx_client = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                                  CONF.nsxv3.nsx_user,
                                                  CONF.nsxv3.nsx_password)

    def create_network_topo(self, enable_snat="False", cidr=None):
        kwargs = {}
        network = \
            self.create_topology_network(
                network_name="vpn-network",
                networks_client=self.admin_mgr.networks_client)
        router_name = 'vpn-router'
        # Create router topo
        kwargs["enable_snat"] = enable_snat
        routers_client = self.admin_mgr.routers_client
        router = self.create_topology_router(
            router_name, routers_client=routers_client, **kwargs)
        subnet_name = 'vpn-subnet'
        # Create subnet topo
        subnets_client = self.admin_mgr.subnets_client
        if cidr is None:
            subnet = self.create_topology_subnet(subnet_name, network,
                                                 router_id=router['id'],
                                                 subnets_client=subnets_client,
                                                 routers_client=routers_client
                                                 )
        else:
            subnet = self.create_topology_subnet(subnet_name, network,
                                                 router_id=router['id'],
                                                 subnets_client=subnets_client,
                                                 routers_client=routers_client,
                                                 cidr=cidr
                                                 )
        return dict(network=network, subnet=subnet, router=router)

    def create_vpn_basic_topo(
        self, network_topology, name=None, ike=None, pfs=constants.PFS,
        encryption_algorithm=constants.ENCRYPTION_ALGO,
        lifetime=constants.LIFETIME,
        peer_address=constants.PEER_ADDRESS,
        peer_id=constants.PEER_ID,
            site_connection_state=constants.SITE_CONNECTION_STATE):
        # Create network topo
        kwargs = {}
        subnet = network_topology['subnet']
        router = network_topology['router']
        kwargs['vpnservice'] = dict(subnet_id=subnet['id'],
                                    router_id=router['id'],
                                    admin_state_up=site_connection_state,
                                    name="vpn")
        vpn_service = self.vpnaas_client.create_vpnservice(**kwargs)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.vpnaas_client.delete_vpnservice,
            vpn_service.get('vpnservice')['id'])
        self.vpnaas_client.list_vpnservices()
        if ike is None:
            kwargs = {}
            if lifetime is not None:
                kwargs[
                    'ikepolicy'] = \
                    dict(name=data_utils.rand_name("ike-policy-"), pfs=pfs,
                         encryption_algorithm=encryption_algorithm,
                         lifetime=lifetime)

            ike = self.vpnaas_client.create_ikepolicy(**kwargs)
            self.addCleanup(
                test_utils.call_and_ignore_notfound_exc,
                self.vpnaas_client.delete_ikepolicy,
                ike.get('ikepolicy')['id'])
        kwargs = {}
        kwargs[
            'ipsecpolicy'] = dict(name=data_utils.rand_name("ipsec-policy-"),
                                  pfs=pfs)
        ipsec = self.vpnaas_client.create_ipsecpolicy(**kwargs)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.vpnaas_client.delete_ipsecpolicy,
            ipsec.get('ipsecpolicy')['id'])
        kwargs = {}
        if name is not None:
            name = "site-conn-" + name
        else:
            name = "site-conn"
        kwargs[
            "ipsec_site_connection"] = \
            dict(vpnservice_id=vpn_service.get('vpnservice')['id'],
                 psk="secret",
                 admin_state_up=site_connection_state, peer_cidrs=[
                     "10.0.1.0/24"],
                 ikepolicy_id=ike.get(
                     'ikepolicy')['id'],
                 ipsecpolicy_id=ipsec.get(
                     'ipsecpolicy')['id'],
                 peer_address=peer_address,
                 peer_id=peer_id, name=name)
        endpoint = self.vpnaas_client.create_ipsec_site_connection(**kwargs)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.vpnaas_client.delete_ipsec_site_connection,
            endpoint.get("ipsec_site_connection")['id'])
        return dict(endpoint=endpoint, vpn_service=vpn_service,
                    ike=ike, ipsec=ipsec)

    @decorators.idempotent_id('7022b98f-f006-43c0-a1f7-5926035eb2b9')
    def test_create_vpnservice_long_description(self):
        description = 'x' * 256
        network_topology = self.create_network_topo()
        subnet = network_topology['subnet']
        router = network_topology['router']
        kwargs = {}
        kwargs['vpnservice'] = dict(subnet_id=subnet['id'],
                                    router_id=router['id'],
                                    admin_state_up="True",
                                    description=description,
                                    name="vpn")
        self.assertRaises(
            lib_exc.BadRequest, self.vpnaas_client.create_vpnservice, **kwargs)

    @decorators.idempotent_id('a4b0112d-2ab5-4b02-b0ab-562ae2cd4078')
    def test_create_vpnservice_with_router_enable_snat(self):
        network_topology = self.create_network_topo(enable_snat="True")
        subnet = network_topology['subnet']
        router = network_topology['router']
        kwargs = {}
        kwargs['vpnservice'] = dict(subnet_id=subnet['id'],
                                    router_id=router['id'],
                                    admin_state_up="True",
                                    name="vpn")
        self.assertRaises(
            lib_exc.ServerFault, self.vpnaas_client.create_vpnservice, **kwargs
        )

    @decorators.idempotent_id('a68cd562-1df1-44e6-bb8b-f1ed7a1f0e2e')
    def test_vpn_basic_ops(self):
        """
        Test vpnaasv2 api to create icmp rule/policy/group and update it and
        verifying its values
        """
        network_topology = self.create_network_topo()
        self.create_vpn_basic_topo(network_topology)

    @decorators.idempotent_id('5802b98f-f006-43c0-a1f7-5926035eb2b9')
    def test_try_to_delete_vpn_service_when_site_connection_active(self):
        network_topology = self.create_network_topo(cidr="37.5.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology, "test")
        vpn_service = vpn_topo['vpn_service']
        self.assertRaises(
            lib_exc.Conflict, self.vpnaas_client.delete_vpnservice,
            vpn_service.get('vpnservice')['id'])

    @decorators.idempotent_id('4602b98f-f006-43c0-a1f7-5926035eb2b9')
    def test_try_to_delete_ike_when_site_connection_active(self):
        network_topology = self.create_network_topo(cidr="37.6.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology, "test")
        ike = vpn_topo['ike']
        self.assertRaises(
            lib_exc.Conflict, self.vpnaas_client.delete_ikepolicy,
            ike.get('ikepolicy')['id'])

    @decorators.idempotent_id('4502b98f-f006-43c0-a1f7-5926035eb2b9')
    def test_try_to_delete_ipsec_when_site_connection_active(self):
        network_topology = self.create_network_topo(cidr="37.9.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology, "test")
        ipsec = vpn_topo['ipsec']
        self.assertRaises(
            lib_exc.Conflict, self.vpnaas_client.delete_ipsecpolicy,
            ipsec.get('ipsecpolicy')['id'])

    @decorators.idempotent_id('1902b98f-f006-43c0-a1f7-5926035eb2b9')
    def test_delete_vpn_ops(self):
        network_topology = self.create_network_topo(cidr="37.10.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology, "test")
        ipsecpolicy = vpn_topo['ipsec']
        vpnservice = vpn_topo['vpn_service']
        ikepolicy = vpn_topo['ike']
        endpoint = vpn_topo['endpoint']
        self.vpnaas_client.delete_ipsec_site_connection(
            endpoint.get("ipsec_site_connection")['id'])
        self.vpnaas_client.delete_ikepolicy(ikepolicy.get('ikepolicy')['id'])
        self.vpnaas_client.delete_ipsecpolicy(
            ipsecpolicy.get('ipsecpolicy')['id'])
        self.vpnaas_client.delete_vpnservice(
            vpnservice.get('vpnservice')['id'])

    @decorators.idempotent_id('2022b98f-f006-43c0-a1f7-5926035eb2b9')
    def test_peer_endpoint_delete_at_the_backend(self):
        flag = 0
        network_topology = self.create_network_topo(cidr="37.2.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology)
        site = vpn_topo["endpoint"]
        dpd_info = self.nsx_client.get_dpd_profiles()
        peer_endpoints = self.nsx_client.get_peer_endpoints()
        for dpd in dpd_info:
            if dpd is not None and dpd.get("tags"):
                if dpd.get("tags")[0]["tag"] == \
                        site.get('ipsec_site_connection')['id']:
                    dpd_profile = dpd["id"]
                    break
            continue
        for end in peer_endpoints:
            if end.get("tags")[0]["tag"] == \
                    site.get('ipsec_site_connection')['id']:
                if end['dpd_profile_id'] == dpd_profile:
                    flag = 1
                    self.assertEqual(end['peer_id'], '172.24.4.12')
                    self.assertEqual(
                        "IPSecVPNPeerEndpoint",
                        end.get("resource_type"))
                break
            if flag == 0:
                raise Exception('dpd_profile_id doesnt match with endpoint_id')
            if flag == 1:
                break
        flag = 0
        endpoint = vpn_topo['endpoint']
        self.vpnaas_client.delete_ipsec_site_connection(
            endpoint.get("ipsec_site_connection")['id'])
        peer_endpoints = self.nsx_client.get_peer_endpoints()
        for end in peer_endpoints:
            if end.get("tags")[0]["tag"] == \
                   site.get('ipsec_site_connection')['id']:
                if end['dpd_profile_id'] == dpd_profile:
                    flag = 1
                    self.assertEqual(end['peer_id'], '172.24.4.12')
                    self.assertEqual(
                        "IPSecVPNPeerEndpoint",
                        end.get("resource_type"))
        if flag == 1:
            raise Exception('rtr_id doesnt match with endpoint_id')

    @decorators.idempotent_id('1092b98f-f006-43c0-a1f7-5926035eb2b9')
    def test_local_endpoint_delete_at_the_backend(self):
        flag = 0
        network_topology = self.create_network_topo(cidr="37.14.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology)
        local_endpoints = self.nsx_client.get_local_endpoints()
        for local in local_endpoints:
            if local is not None and local.get("tags"):
                if local.get("tags")[0]["tag"] == \
                        network_topology["router"]["id"]:
                    self.assertIsNotNone(local["local_address"])
                    self.assertIsNotNone(local["local_id"])
                    flag = 1
                    break
        if flag == 1:
            pass
        else:
            raise Exception('rtr_id doesnt match with endpoint_id')
        endpoint = vpn_topo['endpoint']
        self.vpnaas_client.delete_ipsec_site_connection(
            endpoint.get("ipsec_site_connection")['id'])
        local_endpoints = self.nsx_client.get_local_endpoints()
        for local in local_endpoints:
            if local is not None and local.get("tags"):
                if local.get("tags")[0]["tag"] == \
                        network_topology["router"]["id"]:
                    self.assertIsNotNone(local["local_address"])
                    self.assertIsNotNone(local["local_id"])
                    flag = 1
                    break
        if flag == 1:
            raise Exception('local endpoint not deleted from backend')

    @decorators.idempotent_id('7022b98f-f006-43c0-a1f7-5926035eb212')
    def test_vpn_service_delete_at_the_backend(self):
        flag = 0
        network_topology = self.create_network_topo(cidr="37.12.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology, "test-delete")
        routers = self.nsx_client.get_logical_routers()
        vpn_services = self.nsx_client.get_vpn_services()
        for rtr in routers:
            for vpn in vpn_services:
                if vpn['logical_router_id'] == rtr["id"]:
                    self.assertEqual(vpn['logical_router_id'], rtr["id"])
                    self.assertEqual(vpn['resource_type'], 'IPSecVPNService')
                    break
                break
        vpnservice = vpn_topo['vpn_service']
        endpoint = vpn_topo['endpoint']
        self.vpnaas_client.delete_ipsec_site_connection(
            endpoint.get("ipsec_site_connection")['id'])
        self.vpnaas_client.delete_vpnservice(
            vpnservice.get('vpnservice')['id'])
        vpn_services = self.nsx_client.get_vpn_services()
        for rtr in routers:
            for vpn in vpn_services:
                if vpn['logical_router_id'] == rtr["id"]:
                    self.assertEqual(vpn['logical_router_id'], rtr["id"])
                    self.assertEqual(vpn['resource_type'], 'IPSecVPNService')
                    flag = 1
                    break
            if flag == 1:
                break
        if flag == 1:
            raise Exception('vpn service not deleted from backend')

    @decorators.idempotent_id('747c5864-409f-4ac4-bdbb-b74d7c618504')
    def test_vpn_dpd_ike_ipsec_check_at_the_backend(self):
        network_topology = self.create_network_topo(cidr="37.0.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology, "test")
        site = vpn_topo["endpoint"]
        dpd_info = self.nsx_client.get_dpd_profiles()
        for dpd in dpd_info:
            if dpd is not None and dpd.get("tags"):
                if dpd.get("tags")[0]["tag"] == \
                        site.get('ipsec_site_connection')['id']:
                    self.assertIn(
                        "site-conn-test-dpd-profile",
                        dpd["display_name"])
                    self.assertEqual(
                        "os-vpn-connection-id",
                        dpd.get("tags")[0]["scope"])
                    break
        ike_info = self.nsx_client.get_ike_profiles()
        for ike in ike_info:
            if ike is not None and ike.get("tags"):
                if ike.get("tags")[0]["tag"] == \
                        site.get('ipsec_site_connection')['id']:
                    self.assertEqual(
                        ike.get('resource_type'),
                        "IPSecVPNIKEProfile")
                    self.assertEqual(
                        ike.get('encryption_algorithms'),
                        [u'AES_128'])
                    self.assertEqual(ike.get('ike_version'), 'IKE_V1')
                    self.assertEqual(ike.get('dh_groups'), [u'GROUP14'])
                    break
        ipsec_info = self.nsx_client.get_ipsec_profiles()
        for ipsec in ipsec_info:
            if ipsec is not None and ipsec.get("tags"):
                if ipsec.get("tags")[0]["tag"] == \
                        site.get('ipsec_site_connection')['id']:
                    self.assertEqual(
                        ipsec.get('resource_type'),
                        "PolicyBasedIPSecVPNSession")
                    cidr = vpn_topo['endpoint'].get(
                        'ipsec_site_connection')['peer_cidrs']
                    peer_cidr = [{u'subnet': u'%s' % cidr[0]}]
                    self.assertEqual(
                        ipsec.get('policy_rules')[0]['destinations'],
                        peer_cidr)
                    self.assertEqual(
                        "os-vpn-connection-id",
                        ipsec.get("tags")[0]["scope"])
                    break

    @decorators.idempotent_id('cdb7333a-94c0-487f-9602-3bd990128a0f')
    def test_vpn_dpd_ike_ipsec_update_at_the_backend(self):
        kwargs = {}
        kwargs[
            'ikepolicy'] = dict(name=data_utils.rand_name("ike-policy-"),
                                pfs=constants.PFS,
                                encryption_algorithm=constants.ENCRYPTION_ALGO,
                                lifetime=constants.LIFETIME)
        ike = self.vpnaas_client.create_ikepolicy(**kwargs)

        kwargs['ikepolicy'] = \
            dict(name="ike-new", ike_version="v2",
                 encryption_algorithm=constants.ENCRYPTION_ALGO_256,
                 auth_algorithm=constants.AUTH_ALGO_256)
        self.vpnaas_client.update_ikepolicy(ike['ikepolicy']['id'],
                                            **kwargs)
        network_topology = self.create_network_topo(cidr="37.1.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(
            network_topology, "test-2", ike=ike)
        ike_info = self.nsx_client.get_ike_profiles()
        site = vpn_topo["endpoint"]
        for ike_p in ike_info:
            if ike_p is not None and ike_p.get("tags"):
                if ike_p.get("tags")[0]["tag"] == \
                        site.get('ipsec_site_connection')['id']:
                    self.assertEqual(ike_p.get('display_name'), "ike-new")
                    self.assertEqual(ike_p.get('ike_version'), "IKE_V2")
                    self.assertEqual(
                        ike_p.get('encryption_algorithms'),
                        [u'AES_256'])
                    self.assertEqual(
                        ike_p.get('digest_algorithms'),
                        [u'SHA2_256'])
                    break

    @decorators.idempotent_id('a0a87543-fb0a-4c7a-897f-b5cd835de843')
    def test_vpn_service_update_at_the_backend(self):
        flag = 0
        network_topology = self.create_network_topo(cidr="37.1.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology, "test-4")
        routers = self.nsx_client.get_logical_routers()
        vpn_services = self.nsx_client.get_vpn_services()
        kwargs = {}
        kwargs['vpnservice'] = dict(name="vpn-new", admin_state_up='false')
        self.vpnaas_client.update_vpnservice(
            vpn_topo['vpn_service'].get('vpnservice')['id'],
            **kwargs)
        for rtr in routers:
            for vpn in vpn_services:
                if vpn['logical_router_id'] == rtr["id"]:
                    self.assertEqual(vpn['logical_router_id'], rtr["id"])
                    self.assertEqual(vpn['resource_type'], 'IPSecVPNService')
                    self.assertEqual(vpn['enabled'], True)
                    flag = 1
                    break
            if flag == 1:
                break

    # ToDO testcase need to add
    # def test_vpn_site_update_at_the_backend

    @decorators.idempotent_id('00c8679d-68cd-49a9-b8b7-0dba1b675298')
    def test_vpn_service_check_at_the_backend(self):
        flag = 0
        network_topology = self.create_network_topo(cidr="37.1.0.0/24")
        self.create_vpn_basic_topo(network_topology, "test-2")
        routers = self.nsx_client.get_logical_routers()
        vpn_services = self.nsx_client.get_vpn_services()
        for rtr in routers:
            for vpn in vpn_services:
                if vpn['logical_router_id'] == rtr["id"]:
                    self.assertEqual(vpn['logical_router_id'], rtr["id"])
                    self.assertEqual(vpn['resource_type'], 'IPSecVPNService')
                    flag = 1
                    break
            if flag == 1:
                break
        tunnel_profiles = self.nsx_client.get_tunnel_profiles()
        for tunnel in tunnel_profiles:
            if tunnel is not None and tunnel.get("tags"):
                if tunnel.get("tags")[0]["tag"] == tunnel['id']:
                    self.assertEqual(
                        "IPSecVPNTunnelProfile",
                        tunnel.get("resource_type"))
                    self.assertEqual("ESP", tunnel.get("transform_protocol"))
                    self.assertEqual(
                        [u'AES_128'],
                        tunnel.get("encryption_algorithms"))
                    self.assertEqual(
                        "TUNNEL_MODE",
                        tunnel.get("encapsulation_mode"))
                    self.assertEqual(tunnel.get('dh_groups'), [u'GROUP14'])
                    break

    @decorators.idempotent_id('f446a67a-4d09-4d5f-adff-cc497882d866')
    def test_vpn_site_connection_at_the_backend(self):
        flag = 1
        network_topology = self.create_network_topo(cidr="37.2.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topology)
        site = vpn_topo["endpoint"]
        dpd_info = self.nsx_client.get_dpd_profiles()
        peer_endpoints = self.nsx_client.get_peer_endpoints()
        for dpd in dpd_info:
            if dpd is not None and dpd.get("tags"):
                if dpd.get("tags")[0]["tag"] == \
                        site.get('ipsec_site_connection')['id']:
                    dpd_profile = dpd["id"]
                    break
            continue
        for end in peer_endpoints:
            if end.get("tags")[0]["tag"] == \
                      site.get('ipsec_site_connection')['id']:
                if end['dpd_profile_id'] == dpd_profile:
                    flag = 1
                    self.assertEqual(end['peer_id'], '172.24.4.12')
                    self.assertEqual(
                        "IPSecVPNPeerEndpoint",
                        end.get("resource_type"))
                    break
            if flag == 0:
                raise Exception('dpd_profile_id doesnt match with endpoint_id')
            if flag == 1:
                break
        flag = 0
        local_endpoints = self.nsx_client.get_local_endpoints()
        for local in local_endpoints:
            if local is not None and local.get("tags"):
                if local.get("tags")[0]["tag"] == \
                        network_topology["router"]["id"]:
                    self.assertIsNotNone(local["local_address"])
                    self.assertIsNotNone(local["local_id"])
                    flag = 1
                    break
        if flag == 1:
            pass
        else:
            raise Exception('rtr_id doesnt match with endpoint_id')

    @decorators.idempotent_id('eb953c67-8d8a-4ac5-b7c3-3c18270b50ce')
    def test_vpn_basic_invalid_pfs(self):
        network_topology = self.create_network_topo()
        try:
            self.create_vpn_basic_topo(network_topology, pfs="group5")
        except exceptions.ServerFault:
            LOG.info(
                "Invalid VPN configuration: Unsupported pfs: "
                " group5 in IKE policy.")
            pass

    @decorators.idempotent_id('1c034ea4-d8e6-41d0-b963-33dd5053476b')
    def test_vpn_basic_algo_aes256(self):
        network_topology = self.create_network_topo()
        try:
            self.create_vpn_basic_topo(
                network_topology,
                encryption_algorithm="aes-256")
        except exceptions.ServerFault:
            LOG.info(
                "Invalid VPN configuration: Unsupported algo: aes-256 "
                " is not supported.")
            pass

    @decorators.idempotent_id('885e1cda-b21d-4dec-8751-2a1f4e91773e')
    def test_vpn_basic_invalid_algo(self):
        kwargs = {}
        try:
            kwargs[
                'ipsecpolicy'] = \
                dict(name=data_utils.rand_name("ipsec-policy-"),
                     pfs="group14", encryption_algorithm="aes-512")
            self.vpnaas_client.create_ipsecpolicy(**kwargs)
        except exceptions.BadRequest:
            pass

    @decorators.idempotent_id('1e6f2f25-de83-4ee2-a30f-0f833da0c741')
    def test_vpn_basic_invalid_pfs_value(self):
        kwargs = {}
        try:
            kwargs[
                'ipsecpolicy'] = \
                dict(name=data_utils.rand_name("ipsec-policy-"),
                     pfs="group-14")
            self.vpnaas_client.create_ipsecpolicy(**kwargs)
        except exceptions.BadRequest:
            pass

    @decorators.idempotent_id('f4bea30b-76df-4dc2-a624-20621b8e0ef7')
    def test_vpn_site_conenction_update_ops(self):
        network_topo = self.create_network_topo(cidr="34.0.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topo)
        site = vpn_topo['endpoint']
        kwargs = {}
        kwargs["ipsec_site_connection"] = dict(psk="new-secret")
        self.vpnaas_client.update_ipsec_site_connections(
            site.get('ipsec_site_connection')['id'],
            **kwargs)
        site_data = self.vpnaas_client.show_ipsec_site_connections(
            endpoint_id=site.get('ipsec_site_connection')['id'])
        self.assertEqual(
            "new-secret",
            site_data['ipsec_site_connection']['psk'])
        kwargs = {}
        kwargs["ipsec_site_connection"] = dict(
            admin_state_up='False',
            description="New Vpn site")
        self.vpnaas_client.update_ipsec_site_connections(
            site.get('ipsec_site_connection')['id'],
            **kwargs)
        site_data = self.vpnaas_client.show_ipsec_site_connections(
            endpoint_id=site.get('ipsec_site_connection')['id'])
        self.assertEqual(
            False,
            site_data[
                'ipsec_site_connection'][
                'admin_state_up'])
        self.assertEqual(
            "New Vpn site",
            site_data[
                'ipsec_site_connection'][
                'description'])

    @decorators.idempotent_id('8fbf9280-d154-425f-ad26-0a1250e0dd91')
    def test_vpn_site_conenction_wrong_dpd_info(self):
        network_topo = self.create_network_topo(cidr="35.0.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topo)
        site = vpn_topo['endpoint']
        kwargs = {}
        kwargs["ipsec_site_connection"] = dict(action="disabled", timeout=1)
        self.assertRaises(
            lib_exc.BadRequest,
            self.vpnaas_client.update_ipsec_site_connections,
            site.get('ipsec_site_connection')['id'], **kwargs
        )
        kwargs["ipsec_site_connection"] = dict(action="restart-by-peer")
        self.assertRaises(
            lib_exc.BadRequest,
            self.vpnaas_client.update_ipsec_site_connections,
            site.get('ipsec_site_connection')['id'], **kwargs
        )
        kwargs["ipsec_site_connection"] = \
            {"dpd": {"action": "hold", "timeout": 300}}
        site_data = self.vpnaas_client.update_ipsec_site_connections(
            site.get('ipsec_site_connection')['id'], **kwargs)
        self.assertEqual(
            "hold",
            site_data['ipsec_site_connection'].get("dpd")["action"])

    @decorators.idempotent_id('ea4fedae-4727-4524-a74a-0078d7fbfdd9')
    def test_vpn_basic_update_ops(self):
        network_topo = self.create_network_topo()
        vpn_topo = self.create_vpn_basic_topo(network_topo)
        vpn_service = vpn_topo['vpn_service']
        kwargs = {}
        kwargs['vpnservice'] = dict(admin_state_up='false')
        self.vpnaas_client.update_vpnservice(
            vpnservice_id=vpn_service.get('vpnservice')['id'],
            **kwargs)
        kwargs['vpnservice'] = dict(admin_state_up='true', description="vpn")
        self.vpnaas_client.update_vpnservice(
            vpnservice_id=vpn_service.get('vpnservice')['id'],
            **kwargs)

    @decorators.idempotent_id('d576c487-e7d5-4698-8a17-ea5521607675')
    def test_vpn_ike_policy_update(self):
        network_topo = self.create_network_topo(cidr="36.0.0.0/24")
        vpn_topo = self.create_vpn_basic_topo(network_topo)
        try:
            kwargs = {}
            kwargs['ikepolicy'] = dict(pfs="group5")
            self.vpnaas_client.update_ikepolicy(
                vpn_topo['ike'].get('ikepolicy')['id'],
                **kwargs)
        except exceptions.Conflict:
            LOG.info(
                "IKEPolicy is in use by existing IPsecSiteConnection and "
                " can't be updated or deleted")

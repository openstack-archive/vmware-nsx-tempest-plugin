# Copyright 2017 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

LOG = log.getLogger(__name__)

# General constants.
ONE_SEC = 1

# L2GW constants.
L2GW = "l2_gateway"
L2GWS = L2GW + "s"
L2_GWS_BASE_URI = "/l2-gateways"
EXPECTED_HTTP_RESPONSE_200 = "200"
EXPECTED_HTTP_RESPONSE_201 = "201"
EXPECTED_HTTP_RESPONSE_204 = "204"
L2GWC = "l2_gateway_connection"

# MAC Learning constants
MAC_SW_PROFILE = "MacManagementSwitchingProfile"
PORT_SEC_PROFILE = "SpoofGuardSwitchingProfile"
SEC_GRPS_PROFILE = "SwitchSecuritySwitchingProfile"

# NSXV3 MDProxy constants.
MD_ERROR_CODE_WHEN_LS_BOUNDED = "10026"
INTERVAL_BETWEEN_EXEC_RETRY_ON_SSH = 5
MAX_NO_OF_TIMES_EXECUTION_OVER_SSH = 30
MD_BASE_URL = "http://169.254.169.254/"

# NSXV3 Port Security constants.
NSX_BACKEND_TIME_INTERVAL = 30
NSX_BACKEND_SMALL_TIME_INTERVAL = 10
NSX_BACKEND_VERY_SMALL_TIME_INTERVAL = 5
NSXP_BACKEND_SMALL_TIME_INTERVAL = 10

# DFW
NSX_FIREWALL_REALIZED_TIMEOUT = 120

# FWaaS
NO_OF_ENTRIES = 20
EXCLUSIVE_ROUTER = 'exclusive'
DISTRIBUTED_ROUTER = 'distributed'
TCP_PROTOCOL = 'tcp'
ICMP_PROTOCOL = 'icmp'

# NSXV3 Firewall
NSX_FIREWALL_REALIZED_DELAY = 2

APPLIANCE_NAME_STARTS_WITH = "vmw_"

# Time interval
TIME = {"SEC": {"SIXTY": 60}}

VLAN_TYPE = 'vlan'
VXLAN_TYPE = 'geneve'
VLAN = 4050

NO_OF_VMS_2 = 2
NO_OF_VMS_4 = 4
HTTP_PORT = 80
HTTPS_PORT = 443
SLEEP_BETWEEN_VIRTUAL_SEREVRS_OPEARTIONS = 120
REDIRECT_TO_POOL = "REDIRECT_TO_POOL"
REJECT = "REJECT"

# AUDIT LOG WAIT TIME
AUDIT_WAIT_TIME = 300
# ZONE Designate
ZONE_WAIT_TIME = 120
REGION_NAME = "RegionOne"
ZONE_NAME = 'tempest-dns-network.com.'
# VPN
PEER_ID = "172.24.4.12"
PFS = "group14"
ENCRYPTION_ALGO = "aes-128"
ENCRYPTION_ALGO_256 = "aes-256"
AUTH_ALGO = "sha1"
AUTH_ALGO_256 = "sha256"
LIFETIME = {"units": "seconds", "value": 21600}
PEER_ADDRESS = "172.24.4.12"
SITE_CONNECTION_STATE = 'True'
PSK = "secret"
CIDR = "22.0.9.0/24"
#BARBICAN
SECRET_TYPE = "opaque"
ALGORITHM = "aes"
PAYLOAD_CONTENT_TYPE = "text/plain"
MODE = "cbc"
BIT_LENGTH = 256
CERT_FILE = "/root/server.crt"
KEY_FILE = "/root/server.key"
CONTAINER_TYPE = "certificate"

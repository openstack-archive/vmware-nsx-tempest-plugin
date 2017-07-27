Welcome!
========

===============================
vmware-nsx-tempest-plugin
===============================

Tempest plugin vmware-nsx-tempest-plugin


This repo hosts vmware-nsx's functional api and scenario tests.

vmware-nsx is Vmware plugin for neutron. This repo is tempest plugin to
test vmware-nsx at function level. All vmware-nsx-tempest-plugin tests
are in "master" branch. Some of the tests are designed based on N-S traffic.
Intstall thsi repo on external VM to run entire test suite.

* Free software: Apache license
* Launchpad: https://launchpad.net/vmware-nsx-tempest-plugin
* Source: http://git.openstack.org/cgit/openstack/vmware-nsx-tempest-plugin
* Bugs: http://bugs.launchpad.net/vmware-nsx-tempest-plugin

Features:
=========

* API tests
* Scenario tests

Overview:
=========

Installation:
=============

#. On your own development folder, for example /opt/stack/,
   install your own tempest development env at /opt/stack/tempest/::

    $ cd /opt/stack
    $ git clone https://github.com/openstack/tempest

#. Install virtualenv with the following command::

    $ cd /opt/stack/tempest
    $ ./run_tempest.sh -u not_exist_tests

#. Install vmware-nsx-tempest-plugin master branch at /opt/stack::

    $ cd /opt/stack
    $ git clone https://github.com/openstack/vmware-nsx-tempest-plugin.git

#. Install vmware-nsx-tempest-plugin in your tempest development environment::

    $ cd /opt/stack
    $ sudo pip install -e vmware-nsx-tempest-plugin

   Run command::

    $ pip show vmware-nsx-tempest-plugin

   You should observe the following statements::

    Location: /opt/stack/vmware-nsx-tempest-plugin

#. Validate installed vmware_nsx_tempest successfully do::

    $ cd /opt/stack/vmware-nsx-tempest-plugin
    $ ostestr -l vmware_nsx_tempest
    $ ostestr vmware_nsx_tempest.tests.nsxv3.scenario.test_mdproxy.TestMDProxy.test_mdproxy_ping
    $ python -m testtools.run vmware_nsx_tempest.tests.nsxv3.scenario.test_mdproxy.TestMDProxy.test_mdproxy_ping

Your installation failed, if no tests are shown.

Execution:
==========

vmware-nsx-tempest tests are tempest tests, you need to
run from tempest directory. For example, to run only l2-gateway tests::

    $ cd /opt/stack/tempest
    $ ostestr vmware_nsx_tempest.*test_l2_gateway
    $ ostestr vmware_nsx_tempest.tests.nsxv.api.test_l2_gateway_connection.L2GatewayConnectionTest.test_csuld_single_device_interface_vlan

TechNote on vmware-nsx-tempest-plugin:
=========================================

vmware-nsx-tempest-plugin is a plugin to tempest, not neutron, nor vmware-nsx.
It is defined by tempest.test_plugins.

Modules within vmware-nsx-tempest can not see resources defined
by vmware-nsx. Commands like following will not work, unless
vmware-nsx is installed in your tempest environment::

    import vmware_nsx.shell.admin.plugins.common.utils as admin_utils

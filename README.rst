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

* 

Overview
========

Installation:
-------------

#. On your own development folder, for example /opt/devtest/,
   install your own tempest development env at /opt/devtest/os-tempest/::

    $ cd /opt/devtest
    $ git clone https://github.com/openstack/tempest os-tempest

#. Install virtualenv with the following command::

    $ cd /opt/devtest/os-tempest
    $ ./run_tempest.sh -u not_exist_tests

#. Install vmware-nsx master branch at /opt/devtest/vmware-nsx::

    $ cd /opt/devtest
    $ git clone https://github.com/openstack/vmware-nsx

#. Install vmware_nsx_tempest in your tempest development environment::

    $ cd /opt/devtest/os-tempest
    $ source .venv/bin/activate
    $ pip install -e /opt/devtest/vmware-nsx/

   Run command::

    $ pip show vmware-nsx

   You should observe the following statements::

    Location: /opt/devtest/vmware-nsx

   and under section of Entry-points::

    [tempest.test_plugins]
    vmware-nsx-tempest-plugin = vmware_nsx_tempest.plugin:VmwareNsxTempestPlugin

#. Validate installed vmware_nsx_tempest successfully do::

    $ cd /opt/devtest/os-tempest
    $ tools/with_venv.sh testr list-tests vmware_nsx_tempest.*l2_gateway

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

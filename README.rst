***********************
Security APAR Assistant
***********************

:SAAssist: Security APAR Assistant
:URL: https://saassist.github.io
:License: Apache 2.0
:Development: https://github.com/SAAssist/


.. contents::
    :local:
    :depth: 3
    :backlinks: none

Overview
********

Security APAR Assist (SAAssist) is a tool (Open Source) to help System
Administrators manage APARs (Security Fixes) for IBM AIX and IBM PowerVM
environment.

This tool works like Linux "yum" or "apt-get" to manage the security fixes
(CVE and IVs).

SAAssist works as client/server reducing time to verify if fix is applicable,
reducing time to deploy the fix to AIX and VIOS servers, reducing
false-positives, and is not necessary high skill knowledge about AIX
filesets/version management :)

SAAssist works directly with Fix Level Recommendation Tool, the IBM official
website.

The installation and configuration is simple and also can be integrated with
orchestrator or automation software (IBM BigFix, Chef, Puppet, etc)

There are two basic components on SAAssist: SAAssist Server (saassist-server)
and SAAssist Client (saassist-client).
This is a Open Source software licensed by Apache License 2.0.


SAAssist Client (saassist-client)
=================================

The SAAssist Client (saassist-client) is written in Korn Shell (ksh).

This is a simple ksh script that accesses the SAAssist Server (saassist-server)
using HTTP or NFS protocol and collects information about a specific APAR
(CVE/IV), checks if it is applicable for the server, provides detailed
information and installs the fix if required by you.

Using NFS procotol, there is no requirements.
To use HTTP, Curl is required on AIX or PowerVM/VIOS

For move information visit: https://saassist.github.io

SAAssist Server Documentation
=============================

`Security APAR Assistant Client
Documentation <https://saassist.github.io/saassist-client_doc.html>`_
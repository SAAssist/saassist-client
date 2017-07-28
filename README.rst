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

Security APAR Assist (SAAssist) is a tool to controls security APARs for IBM
AIX and IBM PowerVM environment.

There are two basic components on SAAssist, SAAssist Server (saassist-server)
and SAAssist Client (saassist-client).

This is a Open Source software licensed by Apache License 2.0.

Important:

The Security APAR Assistant (including saassist-server and saassist-client) is
not an IBM Inc. software and it is not supported or guaranteed by IBM.

IBM AIX, IBM PowerVM and IBM Fix Level Recommended Tool website are registered
trademarks of IBM Corporation in the United States, other countries, or both.


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
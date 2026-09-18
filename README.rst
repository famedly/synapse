.. image:: ./docs/famedly_logo_light_bg.webp
   :height: 60px

**Famedly Synapse - Matrix homeserver implementation (Fork of Element Synapse)**

|support| |development| |documentation| |license| |pypi| |python|

This is Famedly's fork of `Element Synapse <https://github.com/element-hq/synapse>`_,
an open source `Matrix <https://matrix.org>`__ homeserver implementation.
`Matrix <https://github.com/matrix-org>`__ is the open standard for
secure and interoperable real-time communications.

This fork applies additional patches and customizations for Famedly's needs.
The original Synapse is written and maintained by `Element <https://element.io>`_.
You can directly run and manage the source code in this repository, available
under an AGPL license.


Release process for this fork
=============================

There is more information for Famedly employees in `Notion <https://www.notion.so/famedly/Synapse-Release-Process-2ae4c3a9792080428920cff83fb8bfaf>`__


🛠️ Standalone installation and configuration
============================================

The Synapse documentation describes `options for installing Synapse standalone
<https://famedly.github.io/synapse/latest/setup/installation.html>`_. See
below for more useful documentation links.

- `Synapse configuration options <https://famedly.github.io/synapse/latest/usage/configuration/config_documentation.html>`_
- `Synapse configuration for federation <https://famedly.github.io/synapse/latest/federate.html>`_
- `Using a reverse proxy with Synapse <https://famedly.github.io/synapse/latest/reverse_proxy.html>`_
- `Upgrading Synapse <https://famedly.github.io/synapse/develop/upgrade.html>`_


🎯 Troubleshooting and support
==============================

🚀 Professional support
-----------------------

For professional support, please sent us a mail at info@famedly.com

🤝 Community support
--------------------

The `Admin FAQ <https://famedly.github.io/synapse/latest/usage/administration/admin_faq.html>`_
includes tips on dealing with some common problems. For more details, see
`Synapse's wider documentation <https://famedly.github.io/synapse/latest/>`_.

For additional support installing or managing Synapse, please ask in the community
support room |room|_ (from a matrix.org account if necessary). We do not use GitHub
issues for support requests, only for bug reports and feature requests.

.. |room| replace:: ``#synapse:matrix.org``
.. _room: https://matrix.to/#/#synapse:matrix.org

.. |docs| replace:: ``docs``
.. _docs: docs


🛠️ Development
==============

We welcome contributions to Synapse from the community!
The best place to get started is our
`guide for contributors <https://famedly.github.io/synapse/latest/development/contributing_guide.html>`_.
This is part of our broader `documentation <https://famedly.github.io/synapse/latest>`_, which includes
information for Synapse developers as well as Synapse administrators.

Developers might be particularly interested in:

* `Synapse's database schema <https://famedly.github.io/synapse/latest/development/database_schema.html>`_,
* `notes on Synapse's implementation details <https://famedly.github.io/synapse/latest/development/internal_documentation/index.html>`_, and
* `how we use git <https://famedly.github.io/synapse/latest/development/git.html>`_.

Alongside all that, join our developer community on Matrix:
`#synapse-dev:matrix.org <https://matrix.to/#/#synapse-dev:matrix.org>`_, featuring real humans!

Copyright and Licensing
=======================

  | Copyright 2014–2017 OpenMarket Ltd
  | Copyright 2017 Vector Creations Ltd
  | Copyright 2017–2025 New Vector Ltd
  | Copyright 2025 Element Creations Ltd
  | Copyright 2025 Famedly

Licensed under the AGPL.

.. |support| image:: https://img.shields.io/badge/matrix-community%20support-success
  :alt: (get community support in #synapse:matrix.org)
  :target: https://matrix.to/#/#synapse:matrix.org

.. |development| image:: https://img.shields.io/matrix/synapse-dev:matrix.org?label=development&logo=matrix
  :alt: (discuss development on #synapse-dev:matrix.org)
  :target: https://matrix.to/#/#synapse-dev:matrix.org

.. |documentation| image:: https://img.shields.io/badge/documentation-%E2%9C%93-success
  :alt: (Rendered documentation on GitHub Pages)
  :target: https://famedly.github.io/synapse/latest/

.. |license| image:: https://img.shields.io/github/license/element-hq/synapse
  :alt: (check license in LICENSE file)
  :target: LICENSE

.. |pypi| image:: https://img.shields.io/pypi/v/matrix-synapse
  :alt: (latest version released on PyPi)
  :target: https://pypi.org/project/matrix-synapse

.. |python| image:: https://img.shields.io/pypi/pyversions/matrix-synapse
  :alt: (supported python versions)
  :target: https://pypi.org/project/matrix-synapse

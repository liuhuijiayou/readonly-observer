# Third-party dependencies and notices

ReadOnly Observer's own code is licensed under the [MIT License](LICENSE). This inventory describes its third-party dependencies; it does not relicense them or certify ownership. No third-party runtime package, native binary, Python or Git is vendored. Installed dependencies retain their own licenses; package managers distribute them separately. If they are bundled later, distribute their complete applicable license/NOTICE/source-offer materials and audit the actual artifact.

Direct runtime dependencies:

| Component | Pinned version | License / source |
| --- | --- | --- |
| MCP Python SDK | 1.30.0 | MIT; https://github.com/modelcontextprotocol/python-sdk |
| regex | 2026.9.29 | Apache-2.0 AND CNRI-Python; https://github.com/mrabarnett/mrab-regex |

The files supplied by the installed direct distributions are copied unmodified to `src/observer/resources/licenses/mcp-LICENSE` and `regex-LICENSE.txt`, with their existing copyright notices. Observer does not modify those package sources. The regex file contains its Apache-2.0 text and a CNRI attribution; it does not contain the full CNRI agreement. Preserve the following notices with it:

- MCP Python SDK: Copyright (c) 2024 Anthropic, PBC.
- regex additions and alterations: Copyright 2020 Matthew Barnett, Apache-2.0.
- regex's CPython `re` ancestry: Copyright (c) 1998-2001 by Secret Labs AB.
- Copyright (c) 1995-2000 Corporation for National Research Initiatives; All Rights Reserved.

The following alternative notice is supplied as permitted by section 2 of the [CNRI Python 1.6 agreement](https://www.handle.net/python_licenses/python1.6_9-5-00.html):

> Python 1.6 is made available subject to the terms and conditions in CNRI's License Agreement. This Agreement together with Python 1.6 may be located on the Internet using the following unique, persistent identifier (known as a handle): 1895.22/1012. This Agreement may also be obtained from a proxy server on the Internet using the following URL: http://hdl.handle.net/1895.22/1012.

The installed regex metadata declares `Apache-2.0 AND CNRI-Python`; do not relabel the dependency as MIT. `src/observer/resources/licenses/regex-NOTICE.txt` carries the attribution and alternative notice into the wheel as well as the source archive. The direct license copies match the installed distributions byte for byte (SHA-256: MCP `5e13dbbc1d120fc2a03cecde7c91424ae2d7de11b63d58ded2f4431e261ee50d`; regex `bff55ef4cdcc8c14ce259f8e8ab60e264418440d6335f4dc138273fbd506144d`).

The tested dependency inventory is `dependencies-tested.json`; it records distribution name, version and declared license expression/classifier only. These metadata are not all legally equivalent: certifi declares MPL-2.0; python-multipart Apache-2.0; cryptography Apache-2.0 OR BSD-3-Clause; typing_extensions PSF-2.0; cffi MIT-0; other packages include MIT/BSD variants. Their installed files are not included in this release. Review each selected distribution's supplied license when changing or redistributing it; version constraints are not a license or vulnerability audit.

Optional external official OpenAI tunnel-client: the locally documented v0.0.17 upstream uses Apache-2.0 and has a NOTICE at https://github.com/openai/tunnel-client/blob/v0.0.17/NOTICE (license: https://github.com/openai/tunnel-client/blob/v0.0.17/LICENSE). The adapter implements a config boundary; the client executable, downloads and resolved configs are excluded. Its complete binary dependency/license bundle has not been audited here. Obtain/review it separately. Future bundling must preserve its actual LICENSE/NOTICE and other obligations, not merely this link.

Build tools setuptools 80.9.0 (MIT), wheel 0.45.1 (MIT), build 1.2.2.post1 (MIT) are external and not bundled. Native macOS Security.framework/Keychain, system Git and Python remain external platform dependencies. No automatic installation of a skill, binary, credential or remote plugin is included.

Observer's root LICENSE applies to its own code. These third-party notices preserve the dependencies' terms; they do not replace the root license or establish rights to redistribute future contributions or bundled binaries.

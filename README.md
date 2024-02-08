# Remote Attestation Clients

This repository is created to support [Remote Attestation](https://datatracker.ietf.org/doc/html/rfc9334)
clients that also works with `no_std` crates. This is to support the client
also in firmware such as [COCONUT-SVSM](https://github.com/coconut-svsm/svsm).

Our goal is to support several servers:
- [reference-kbs](https://github.com/virtee/reference-kbs)
  - Supported, but used just for testing and debugging
- [keybroker](https://github.com/tylerfanelli/keybroker)
  - Supported
- [KBS](https://github.com/confidential-containers/kbs/)
  - TODO

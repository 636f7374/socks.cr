<div align = "center"><img src="images/icon.png" width="256" height="256" /></div>

<div align = "center">
  <h1>Socks.cr - SOCKS Client and Server</h1>
</div>

<p align="center">
  <a href="https://crystal-lang.org">
    <img src="https://img.shields.io/badge/built%20with-crystal-000000.svg" /></a>
  <a href="https://github.com/636f7374/socks.cr/actions">
    <img src="https://github.com/636f7374/socks.cr/workflows/Continuous%20Integration/badge.svg" /></a>
  <a href="https://github.com/636f7374/socks.cr/releases">
    <img src="https://img.shields.io/github/release/636f7374/socks.cr.svg" /></a>
  <a href="https://github.com/636f7374/socks.cr/blob/master/license">
    <img src="https://img.shields.io/github/license/636f7374/socks.cr.svg"></a>
</p>

## Description

* High-performance, reliable, and stable SOCKS server and client.
* This repository is under evaluation and will replace [Herbal.cr](https://github.com/636f7374/herbal.cr).

## Features

[X] TCPConnection
[X] TCPBinding
[X] AssociateUDP

## Usage

* Please check the examples folder.

### Used as Shard

Add this to your application's shard.yml:
```yaml
dependencies:
  socks:
    github: 636f7374/socks.cr
```

### Installation

```bash
$ git clone https://github.com/636f7374/socks.cr.git
```

## Development

```bash
$ make test
```

## References

* [Official | Wikipedia - SOCKS](https://en.wikipedia.org/wiki/SOCKS)
* [Official | RFC 1928 - SOCKS Protocol Version 5 - IETF Tools](https://tools.ietf.org/html/rfc1928)
* [Document | How Socks 5 Works](https://samsclass.info/122/proj/how-socks5-works.html)
* [Document | SOCKS 5  - A Proxy Protocol](https://dev.to/nimit95/socks-5-a-proxy-protocol-5hcd)
* [Document | Implement SOCKS5 Protocol](https://developpaper.com/using-nodejs-to-implement-socks5-protocol/)


## Credit

* [\_Icon::Freepik/Communication](https://www.flaticon.com/packs/communication-196)

## Contributors

|Name|Creator|Maintainer|Contributor|
|:---:|:---:|:---:|:---:|
|**[636f7374](https://github.com/636f7374)**|√|√||

## License

* BSD 3-Clause Clear License

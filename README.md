# etcd2-proxy-proxy – proxying a proxy

There is a proxy mode in [etcd2](https://github.com/coreos/etcd) that allows to create a non-member instance on every host of a big cluster without growing the etcd cluster itself to more than 3 or 5 nodes.

The proxy mode though has some drawbacks:
- it does not hide the client URLs of the etcd cluster members: etcdctl and other etcd clients will still list the members and access them directly,
- an etcd proxy cannot work behind another etcd proxy.

For the first issue etcdctl has a `--no-sync` option that is not enabled by default. It's ulgy to use that everywhere in scripts though, or maybe even impossible if those are 3rdparty scripts.

The second drawback has no obvious solution.

etcd2-proxy-proxy will solve both problems
- by implementing an http/https reverse proxy,
- by hiding the upstream client URLs,
- by returning itself as the advertised client URL which makes `--no-sync` unneccessary.

Moreover, it can use different authentication and encryption settings locally for its clients than those used to communicate with the upstream etcd proxy.

## Usage

### Example

Without any SSL encryption:

```bash
$ ./etcd2-proxy-proxy -upstream https://some-etcd-proxy:2379
$ etcdctl get foo
bar
```

With SSL encryption between etcd2-proxy-proxy and the upstream, without SSL locally:

```bash
$ ./etcd2-proxy-proxy -upstream https://some-etcd-proxy:2379 \
    -upstream-cert-file client.crt -upstream-key-file client.key
$ etcdctl get foo
bar
```

With client certificates to the upstream server and 

```bash
$ ./etcd2-proxy-proxy -upstream https://some-etcd-proxy:2379 \
    -upstream-cert-file client.crt -upstream-key-file client.key \
    -cert-file server.crt -key-file server.key \
    -trust-ca-file root-ca.crt -client-cert-auth
$ etcdctl -cert-file client.crt -key-file client.key get foo
bar
```

Advertising another URL, e.g. behind a DMZ:

```bash
$ ./etcd2-proxy-proxy -upstream https://some-etcd-proxy:2379 \
    -cert-file server.crt -key-file server.key \
    -trust-ca-file root-ca.crt -client-cert-auth \
    -listen-client-urls https://0.0.0.0:2379 \
    -advertise-client-urls https://etcd.cluster,https://api.example.com
$ etcdctl -C https://api.example.com -cert-file client.crt -key-file client.key get foo
bar
```

### Configuration

```bash
$ etcd2-proxy-proxy --help
Usage of ./etcd2-proxy-proxy:
  -cert-file string
        path to the client server TLS cert file.
  -client-advertise-urls string
        The client URL to advertise to the etcd clients. (default "http://localhost:2379")
  -client-cert-auth
        enable client cert authentication.
  -k    Do not verify certificates.
  -key-file string
        path to the client server TLS key file.
  -listen-client-urls string
        list of URLs to listen on for client traffic. (default "http://localhost:2379,http://localhost:4001")
  -trusted-ca-file string
        verify certificates of HTTPS-enabled clients using this CA bundle
  -upstream string
        The upstream server.
  -upstream-ca-file string
        verify certificates of HTTPS-enabled upstream servers using this CA bundle.
  -upstream-cert-file string
        identify HTTPS-enabled upstream servers using this SSL certificate file.
  -upstream-key-file string
        identify at HTTPS-enabled upstream servers using this SSL key file.
```

## Build

```bash
$ export GOPATH=$PWD
$ mkdir -p pkg src bin
$ go get github.com/sttts/etcd2-proxy-proxy
$ cd src/github.com/sttts/etcd2-proxy-proxy
$ go build .
```


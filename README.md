# DNS Server

DNS server that allows to override record while handling proxy between multiple upstreams.


## Requirements

Create a virtual environment of python 3.6 or run the following to install python 3.6 and setup virtual environment.

```shell
./init.sh
 ```

Inside virtual environment run the following to install python requirements.
```shell
make venv-update
 ```

## Development

Install pre-commit hooks before making any changes. Run the following once to setup hooks.

```shell
pre-commit install
 ```

## Usage

You can launch the DNS server in two modes.

* Proxy
* Race

### Proxy

Run the following to launch the server in proxy mode

```shell
python server.py --proxy <upstream ip>
 ```

Upstream ip is the ip of the dns server that you want to proxy.

The `--proxy` option can be repeated multiple times to proxy multiple upstream ips. Sever will make requests to all upstream ips and returns the first successful response.

### Race

Run the following to launch the server in race mode

```shell
python server.py --race <upstream ip1> --race <upstream ip2>
 ```

Server makes request to the upstream server in the given order, giving the initial servers a head start.

The head start time can be controlled using `--delay` option. Default is set to `1s`.

Server will keep making requests to the next upstream with the mentioned delay until a successful response is returned. Server will not cancel the previous requests until the requirement is met.

In race mode, stats are recorded per upstream/protocol against each response. If there are more than three error response within last five requests, upstream is removed from the race. It will be added once it is detected to be recovered by the health check scheduler.

---
> Successful response means any non error response from upstream. **NXDOMAIN** is still a successful response.
---

### Overriding

Both proxy and race modes provide option to override DNS records. This can be done using `--override` option.

`--override` takes path to json file which contains the list of custom records. Each record is a list of five elements. Record name, record type, record class, ttl and record data.
Record name can be a glob pattern.

Example record.
> ['[a-z]abc.com', 'A', 'IN', 60, '1.1.1.1']

---
> Since this is meant to be used as internal DNS server, only requests coming from an internal ip will get a valid response. Any request coming from an external ip will get **NXDOMAIN** response.
---

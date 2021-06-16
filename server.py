#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-
import abc
import argparse
import asyncio
import collections
import concurrent.futures
import copy
import functools
import ipaddress
import json
import logging
import signal
import socket
import struct
import sys

import dnslib as dns
import uvloop

log_handler = logging.StreamHandler()
log_handler.setLevel(logging.DEBUG)
log_handler.setFormatter(
    logging.Formatter("%(asctime)s: %(message)s", datefmt="%H:%M:%S")
)

logger = logging.getLogger(__name__)
logger.addHandler(log_handler)
logger.setLevel(logging.DEBUG)

INTERNAL_DOMAINS = ()

# Sane default used by `dig` and `resolv.conf`
UPSTREAM_TIMEOUT = 5

NO_RECORD = 0
EXACT_RECORD = 1
GLOB_RECORD = 2


def match_record(record: dns.RR, req: dns.DNSQuestion) -> int:
    if req.qtype == dns.QTYPE.ANY or req.qtype == record.rtype:
        if req.qname == record.rname:
            return EXACT_RECORD
        if req.qname.matchGlob(record.rname):
            return GLOB_RECORD

    return NO_RECORD


def nodomain(record: dns.DNSRecord) -> dns.DNSRecord:
    reply = record.reply()
    reply.header.rcode = getattr(dns.RCODE, "NXDOMAIN")
    return reply


def is_internal_ip(request_ip: str) -> bool:
    try:
        return ipaddress.ip_address(request_ip).is_private
    except ValueError:
        logger.debug("Unable to determine ip state", exc_info=True)
        return False


def _release_waiter(waiter, *_):
    if not waiter.done():
        waiter.set_result(None)


async def wait_for_first_success(fs, timeout, loop):
    fs = {asyncio.ensure_future(f, loop=loop) for f in set(fs)}
    assert fs, "Set of Futures is empty."

    waiter = loop.create_future()
    timeout_handle = None
    if timeout is not None:
        timeout_handle = loop.call_later(timeout, _release_waiter, waiter)

    counter = len(fs)

    def _on_completion(fut):
        nonlocal counter
        counter -= 1
        if counter <= 0 or fut.exception() is None:
            if timeout_handle is not None:
                timeout_handle.cancel()
            if not waiter.done():
                waiter.set_result(None)

    for f in fs:
        f.add_done_callback(_on_completion)

    try:
        await waiter
    finally:
        if timeout_handle is not None:
            timeout_handle.cancel()

    success, pending = set(), set()
    for f in fs:
        f.remove_done_callback(_on_completion)
        if f.done() and f.exception() is None:
            success.add(f)
        else:
            pending.add(f)

    return success, pending


class UpstreamException(RuntimeError):
    ...


def receive(sock, nbytes=8192, timeout=UPSTREAM_TIMEOUT, *, loop=None):
    return asyncio.wait_for(loop.sock_recv(sock, nbytes), timeout=timeout)


async def resolver(
    request_record: dns.DNSRecord,
    upstream: ipaddress.IPv4Address,
    protocol: str,
    loop=None,
) -> dns.DNSRecord:
    reply = request_record.reply()
    previous_match = NO_RECORD
    for domain in INTERNAL_DOMAINS:
        match = match_record(domain, request_record.q)
        if not match:
            continue

        if match == GLOB_RECORD and previous_match == EXACT_RECORD:
            # glob cannot override exact
            continue

        if domain.rdata is None:
            # if we are overriding to NXDOMAIN, then don't include it in ANY
            if request_record.q.qtype == dns.QTYPE.ANY:
                continue
            return nodomain(request_record)

        answer: dns.RR = copy.copy(domain)
        answer.rname = request_record.q.qname

        if match == EXACT_RECORD and previous_match == GLOB_RECORD:
            # exact always overrides glob match
            reply = request_record.reply()
        reply.add_answer(answer)
        previous_match = match

    if reply.rr:
        return reply

    assert protocol in ["tcp", "udp"]
    loop = loop or asyncio.get_event_loop()

    data = request_record.pack()
    if len(data) > 65535:
        raise ValueError("Packet length too long: %d" % len(data))
    if protocol == "tcp":
        data = struct.pack("!H", len(data)) + data
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    else:
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    sock.setblocking(False)

    try:
        conn = loop.sock_connect(sock=sock, address=(upstream.compressed, 53))
        await asyncio.wait_for(conn, timeout=UPSTREAM_TIMEOUT)

        send_req = loop.sock_sendall(sock=sock, data=data)
        await asyncio.wait_for(send_req, timeout=UPSTREAM_TIMEOUT)

        if protocol == "tcp":
            response = await receive(sock, loop=loop)
            length = struct.unpack("!H", bytes(response[:2]))[0]
            while len(response) - 2 < length:
                response += await receive(sock, loop=loop)

            response = response[2:]
        else:
            response = await receive(sock, loop=loop)

        return dns.DNSRecord.parse(response)
    except (asyncio.TimeoutError, ConnectionError):
        _, exc_value, tb = sys.exc_info()
        raise UpstreamException(exc_value).with_traceback(tb)
    finally:
        sock.close()


class DNSResolver(abc.ABC):
    def __init__(self, upstreams, loop=None):
        self.upstreams = upstreams
        self.loop = loop or asyncio.get_event_loop()

    @abc.abstractmethod
    async def _get_reply(self, request: dns.DNSRecord, protocol: str) -> dns.DNSRecord:
        ...

    async def get_reply(self, data: bytes, request_ip: str, protocol: str) -> bytearray:
        request = dns.DNSRecord.parse(data)
        if is_internal_ip(request_ip=request_ip):
            response = await self._get_reply(request=request, protocol=protocol)
        else:
            response = nodomain(request)

        if response.header.rcode == dns.RCODE.NOERROR:
            logger.info(
                f"{protocol} / {request_ip} / "
                f'"{request.q.qname} ({dns.QTYPE[request.q.qtype]})" --> '
                f'RRs: {", ".join(str(a.rdata) for a in response.rr)}'
            )
        else:
            logger.info(
                f"{protocol} / {request_ip} / "
                f'"{request.q.qname} ({dns.QTYPE[request.q.qtype]})" --> '
                f'{dns.RCODE[response.header.rcode]}"'
            )

        return response.pack()

    get_tcp_reply = functools.partialmethod(get_reply, protocol="tcp")
    get_udp_reply = functools.partialmethod(get_reply, protocol="udp")

    async def watch_upstreams(self):
        request = dns.DNSRecord()
        request.add_question(dns.DNSQuestion("google.com"))

        await self._get_reply(request=request, protocol="udp")


class ProxyDNSResolver(DNSResolver):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.upstreams = frozenset(self.upstreams)

    async def _get_reply(self, request: dns.DNSRecord, protocol: str) -> dns.DNSRecord:
        done, pending = await wait_for_first_success(
            [
                resolver(request_record=request, upstream=upstream, protocol=protocol)
                for upstream in self.upstreams
            ],
            timeout=None,
            loop=self.loop,
        )

        for task in pending:
            task.cancel()

        for task in done:
            return task.result()

        return nodomain(request)


class RaceDNSResolver(DNSResolver):

    sample_count = 5
    cutoff = 3

    def __init__(self, upstreams, delay: float, loop=None):
        self._upstreams = None
        super().__init__(upstreams=upstreams, loop=loop)
        self._delay = delay
        asyncio.gather(
            self.schedule_upstream_health_check(),
            loop=self.loop,
            return_exceptions=True,
        )

    def set_upstreams(self, value: list):
        self._upstreams = {
            upstream: {
                "tcp": collections.deque(
                    (True for _ in range(self.sample_count)),
                    maxlen=self.sample_count,
                ),
                "udp": collections.deque(
                    (True for _ in range(self.sample_count)),
                    maxlen=self.sample_count,
                ),
            }
            for upstream in value
        }

    def get_upstreams(self, protocol="udp"):
        return [
            upstream
            for upstream, proto_stats in self._upstreams.items()
            if sum(proto_stats[protocol]) >= self.cutoff
        ] or self._upstreams.keys()

    def del_upstreams(self):
        del self._upstreams

    upstreams = property(get_upstreams, set_upstreams, del_upstreams)

    async def _get_reply(self, request: dns.DNSRecord, protocol: str) -> dns.DNSRecord:
        done, pending = await wait_for_first_success(
            [
                self._get_delay_reply(
                    request=request,
                    upstream=upstream,
                    delay=i * self._delay,
                    protocol=protocol,
                )
                for i, upstream in enumerate(self.get_upstreams(protocol=protocol))
            ],
            timeout=None,
            loop=self.loop,
        )

        for task in pending:
            task.cancel()

        for task in done:
            return task.result()

        return nodomain(request)

    async def _get_delay_reply(
        self,
        request: dns.DNSRecord,
        upstream: ipaddress.IPv4Address,
        delay: float,
        protocol: str,
    ) -> dns.DNSRecord:
        await asyncio.sleep(delay=delay)
        fut = asyncio.ensure_future(
            resolver(request_record=request, upstream=upstream, protocol=protocol),
            loop=self.loop,
        )
        callback = functools.partial(
            self.update_upstream_status,
            upstream=upstream,
            protocol=protocol,
        )
        fut.add_done_callback(callback)
        return await fut

    def update_upstream_status(self, future, upstream, protocol):

        if future.cancelled():
            return

        exc = future.exception()
        if exc is not None and not isinstance(exc, UpstreamException):
            return

        self._upstreams[upstream][protocol].append(exc is None)

    @staticmethod
    def get_health_check_request() -> dns.DNSRecord:
        return dns.DNSRecord.question(qname="www.google.com")

    def upstream_health_check(self, upstream: ipaddress.IPv4Address, protocol: str):
        return asyncio.ensure_future(
            asyncio.gather(
                self._get_delay_reply(
                    request=self.get_health_check_request(),
                    upstream=upstream,
                    protocol=protocol,
                    delay=0,
                ),
                loop=self.loop,
                return_exceptions=True,
            ),
            loop=self.loop,
        )

    async def schedule_upstream_health_check(self):
        while True:
            await asyncio.sleep(1 * 20)
            logger.debug(f"current stats: {self._upstreams}")
            for upstream, proto_stats in self._upstreams.items():
                for protocol in proto_stats:
                    self.upstream_health_check(upstream=upstream, protocol=protocol)
                    logger.info(f"Scheduled health check for {upstream} ({protocol})")


async def tcp_client_cb(
    client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, get_reply
) -> None:
    try:
        data = await client_reader.read(8192)
        length = struct.unpack("!H", bytes(data[:2]))[0]
        while len(data) - 2 < length:
            new_data = await client_reader.read(8192)
            if not new_data:
                break
            data += new_data
        data = data[2:]

        addr = client_writer.transport.get_extra_info("peername", (None, 0))
        request_ip, _ = addr
        return_data = await get_reply(data=data, request_ip=request_ip)
        return_data = struct.pack("!H", len(return_data)) + return_data
        client_writer.write(return_data)
        await client_writer.drain()
    finally:
        client_writer.close()


class DNSUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, get_reply):
        super().__init__()
        self.get_reply = get_reply

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self.reply(data=data, addr=addr))

    async def reply(self, data, addr):
        request_ip, _ = addr
        response_data = await self.get_reply(data=data, request_ip=request_ip)
        self.transport.sendto(response_data, addr)


def dns_udp_factory(get_reply):
    return DNSUDPProtocol(get_reply=get_reply)


def reload_conf(path):
    global INTERNAL_DOMAINS
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (TypeError, ValueError):
        return logger.warning("Unable to load json", exc_info=True)

    try:
        INTERNAL_DOMAINS = tuple(
            dns.RR(
                rname=dns.DNSLabel(rname.encode()),
                rtype=getattr(dns.QTYPE, rtype),
                rclass=getattr(dns.CLASS, rclass),
                ttl=ttl,
                rdata=getattr(dns.dns, rtype)(rdata) if rdata is not None else rdata,
            )
            for rname, rtype, rclass, ttl, rdata in data
        )
        loaded = ", ".join(
            f"{r.rname} ({dns.QTYPE[r.rtype]})" for r in INTERNAL_DOMAINS
        )
        logger.debug(f'loaded internal records from "{path}": {loaded}')
    except (AttributeError, ValueError, TypeError):
        return logger.warning("Unable to parse json", exc_info=True)


def validate_file(path):
    try:
        f = open(path, mode="r")
    except OSError as e:
        raise argparse.ArgumentTypeError(f"can't open '{path}': {e}")
    else:
        f.close()
        return path


def main(args=None):
    parser = argparse.ArgumentParser(prog="DNS Server")

    excl_group = parser.add_mutually_exclusive_group()
    excl_group.add_argument(
        "--proxy",
        action="append",
        type=ipaddress.IPv4Address,
        help="Runs dns server in proxy mode",
    )
    excl_group.add_argument(
        "--race",
        action="append",
        type=ipaddress.IPv4Address,
        help=(
            "forwards requests to all the given servers and "
            "returns the first response of first server"
        ),
    )
    parser.add_argument(
        "--delay",
        action="store",
        type=float,
        default=1.0,
        help=("time to wait before starting to query from next server in the race"),
    )
    parser.add_argument(
        "--port",
        action="store",
        type=int,
        default=53,
        help="port on which to run the dns server",
    )
    parser.add_argument(
        "--override",
        action="store",
        type=validate_file,
        required=False,
        help="json file containing records to override",
    )

    options = parser.parse_args(args=args)
    port = options.port
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    # offload worker that can execute blocking operations
    io_exc = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    if options.race:
        if len(options.race) != len(set(options.race)):
            raise ValueError("Repeated entries found in upstreams")

        handler = RaceDNSResolver(
            upstreams=options.race,
            delay=options.delay,
            loop=loop,
        )
    else:
        handler = ProxyDNSResolver(
            upstreams=options.proxy or [ipaddress.IPv4Address("8.8.8.8")],
            loop=loop,
        )

    if options.override:
        reload_conf(path=options.override)

        def handle_hup(*_):
            logger.debug("received reload signal")
            loop.run_in_executor(io_exc, reload_conf, options.override)

        signal.signal(signal.SIGHUP, handle_hup)

    dns_tcp = loop.run_until_complete(
        asyncio.start_server(
            functools.partial(tcp_client_cb, get_reply=handler.get_tcp_reply),
            host="0.0.0.0",
            port=port,
            reuse_port=True,
        )
    )
    dns_udp, _ = loop.run_until_complete(
        loop.create_datagram_endpoint(
            functools.partial(DNSUDPProtocol, get_reply=handler.get_udp_reply),
            local_addr=("0.0.0.0", port),
            reuse_port=True,
        )
    )

    logger.info("started dns server on port %s", port)

    def handle_exit(*_):
        logger.debug("received exit signal")
        cleanup()

    def cleanup():
        logger.info("Stopping dns server")
        try:
            dns_tcp.close(), dns_udp.close()
            # wait till dns server is closed
            loop.run_until_complete(dns_tcp.wait_closed())
            # wait till all the scheduled tasks are executed
            # this is mainly for udp requests to complete
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
        except:  # noqa
            ...

    signal.signal(signal.SIGQUIT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    cleanup()


if __name__ == "__main__":
    sys.exit(main())

"""txtfs-serve: minimal authoritative TXT responder backed by a zone store JSON.

dnspython is a wire-format toolkit, not a server framework: it parses and builds
DNS messages; this module owns the asyncio UDP + TCP socket loop, the AA flag,
EDNS echo, UDP truncation (TC) handling, and TCP length framing.

Resolution paths:
  * Lab / direct: point txtfs-fetch straight at this server's IP; no delegation.
  * Real DNS:     delegate the zone (NS records at the parent) to this server's IP.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import struct
from pathlib import Path

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.TXT
import dns.rrset

from .common import to_txt_strings


class Zone:
    """In-memory view of a zone store: name -> TXT payload bytes."""

    def __init__(self, store: dict):
        meta = store["meta"]
        self.zone_name = dns.name.from_text(meta["zone"])
        self.ttl = int(meta.get("ttl", 3600))
        self.records: dict[str, bytes] = {
            key.lower(): rec["value"].encode("ascii")
            for key, rec in store["records"].items()
        }
        self.soa = self._make_soa()

    def _make_soa(self):
        zone = self.zone_name.to_text()
        mname = dns.name.from_text(f"ns.{zone}")
        rname = dns.name.from_text(f"hostmaster.{zone}")
        # serial, refresh, retry, expire, minimum
        return dns.rdtypes.ANY.SOA.SOA(
            dns.rdataclass.IN, dns.rdatatype.SOA,
            mname, rname, 1, 3600, 600, 86400, self.ttl,
        )

    def lookup(self, qname: dns.name.Name):
        """Return (payload_or_None, authoritative_bool) for a query name."""
        if not qname.is_subdomain(self.zone_name):
            return None, False
        rel = qname.relativize(self.zone_name)
        if len(rel.labels) == 0:  # the apex itself
            return None, True
        key = rel.labels[0].decode("ascii").lower()
        return self.records.get(key), True


def build_response(zone: Zone, query: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA

    if not query.question:
        response.set_rcode(dns.rcode.FORMERR)
        return response

    q = query.question[0]
    qname, qtype = q.name, q.rdtype
    value, authoritative = zone.lookup(qname)

    if not authoritative:
        response.set_rcode(dns.rcode.REFUSED)
        return response

    soa_rrset = dns.rrset.from_rdata(zone.zone_name, zone.ttl, zone.soa)

    if value is None:
        # Name not found: NXDOMAIN with SOA in authority for negative caching.
        response.set_rcode(dns.rcode.NXDOMAIN)
        response.authority.append(soa_rrset)
    elif qtype in (dns.rdatatype.TXT, dns.rdatatype.ANY):
        rd = dns.rdtypes.ANY.TXT.TXT(
            dns.rdataclass.IN, dns.rdatatype.TXT, to_txt_strings(value)
        )
        response.answer.append(dns.rrset.from_rdata(qname, zone.ttl, rd))
    else:
        # Name exists, wrong type: NODATA (NOERROR, empty answer, SOA in authority).
        response.authority.append(soa_rrset)

    return response


def udp_wire(response: dns.message.Message, requestor_budget: int) -> bytes:
    """Serialize for UDP; if oversized, set TC and return a minimal answer so the
    client retries over TCP."""
    budget = max(requestor_budget, 512)
    try:
        return response.to_wire(max_size=budget)
    except dns.exception.TooBig:
        response.flags |= dns.flags.TC
        response.answer = []
        response.authority = []
        response.additional = []
        return response.to_wire(max_size=budget)


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, zone: Zone):
        self.zone = zone
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            query = dns.message.from_wire(data)
        except dns.exception.DNSException:
            return
        response = build_response(self.zone, query)
        budget = query.payload if query.edns >= 0 else 512
        self.transport.sendto(udp_wire(response, budget), addr)


async def handle_tcp(zone: Zone, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            header = await reader.readexactly(2)
            (length,) = struct.unpack("!H", header)
            data = await reader.readexactly(length)
            try:
                query = dns.message.from_wire(data)
            except dns.exception.DNSException:
                break
            response = build_response(zone, query)
            # Explicit 65535 budget: without it, to_wire() caps at the echoed EDNS
            # payload size and would wrongly reject large records on the TCP path.
            wire = response.to_wire(max_size=65535)
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        writer.close()


async def run(zone: Zone, host: str, port: int) -> None:
    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPProtocol(zone), local_addr=(host, port)
    )
    tcp_server = await asyncio.start_server(
        lambda r, w: handle_tcp(zone, r, w), host, port
    )
    print(f"txtfs-serve: {host}:{port} UDP+TCP  zone={zone.zone_name.to_text()}  "
          f"records={len(zone.records)}")
    try:
        async with tcp_server:
            await asyncio.Event().wait()
    finally:
        udp_transport.close()


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        prog="txtfs-serve", description="Serve a TXT zone store authoritatively."
    )
    ap.add_argument("zonefile", help="zone store JSON from txtfs-encode")
    ap.add_argument("--host", default="127.0.0.1", help="bind address")
    ap.add_argument("--port", type=int, default=5300, help="bind port (53 needs root)")
    args = ap.parse_args(argv)

    store = json.loads(Path(args.zonefile).read_text())
    zone = Zone(store)
    try:
        asyncio.run(run(zone, args.host, args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

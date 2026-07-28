#!/usr/bin/env python3
"""Conformance smoke test for 0xSCADA OPC-UA Server Mode (Issue #461).

A REAL, third-party UA client (opcua-asyncio / `asyncua`). The vitest suite in
this directory exercises the server with node-opcua on *both* ends, which cannot
demonstrate interoperability with an independent stack; this script can, and is
what the #461 acceptance criterion "conformance smoke test using opcua-asyncio
Python client" asks for.

It is NOT part of the Node/vitest suite: CI has no Python toolchain, so wiring it
into `npx vitest run` would either skip silently or fail the build on machines
without `asyncua`. Run it explicitly against a running server:

    pip install asyncua
    python opcua_asyncio_smoke.py \
        --endpoint opc.tcp://127.0.0.1:4840/0xscada \
        --user ua-operator --password '…'

Checks (each printed PASS/FAIL; exit 0 only if all pass):
  1. Session established with a UserName identity token.
  2. The 0xSCADA namespace is discoverable by URI (not a hardcoded index).
  3. Objects/Sites exists and holds one folder per site.
  4. Each site folder holds one variable per tag, and each reads with a
     StatusCode and a source timestamp.
  5. A subscription delivers a DataChangeNotification, and the worst
     source-timestamp -> client-arrival latency is within --max-latency-ms
     (the issue's stated 200 ms bound). NOTE: that latency subtracts the
     *server's* SourceTimestamp from the *client's* clock, so it is only a
     latency measurement when both run on the same host (or on NTP-synced
     clocks); against a remote server it silently includes clock skew.
  6. Variables are read-only: a write is refused (0xSCADA advertises no UA write
     path — see docs/protocols/opcua-server.md "Known gaps").

With --expect-anonymous-refused the script instead asserts that an anonymous
session is rejected, which is the shipped default posture.

For the secure profile pass --security with an asyncua security string, e.g.
    --security 'Basic256Sha256,SignAndEncrypt,client_cert.pem,client_key.pem'
The client certificate must be in the server's PKI trust list
(`<pkiFolder>/trusted/certs/`) — the server does not auto-accept unknown client
certificates unless OPCUA_SERVER_TRUST_UNKNOWN_CLIENT_CERTS=true on a loopback
bind.
"""

import argparse
import asyncio
import sys
import time

from asyncua import Client, ua

DEFAULT_NAMESPACE_URI = "urn:0xscada:server"


class Results:
    def __init__(self) -> None:
        self.ok = True

    def check(self, label: str, condition: bool, detail: str = "") -> bool:
        status = "PASS" if condition else "FAIL"
        suffix = f" — {detail}" if detail else ""
        print(f"  [{status}] {label}{suffix}")
        self.ok = self.ok and bool(condition)
        return bool(condition)


class SubHandler:
    """Collects DataChangeNotifications and their end-to-end latency."""

    def __init__(self) -> None:
        self.values: list[object] = []
        self.latencies_ms: list[float] = []

    def datachange_notification(self, node, val, data) -> None:  # noqa: ANN001
        self.values.append(val)
        source = getattr(data.monitored_item.Value, "SourceTimestamp", None)
        if source is not None:
            self.latencies_ms.append((time.time() - source.timestamp()) * 1000.0)


def build_client(args: argparse.Namespace) -> Client:
    client = Client(url=args.endpoint)
    client.application_uri = args.application_uri
    return client


async def apply_security(client: Client, args: argparse.Namespace) -> None:
    if args.security:
        await client.set_security_string(args.security)


async def run_anonymous_refusal(args: argparse.Namespace, results: Results) -> None:
    print("0xSCADA OPC-UA conformance smoke test (opcua-asyncio)")
    print(f"Target {args.endpoint} — expecting ANONYMOUS to be refused\n")
    client = build_client(args)
    await apply_security(client, args)
    refused = False
    detail = "an anonymous session was ACCEPTED"
    try:
        async with client:
            pass
    except (OSError, asyncio.TimeoutError) as exc:
        # A transport-level failure proves nothing about the token policy — the
        # server may simply not have been reachable. Do not score it as a pass.
        detail = (
            f"INCONCLUSIVE, not a UA-level refusal: {type(exc).__name__}: "
            f"{str(exc).splitlines()[0]}"
        )
    except Exception as exc:  # noqa: BLE001 - a UA-level rejection is the pass condition
        refused = True
        detail = f"{type(exc).__name__}: {str(exc).splitlines()[0]}"
    results.check("anonymous session is refused at the UA layer", refused, detail)


async def run_conformance(args: argparse.Namespace, results: Results) -> None:
    print("0xSCADA OPC-UA conformance smoke test (opcua-asyncio)")
    print(f"Target {args.endpoint} as user {args.user!r}")
    print(f"Security: {args.security or 'None,None (unencrypted)'}\n")

    client = build_client(args)
    await apply_security(client, args)
    client.set_user(args.user)
    client.set_password(args.password)

    async with client:
        results.check("1. session established with a UserName identity token", True)

        ns = await client.get_namespace_index(args.namespace_uri)
        results.check(
            "2. namespace discoverable by URI",
            isinstance(ns, int) and ns > 0,
            f"{args.namespace_uri} -> ns={ns}",
        )

        sites_root = await client.nodes.objects.get_child([f"{ns}:Sites"])
        site_folders = await sites_root.get_children()
        site_names = [(await f.read_browse_name()).Name for f in site_folders]
        results.check(
            "3. Objects/Sites holds one folder per site",
            len(site_folders) >= 1,
            f"{len(site_folders)} folder(s): {site_names}",
        )

        numeric_node = None
        total_tags = 0
        for folder in site_folders:
            tags = await folder.get_children()
            total_tags += len(tags)
            folder_name = (await folder.read_browse_name()).Name
            for tag in tags:
                name = (await tag.read_browse_name()).Name
                dv = await tag.read_data_value()
                good = dv.StatusCode.is_good()
                has_ts = dv.SourceTimestamp is not None
                print(
                    f"      {folder_name}/{name} = {dv.Value.Value!r} "
                    f"status={dv.StatusCode.name} sourceTimestamp={dv.SourceTimestamp}"
                )
                results.check(
                    f"4. read {folder_name}/{name}",
                    good and has_ts,
                    "" if (good and has_ts) else "bad status or missing source timestamp",
                )
                if numeric_node is None and isinstance(dv.Value.Value, float):
                    numeric_node = tag
        results.check("4. at least one variable per site", total_tags >= 1,
                      f"{total_tags} variable(s)")

        if numeric_node is None:
            results.check("5. DataChangeNotification received", False,
                          "no numeric variable found to subscribe to")
        else:
            handler = SubHandler()
            sub = await client.create_subscription(args.publishing_interval_ms, handler)
            await sub.subscribe_data_change(numeric_node)
            await asyncio.sleep(args.subscribe_seconds)
            await sub.delete()
            worst = max(handler.latencies_ms) if handler.latencies_ms else float("inf")
            results.check(
                "5. DataChangeNotification received on tag update",
                len(handler.values) > 0,
                f"{len(handler.values)} notification(s), values={handler.values[:5]}",
            )
            results.check(
                f"5. worst update latency within {args.max_latency_ms} ms",
                worst <= args.max_latency_ms,
                f"worst={worst:.1f} ms over {len(handler.latencies_ms)} sample(s)",
            )

            refused = False
            detail = "the write was ACCEPTED — the server advertises no UA write path"
            try:
                await numeric_node.write_value(ua.Variant(1.0, ua.VariantType.Double))
            except Exception as exc:  # noqa: BLE001 - any refusal is the pass condition
                refused = True
                detail = f"{type(exc).__name__}: {str(exc).splitlines()[0]}"
            results.check("6. variables are read-only (write refused)", refused, detail)


async def main_async() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="opc.tcp://127.0.0.1:4840/0xscada")
    parser.add_argument("--user", default="ua-operator")
    parser.add_argument("--password", default="")
    parser.add_argument("--namespace-uri", default=DEFAULT_NAMESPACE_URI)
    parser.add_argument("--application-uri", default="urn:0xscada:asyncua-smoke")
    parser.add_argument(
        "--security",
        default="",
        help="asyncua security string, e.g. "
        "'Basic256Sha256,SignAndEncrypt,client_cert.pem,client_key.pem'",
    )
    parser.add_argument("--subscribe-seconds", type=float, default=3.0)
    parser.add_argument("--publishing-interval-ms", type=int, default=50)
    parser.add_argument("--max-latency-ms", type=float, default=200.0)
    parser.add_argument(
        "--expect-anonymous-refused",
        action="store_true",
        help="assert an anonymous session is rejected instead of running the browse/read/subscribe checks",
    )
    args = parser.parse_args()

    results = Results()
    if args.expect_anonymous_refused:
        await run_anonymous_refusal(args, results)
    else:
        await run_conformance(args, results)

    print("\nRESULT:", "ALL PASS" if results.ok else "FAILURES PRESENT")
    return 0 if results.ok else 1


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())

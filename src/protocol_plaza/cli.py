from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agent_api import AgentApi
from .demo import run_demo
from .gateway import Gateway
from .http_relay import HttpRelayClient, RelayHttpServer
from .relay import Relay, ServiceCredential
from .scenario import run_full_scenario


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protocol-plaza",
        description="Protocol Plaza encrypted coordination beta",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run a private two-agent exchange")
    demo.add_argument(
        "--directory", type=Path, default=Path("run"),
        help="new directory for relay, gateway, and story databases"
    )
    demo.add_argument(
        "--transport", choices=("memory", "http"), default="http",
        help="exercise an in-process adapter or the real HTTP boundary"
    )
    serve = sub.add_parser("serve-relay", help="run the development HTTP relay")
    serve.add_argument("--db", type=Path, default=Path("relay.db"))
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument(
        "--bootstrap-token", default=None,
        help="credential used once to register gateway service principals"
    )
    inspect_relay = sub.add_parser(
        "inspect-relay", help="verify the relay's first-party discovery manifest"
    )
    inspect_relay.add_argument("--relay-url", required=True)
    inspect_relay.add_argument(
        "--expected-signing-key", default=None,
        help="out-of-band relay signing-key pin; verifies identity as well as integrity",
    )
    register = sub.add_parser(
        "register-gateway", help="create a service credential file for one gateway"
    )
    register.add_argument("--relay-url", required=True)
    register.add_argument("--label", required=True)
    register.add_argument("--out", type=Path, required=True)
    register.add_argument(
        "--bootstrap-token",
        default=os.environ.get("PLAZA_BOOTSTRAP_TOKEN"),
    )
    agent = sub.add_parser(
        "agent-stdio", help="serve newline-delimited agent requests on stdin/stdout"
    )
    agent.add_argument("--relay-url", required=True)
    agent.add_argument("--credential-file", type=Path, required=True)
    agent.add_argument("--gateway-directory", type=Path, required=True)
    agent.add_argument("--label", default="agent")
    scenario = sub.add_parser(
        "scenario", help="run the full three-agent beta acceptance scenario"
    )
    scenario.add_argument("--directory", type=Path, default=Path("acceptance-run"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "demo":
        if args.directory.exists() and any(args.directory.iterdir()):
            print(
                f"error: demo directory must be absent or empty: {args.directory}",
                file=sys.stderr,
            )
            return 2
        result = run_demo(args.directory, transport=args.transport)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "serve-relay":
        relay = Relay(args.db)
        server = RelayHttpServer(
            relay, args.host, args.port, bootstrap_token=args.bootstrap_token
        )
        print(f"development relay listening on {server.base_url}")
        print(f"relay id: {server.discovery_manifest.relay_id}")
        print(f"relay discovery signing key: {server.discovery_manifest.signing_key}")
        print(f"development bootstrap token: {server.bootstrap_token}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.close()
            relay.close()
        return 0
    if args.command == "inspect-relay":
        manifest = HttpRelayClient(args.relay_url).discover_relay(
            expected_signing_key=args.expected_signing_key
        )
        print(json.dumps({
            "integrity_verified": True,
            "identity_pinned": args.expected_signing_key is not None,
            "manifest": manifest.to_dict(),
        }, indent=2, sort_keys=True))
        return 0
    if args.command == "register-gateway":
        if not args.bootstrap_token:
            print("error: bootstrap token is required", file=sys.stderr)
            return 2
        if args.out.exists():
            print(f"error: refusing to overwrite credential file: {args.out}", file=sys.stderr)
            return 2
        client = HttpRelayClient.register(
            args.relay_url, args.bootstrap_token, args.label
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "principal_id": client.credential.principal_id,
                    "access_token": client.credential.access_token,
                    "proof_private_key": client.credential.proof_private_key,
                },
                handle,
                sort_keys=True,
            )
        print(f"wrote gateway credential: {args.out}")
        return 0
    if args.command == "agent-stdio":
        value = json.loads(args.credential_file.read_text(encoding="utf-8"))
        credential = ServiceCredential(
            principal_id=value["principal_id"], access_token=value["access_token"],
            proof_private_key=value["proof_private_key"],
        )
        client = HttpRelayClient(args.relay_url, credential=credential)
        gateway = Gateway(args.gateway_directory, client, label=args.label)
        api = AgentApi(gateway)
        try:
            for line in sys.stdin:
                try:
                    request = json.loads(line)
                    if not isinstance(request, dict):
                        raise ValueError("request must be an object")
                    response = api.handle(request)
                except Exception as exc:
                    response = {
                        "jsonrpc": "2.0", "id": None,
                        "error": {"code": "invalid_request", "message": str(exc)},
                    }
                print(json.dumps(response, sort_keys=True), flush=True)
        finally:
            gateway.close()
        return 0
    if args.command == "scenario":
        if args.directory.exists() and any(args.directory.iterdir()):
            print(
                f"error: scenario directory must be absent or empty: {args.directory}",
                file=sys.stderr,
            )
            return 2
        result = run_full_scenario(args.directory)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    return 2

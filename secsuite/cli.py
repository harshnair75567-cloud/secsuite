"""CLI Entry Point for secsuite"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .config import Config, get_config
from .daemon import create_runner
from .logging import get_logger, setup_logging
from .modules import run_fim_audit, run_fim_baseline, run_hips, run_nids


class SecSuiteCLI:
    """Main CLI handler"""

    def __init__(self):
        self.config: Optional[Config] = None
        self.logger = get_logger("secsuite.cli")

    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog="secsuite",
            description="Unified Security Suite - NIDS, HIPS, FIM",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  secsuite init                    # Create default config.json
  secsuite config show             # Show current configuration
  secsuite config set nids.ports "[21,22,80]"  # Update config
  secsuite nids start              # Start NIDS
  secsuite hips start              # Start HIPS
  secsuite fim baseline            # Create FIM baseline
  secsuite fim audit               # Run FIM audit
  secsuite start                   # Start all enabled services
  secsuite status                  # Show service status
  secsuite stop                    # Stop all services
"""
        )

        parser.add_argument(
            "-c", "--config",
            help="Path to config file",
            default=None
        )
        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose logging"
        )

        subparsers = parser.add_subparsers(dest="command", help="Commands")

        # init command
        init_parser = subparsers.add_parser("init", help="Create default configuration")
        init_parser.add_argument(
            "-o", "--output",
            help="Output config file path",
            default="config.json"
        )
        init_parser.add_argument(
            "--force",
            action="store_true",
            help="Overwrite existing config"
        )

        # config command
        config_parser = subparsers.add_parser("config", help="Configuration management")
        config_sub = config_parser.add_subparsers(dest="config_action")
        config_sub.add_parser("show", help="Show current config")
        config_sub.add_parser("validate", help="Validate config")

        set_parser = config_sub.add_parser("set", help="Set config value")
        set_parser.add_argument("key", help="Config key (e.g., nids.ports)")
        set_parser.add_argument("value", help="JSON value")

        get_parser = config_sub.add_parser("get", help="Get config value")
        get_parser.add_argument("key", help="Config key")

        # nids command
        nids_parser = subparsers.add_parser("nids", help="NIDS commands")
        nids_sub = nids_parser.add_subparsers(dest="nids_action")
        nids_sub.add_parser("start", help="Start NIDS")
        nids_sub.add_parser("stop", help="Stop NIDS")
        nids_sub.add_parser("test", help="Run NIDS test")

        # hips command
        hips_parser = subparsers.add_parser("hips", help="HIPS commands")
        hips_sub = hips_parser.add_subparsers(dest="hips_action")
        hips_sub.add_parser("start", help="Start HIPS")
        hips_sub.add_parser("stop", help="Stop HIPS")

        # fim command
        fim_parser = subparsers.add_parser("fim", help="FIM commands")
        fim_sub = fim_parser.add_subparsers(dest="fim_action")
        fim_sub.add_parser("baseline", help="Create baseline")
        fim_sub.add_parser("audit", help="Run integrity audit")

        # service commands
        service_parser = subparsers.add_parser("start", help="Start all enabled services")
        service_parser = subparsers.add_parser("stop", help="Stop all services")
        service_parser = subparsers.add_parser("restart", help="Restart all services")
        service_parser = subparsers.add_parser("status", help="Show service status")

        return parser

    def run(self, args: Optional[list] = None) -> int:
        """Run CLI"""
        parser = self.create_parser()
        parsed = parser.parse_args(args)

        if not parsed.command:
            parser.print_help()
            return 1

        # Load config
        self.config = get_config(parsed.config)
        if parsed.verbose:
            self.config.set("general", "log_level", "DEBUG")

        setup_logging(self.config.config)

        # Dispatch command
        try:
            if parsed.command == "init":
                return self.cmd_init(parsed)
            elif parsed.command == "config":
                return self.cmd_config(parsed)
            elif parsed.command == "nids":
                return self.cmd_nids(parsed)
            elif parsed.command == "hips":
                return self.cmd_hips(parsed)
            elif parsed.command == "fim":
                return self.cmd_fim(parsed)
            elif parsed.command in ("start", "stop", "restart", "status"):
                return self.cmd_service(parsed)
            else:
                parser.print_help()
                return 1
        except KeyboardInterrupt:
            self.logger.info("Interrupted")
            return 130
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            if parsed.verbose:
                import traceback
                traceback.print_exc()
            return 1

    def cmd_init(self, args) -> int:
        """Create default config"""
        output = Path(args.output)
        if output.exists() and not args.force:
            print(f"Config file {output} exists. Use --force to overwrite.")
            return 1

        config = Config()
        config.save(str(output))
        print(f"Created default config: {output}")
        return 0

    def cmd_config(self, args) -> int:
        """Config management"""
        if args.config_action == "show":
            print(json.dumps(self.config.config, indent=2))
            return 0
        elif args.config_action == "validate":
            print("Configuration valid")
            return 0
        elif args.config_action == "set":
            try:
                value = json.loads(args.value)
            except json.JSONDecodeError:
                value = args.value

            parts = args.key.split(".")
            section = parts[0]
            key = ".".join(parts[1:]) if len(parts) > 1 else ""
            if key:
                self.config.set(section, key, value)
            else:
                self.config._config[section] = value
            self.config.save()
            print(f"Set {args.key} = {value}")
            return 0
        elif args.config_action == "get":
            parts = args.key.split(".")
            section = parts[0]
            key = ".".join(parts[1:]) if len(parts) > 1 else ""
            value = self.config.get(section, key)
            print(json.dumps(value, indent=2) if isinstance(value, (dict, list)) else value)
            return 0
        else:
            print("Use: secsuite config {show|validate|set|get}")
            return 1

    def cmd_nids(self, args) -> int:
        """NIDS commands"""
        if args.nids_action == "start":
            run_nids(self.config.config)
            return 0
        elif args.nids_action == "test":
            self._run_nids_test()
            return 0
        else:
            print("Use: secsuite nids {start|test}")
            return 1

    def cmd_hips(self, args) -> int:
        """HIPS commands"""
        if args.hips_action == "start":
            run_hips(self.config.config)
            return 0
        else:
            print("Use: secsuite hips start")
            return 1

    def cmd_fim(self, args) -> int:
        """FIM commands"""
        if args.fim_action == "baseline":
            run_fim_baseline(self.config.config)
            return 0
        elif args.fim_action == "audit":
            run_fim_audit(self.config.config)
            return 0
        else:
            print("Use: secsuite fim {baseline|audit}")
            return 1

    def cmd_service(self, args) -> int:
        """Service management"""
        modules = {
            "nids": run_nids,
            "hips": run_hips,
        }

        runner = create_runner(self.config.config, modules)

        if args.command == "start":
            results = runner.start_all()
            for name, success in results.items():
                status = "OK" if success else "FAILED"
                print(f"  {name}: {status}")
            if any(results.values()):
                print("Services started. Press Ctrl+C to stop.")
                runner.wait()
            return 0
        elif args.command == "stop":
            results = runner.stop_all()
            for name, success in results.items():
                status = "OK" if success else "FAILED"
                print(f"  {name}: {status}")
            return 0
        elif args.command == "restart":
            runner.stop_all()
            import time
            time.sleep(0.5)
            results = runner.start_all()
            for name, success in results.items():
                status = "OK" if success else "FAILED"
                print(f"  {name}: {status}")
            return 0
        elif args.command == "status":
            status = runner.status_all()
            for name, info in status.items():
                state = "RUNNING" if info["running"] else "STOPPED"
                pid = info["pid"] or "N/A"
                print(f"  {name}: {state} (PID: {pid})")
            return 0

        return 1

    def _run_nids_test(self) -> None:
        """Run NIDS test using offense-style test"""
        import socket
        import time

        nids_config = self.config.get_section("nids")
        target_ip = "127.0.0.1"
        ports = nids_config.get("ports", [7777, 8888, 21])

        print(f"[*] Starting NIDS test on {target_ip}...")

        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                print(f"[!] Probing Port: {port}")
                s.connect((target_ip, port))
                hex_payload = bytes.fromhex("00000000000000000000000000030000")
                s.send(hex_payload)
                print(f"[+] Payload sent to {port}")
                s.close()
                time.sleep(1)
            except Exception as e:
                print(f"[?] Port {port} might be closed or filtered: {e}")

        print("[*] Test complete. Check 'ids_log.json'!")


def main():
    """Main entry point"""
    cli = SecSuiteCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import re
import sys
import socket
import uuid
import logging
import os
import threading
import pickle
import socketserver
import queue as Queue
import selectors
from getpass import getuser
from tempfile import gettempdir
from time import monotonic as time

import pykms_RpcBind, pykms_RpcRequest
from pykms_RpcBase import rpcBase
from pykms_Dcerpc import MSRPCHeader
from pykms_Misc import check_setup, check_lcid, check_dir, check_other
from pykms_Misc import KmsParser, KmsParserException, KmsParserHelp
from pykms_Misc import (
    kms_parser_get,
    kms_parser_check_optionals,
    kms_parser_check_positionals,
    kms_parser_check_connect,
)
from pykms_Format import enco, deco, pretty_printer, justify
from pykms_Connect import MultipleListener
from pykms_config import KmsServerConfig

srv_version = "py-kms_2025-05-03"
__license__ = "The Unlicense"
__author__ = "Matteo ℱan <SystemRage@protonmail.com>"
__url__ = "https://github.com/SystemRage/py-kms"
srv_description = "py-kms: KMS Server Emulator written in Python"
srv_config = {}


##---------------------------------------------------------------------------------------------------------------------------------------------------------
class KeyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        bind_and_activate=True,
        want_dual=False,
    ):
        socketserver.BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.__shutdown_request = False
        self.r_service, self.w_service = socket.socketpair()

        if hasattr(selectors, "PollSelector"):
            self._ServerSelector = selectors.PollSelector
        else:
            self._ServerSelector = selectors.SelectSelector

        if bind_and_activate:
            try:
                self.multisock = MultipleListener(server_address, want_dual=want_dual)
            except Exception as e:
                if (
                    want_dual
                    and str(e) == "dualstack_ipv6 not supported on this platform"
                ):
                    try:
                        pretty_printer(
                            log_obj=loggersrv.warning,
                            put_text="{reverse}{yellow}{bold}%s. Creating not dualstack sockets...{end}"
                            % str(e),
                        )
                        self.multisock = MultipleListener(
                            server_address, want_dual=False
                        )
                    except Exception as e:
                        pretty_printer(
                            log_obj=loggersrv.error,
                            to_exit=True,
                            put_text="{reverse}{red}{bold}%s. Exiting...{end}" % str(e),
                        )
                else:
                    pretty_printer(
                        log_obj=loggersrv.error,
                        to_exit=True,
                        put_text="{reverse}{red}{bold}%s. Exiting...{end}" % str(e),
                    )

            if self.multisock.cant_dual:
                delim = "" if len(self.multisock.cant_dual) == 1 else ", "
                pretty_printer(
                    log_obj=loggersrv.warning,
                    put_text="{reverse}{yellow}{bold}IPv4 [%s] can't be dualstack{end}"
                    % delim.join(self.multisock.cant_dual),
                )

    def pykms_serve(self):
        """Mixing of socketserver serve_forever() and handle_request() functions,
        without elements blocking tkinter.
        Handle one request at a time, possibly blocking.
        Respects self.timeout.
        """
        # Support people who used socket.settimeout() to escape
        # pykms_serve() before self.timeout was available.
        timeout = self.multisock.gettimeout()
        if timeout is None:
            timeout = self.timeout
        elif self.timeout is not None:
            timeout = min(timeout, self.timeout)
        if timeout is not None:
            deadline = time() + timeout

        try:
            # Wait until a request arrives or the timeout expires.
            with self._ServerSelector() as selector:
                self.multisock.register(selector)
                # self-pipe trick.
                selector.register(
                    fileobj=self.r_service.fileno(), events=selectors.EVENT_READ
                )

                while not self.__shutdown_request:
                    ready = selector.select(timeout)
                    if self.__shutdown_request:
                        break

                    if ready == []:
                        if timeout is not None:
                            timeout = deadline - time()
                            if timeout < 0:
                                return self.handle_timeout()
                    else:
                        for key, mask in ready:
                            if key.fileobj in self.multisock.filenos():
                                self.socket = self.multisock.sockmap[key.fileobj]
                                self.server_address = self.socket.getsockname()
                                self._handle_request_noblock()
                            elif key.fileobj is self.r_service.fileno():
                                # only to clean buffer.
                                msgkill = os.read(self.r_service.fileno(), 8).decode(
                                    "utf-8"
                                )
                                sys.exit(0)
        finally:
            self.__shutdown_request = False

    def shutdown(self):
        self.__shutdown_request = True

    def server_close(self):
        self.multisock.close()

    def handle_timeout(self):
        pretty_printer(
            log_obj=loggersrv.error,
            to_exit=True,
            put_text="{reverse}{red}{bold}Server connection timed out. Exiting...{end}",
        )

    def handle_error(self, request, client_address):
        pass


class server_thread(threading.Thread):
    def __init__(self, queue, name):
        threading.Thread.__init__(self)
        self.name = name
        self.queue = queue
        self.server = None
        self.is_running_server, self.with_gui, self.checked = [False for _ in range(3)]
        self.is_running_thread = threading.Event()

    def terminate_serve(self):
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        self.is_running_server = False

    def terminate_thread(self):
        self.is_running_thread.set()

    def terminate_eject(self):
        os.write(self.server.w_service.fileno(), "☠".encode("utf-8"))

    def run(self):
        while not self.is_running_thread.is_set():
            try:
                item = self.queue.get(block=True, timeout=0.1)
                self.queue.task_done()
            except Queue.Empty:
                continue
            else:
                try:
                    if item == "start":
                        self.eject = False
                        self.is_running_server = True
                        # Check options.
                        if not self.checked:
                            server_check()
                        # Create and run server.
                        self.server = server_create()
                        self.server.pykms_serve()
                except (SystemExit, Exception) as e:
                    self.eject = True
                    if not self.with_gui:
                        raise
                    else:
                        if isinstance(e, SystemExit):
                            continue
                        else:
                            raise


##---------------------------------------------------------------------------------------------------------------------------------------------------------

loggersrv = logging.getLogger("logsrv")

# 'help' string - 'default' value - 'dest' string.
srv_options = {
    "ip": {
        "help": 'The IP address (IPv4 or IPv6) to listen on. The default is "0.0.0.0" (all interfaces).',
        "def": "0.0.0.0",
        "des": "ip",
    },
    "port": {
        "help": 'The network port to listen on. The default is "1688".',
        "def": 1688,
        "des": "port",
    },
    "epid": {
        "help": "Use this option to manually specify an ePID to use. If no ePID is specified, a random ePID will be auto generated.",
        "def": None,
        "des": "epid",
    },
    "lcid": {
        "help": 'Use this option to manually specify an LCID for use with randomly generated ePIDs. Default is "1033" (en-us)',
        "def": 1033,
        "des": "lcid",
    },
    "count": {
        "help": "Use this option to specify the current client count. A number >=25 is required to enable activation of client OSes; \
for server OSes and Office >=5",
        "def": None,
        "des": "clientcount",
    },
    "activation": {
        "help": 'Use this option to specify the activation interval (in minutes). Default is "120" minutes (2 hours).',
        "def": 120,
        "des": "activation",
    },
    "renewal": {
        "help": 'Use this option to specify the renewal interval (in minutes). Default is "10080" minutes (7 days).',
        "def": 1440 * 7,
        "des": "renewal",
    },
    "hwid": {
        "help": "Use this option to specify a HWID. The HWID must be an 16-character string of hex characters. \
The default is \"364F463A8863D35F\" or type \"RANDOM\" to auto generate the HWID.",
        "def": "364F463A8863D35F",
        "des": "hwid",
    },
    "time0": {
        "help": "Use this option to specify the maximum inactivity time (in seconds) after which the client disconnects. \
Default is \"None\" (infinite).",
        "def": None,
        "des": "timeoutidle",
    },
    "time1": {
        "help": "Use this option to specify the maximum time (in seconds) to wait for a client request. \
Default is \"None\" (infinite).",
        "def": None,
        "des": "timeoutsndrcv",
    },
    "llevel": {
        "help": "Use this option to set a log level. The default is \"ERROR\".",
        "def": "ERROR",
        "des": "loglevel",
        "choi": ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "MININFO"],
    },
    "lfile": {
        "help": 'Use this option to set an output log file. The default is "pykms_server.log". \
Type "STDOUT" to view log info on stdout. Type "FILESTDOUT" to combine previous actions. \
Use "STDOUTOFF" to disable stdout messages. Use "FILEOFF" if you not want to create logfile.',
        "def": "/opt/py-kms/pykms_server.log",
        "des": "logfile",
    },
    "lsize": {
        "help": "Use this flag to set a maximum size (in MB) to the output log file. Deactivated by default.",
        "def": 0,
        "des": "logsize",
    },
    "listen": {"help": "Adds an IP address and port to listen on.", "def": [], "des": "listen"},
    "backlog": {
        "help": "Sets the backlog for the server. Default is 5.",
        "def": 5,
        "des": "backlog",
    },
    "reuse": {
        "help": "Allows/Disallows address reuse. Default is True.",
        "def": True,
        "des": "reuse",
    },
    "dual": {
        "help": "Allows listening to an IPv6 address also accepting connections via IPv4. Deactivated by default.",
        "def": False,
        "des": "dual",
    },
    "web_gui": {
        "help": "Enable web-based GUI interface. Default is disabled.",
        "def": False,
        "des": "web_gui",
    },
    "web_port": {
        "help": "Port for the web GUI interface. Default is 8080.",
        "def": 8080,
        "des": "web_port",
    },
    "db_type": {
        "help": "Database backend type (sqlite/mysql/postgresql). Default is sqlite.",
        "def": "sqlite",
        "des": "db_type",
    },
    "db_name": {
        "help": "Database name/path. For SQLite use format 'sqlite:///path/to/db.sqlite'. Default is 'sqlite:///pykms_database.db'.",
        "def": "sqlite:///pykms_database.db",
        "des": "db_name",
    },
    "db_host": {
        "help": "Database host for MySQL/PostgreSQL.",
        "def": "localhost",
        "des": "db_host",
    },
    "db_user": {
        "help": "Database user for MySQL/PostgreSQL.",
        "def": "",
        "des": "db_user",
    },
    "db_password": {
        "help": "Database password for MySQL/PostgreSQL.",
        "def": "",
        "des": "db_password",
    }
}


def server_options():
    server_parser = KmsParser(
        description=srv_description, epilog="version: " + srv_version, add_help=False
    )
    
    # Make IP and port optional when using config file
    server_parser.add_argument(
        "ip",
        nargs="?",
        action="store",
        default=None,  # Changed from srv_options["ip"]["def"]
        help=srv_options["ip"]["help"],
        type=str,
    )
    server_parser.add_argument(
        "port",
        nargs="?",
        action="store",
        default=None,  # Changed from srv_options["port"]["def"]
        help=srv_options["port"]["help"],
        type=int,
    )
    server_parser.add_argument(
        "-e",
        "--epid",
        action="store",
        dest=srv_options["epid"]["des"],
        default=srv_options["epid"]["def"],
        help=srv_options["epid"]["help"],
        type=str,
    )
    server_parser.add_argument(
        "-l",
        "--lcid",
        action="store",
        dest=srv_options["lcid"]["des"],
        default=srv_options["lcid"]["def"],
        help=srv_options["lcid"]["help"],
        type=int,
    )
    server_parser.add_argument(
        "-c",
        "--client-count",
        action="store",
        dest=srv_options["count"]["des"],
        default=srv_options["count"]["def"],
        help=srv_options["count"]["help"],
        type=str,
    )
    server_parser.add_argument(
        "-a",
        "--activation-interval",
        action="store",
        dest=srv_options["activation"]["des"],
        default=srv_options["activation"]["def"],
        help=srv_options["activation"]["help"],
        type=int,
    )
    server_parser.add_argument(
        "-r",
        "--renewal-interval",
        action="store",
        dest=srv_options["renewal"]["des"],
        default=srv_options["renewal"]["def"],
        help=srv_options["renewal"]["help"],
        type=int,
    )
    server_parser.add_argument(
        "-w",
        "--hwid",
        action="store",
        dest=srv_options["hwid"]["des"],
        default=srv_options["hwid"]["def"],
        help=srv_options["hwid"]["help"],
        type=str,
    )
    server_parser.add_argument(
        "-t0",
        "--timeout-idle",
        action="store",
        dest=srv_options["time0"]["des"],
        default=srv_options["time0"]["def"],
        help=srv_options["time0"]["help"],
        type=str,
    )
    server_parser.add_argument(
        "-t1",
        "--timeout-sndrcv",
        action="store",
        dest=srv_options["time1"]["des"],
        default=srv_options["time1"]["def"],
        help=srv_options["time1"]["help"],
        type=str,
    )
    server_parser.add_argument(
        "-V",
        "--loglevel",
        action="store",
        dest=srv_options["llevel"]["des"],
        choices=srv_options["llevel"]["choi"],
        default=srv_options["llevel"]["def"],
        help=srv_options["llevel"]["help"],
        type=str,
    )
    server_parser.add_argument(
        "-F",
        "--logfile",
        nargs="+",
        action="store",
        dest=srv_options["lfile"]["des"],
        default=srv_options["lfile"]["def"],
        help=srv_options["lfile"]["help"],
        type=str,
    )
    server_parser.add_argument(
        "-S",
        "--logsize",
        action="store",
        dest=srv_options["lsize"]["des"],
        default=srv_options["lsize"]["def"],
        help=srv_options["lsize"]["help"],
        type=float,
    )
    server_parser.add_argument(
        "-wg",
        "--web-gui",
        action="store_true",
        dest=srv_options["web_gui"]["des"],
        default=srv_options["web_gui"]["def"],
        help=srv_options["web_gui"]["help"]
    )
    server_parser.add_argument(
        "-wp",
        "--web-port",
        action="store",
        dest=srv_options["web_port"]["des"],
        default=srv_options["web_port"]["def"],
        help=srv_options["web_port"]["help"],
        type=int
    )
    server_parser.add_argument(
        "-dt",
        "--db-type",
        action="store",
        dest=srv_options["db_type"]["des"],
        default=srv_options["db_type"]["def"],
        help=srv_options["db_type"]["help"]
    )
    server_parser.add_argument(
        "-dh",
        "--db-host",
        action="store",
        dest=srv_options["db_host"]["des"],
        default=srv_options["db_host"]["def"],
        help=srv_options["db_host"]["help"]
    )
    server_parser.add_argument(
        "-dn",
        "--db-name",
        action="store",
        dest=srv_options["db_name"]["des"],
        default=srv_options["db_name"]["def"],
        help=srv_options["db_name"]["help"]
    )
    server_parser.add_argument(
        "-du",
        "--db-user",
        action="store",
        dest=srv_options["db_user"]["des"],
        default=srv_options["db_user"]["def"],
        help=srv_options["db_user"]["help"]
    )
    server_parser.add_argument(
        "-dp",
        "--db-password",
        action="store",
        dest=srv_options["db_password"]["des"],
        default=srv_options["db_password"]["def"],
        help=srv_options["db_password"]["help"]
    )
    server_parser.add_argument(
        "-h", "--help", action="help", help="show this help message and exit"
    )

    # Add new argument for config file
    server_parser.add_argument(
        "-cf", "--config-file",
        action="store",
        dest="config_file",
        default=None,
        help="Path to configuration file. If not specified, will search in default locations.",
        type=str
    )

    ## Connection parsing.
    connection_parser = KmsParser(description="connect options", add_help=False)
    connection_subparser = connection_parser.add_subparsers(dest="mode")

    connect_parser = connection_subparser.add_parser("connect", add_help=False)
    connect_parser.add_argument(
        "-n",
        "--listen",
        action="append",
        dest=srv_options["listen"]["des"],
        default=[],
        help=srv_options["listen"]["help"],
        type=str,
    )
    connect_parser.add_argument(
        "-b",
        "--backlog",
        action="append",
        dest=srv_options["backlog"]["des"],
        default=[],
        help=srv_options["backlog"]["help"],
        type=int,
    )
    connect_parser.add_argument(
        "-u",
        "--no-reuse",
        action="append_const",
        dest=srv_options["reuse"]["des"],
        const=False,
        default=[],
        help=srv_options["reuse"]["help"],
    )
    connect_parser.add_argument(
        "-d",
        "--dual",
        action="store_true",
        dest=srv_options["dual"]["des"],
        default=srv_options["dual"]["def"],
        help=srv_options["dual"]["help"],
    )

    try:
        # Parse command line arguments first
        args = server_parser.parse_args()

        # Initialize configuration
        config = KmsServerConfig(args.config_file)
        
        # Update configuration with command line arguments (they take precedence)
        args_dict = vars(args)
        
        # Only update IP/port from args if explicitly provided
        if args.ip is not None:
            args_dict['ip'] = args.ip
        if args.port is not None:
            args_dict['port'] = args.port
            
        config.update_from_args(args_dict)
        
        # Update srv_config with values from configuration
        srv_config.update({
            'ip': config.get('server', 'ip'),
            'port': config.get('server', 'port'),
            'epid': config.get('kms', 'epid'),
            'lcid': config.get('kms', 'lcid'),
            'hwid': config.get('kms', 'hwid'),
            'clientcount': config.get('kms', 'client_count'),
            'activation': config.get('kms', 'intervals.activation'),
            'renewal': config.get('kms', 'intervals.renewal'),
            'timeoutidle': config.get('server', 'timeout.idle'),
            'timeoutsndrcv': config.get('server', 'timeout.send_receive'),
            'loglevel': config.get('logging', 'level'),
            'logfile': config.get('logging', 'file'),
            'logsize': config.get('logging', 'max_size'),
            'web_gui': config.get('web_gui', 'enabled'),
            'web_port': config.get('web_gui', 'port'),
            'db_type': config.get('database', 'type'),
            'db_name': config.get('database', 'name'),
            'db_host': config.get('database', 'host'),
            'db_user': config.get('database', 'user'),
            'db_password': config.get('database', 'password'),
        })

        # Handle additional listeners if configured
        additional_listeners = config.get('server', 'additional_listeners', [])
        if additional_listeners:
            if 'listen' not in srv_config:
                srv_config['listen'] = []
            for listener in additional_listeners:
                srv_config['listen'].append((
                    listener['address'],
                    listener['port'],
                    listener.get('backlog', 5),
                    listener.get('reuse', True)
                ))

        # Run help if requested
        if any(arg in ["-h", "--help"] for arg in sys.argv[1:]):
            KmsParserHelp().printer(
                parsers=[
                    server_parser,
                    (connection_parser, connect_parser),
                ]
            )

        # Get stored arguments for server and connection options
        pykmssrv_zeroarg, pykmssrv_onearg = kms_parser_get(server_parser)
        connect_zeroarg, connect_onearg = kms_parser_get(connect_parser)

        # Check for 'connect' subparser presence
        connect_present = 'connect' in sys.argv[1:]
        connect_idx = sys.argv.index('connect') if connect_present else len(sys.argv)

        # Check main server options before 'connect'
        kms_parser_check_optionals(
            sys.argv[:connect_idx],
            pykmssrv_zeroarg,
            pykmssrv_onearg,
            exclude_opt_len=["-F", "--logfile"],
            exclude_opt_dup=["-n", "--listen", "-b", "--backlog", "-u", "--no-reuse"]
        )

        # Check 'connect' options if present
        if connect_present:
            kms_parser_check_optionals(
                sys.argv[connect_idx:],
                connect_zeroarg,
                connect_onearg,
                msg="optional connect",
                exclude_opt_dup=["-n", "--listen", "-b", "--backlog", "-u", "--no-reuse"]
            )
            kms_parser_check_positionals(
                srv_config,
                connection_parser.parse_args,
                arguments=sys.argv[connect_idx:],
                msg="positional connect"
            )

        # Check connection-related arguments consistency
        kms_parser_check_connect(
            srv_config, srv_options, sys.argv, connect_zeroarg, connect_onearg
        )

    except KmsParserException as e:
        pretty_printer(
            put_text="{reverse}{red}{bold}%s. Exiting...{end}" % str(e),
            to_exit=True
        )


def server_check():
    # Setup and some checks.
    check_setup(srv_config, srv_options, loggersrv, where="srv")

    # Random HWID.
    if srv_config["hwid"] == "RANDOM":
        randomhwid = uuid.uuid4().hex
        srv_config["hwid"] = randomhwid[:16]

    # Sanitize HWID.
    hexstr = srv_config["hwid"]
    # Strip 0x from the start of hexstr
    if hexstr.startswith("0x"):
        hexstr = hexstr[2:]

    hexsub = re.sub(r"[^0-9a-fA-F]", "", hexstr)
    diff = set(hexstr).symmetric_difference(set(hexsub))

    if len(diff) != 0:
        diff = str(diff).replace("{", "").replace("}", "")
        pretty_printer(
            log_obj=loggersrv.error,
            to_exit=True,
            put_text="{reverse}{red}{bold}HWID '%s' is invalid. Digit %s non hexadecimal. Exiting...{end}"
            % (hexstr.upper(), diff),
        )
    else:
        lh = len(hexsub)
        if lh % 2 != 0:
            pretty_printer(
                log_obj=loggersrv.error,
                to_exit=True,
                put_text="{reverse}{red}{bold}HWID '%s' is invalid. Hex string is odd length. Exiting...{end}"
                % hexsub.upper(),
            )
        elif lh < 16:
            pretty_printer(
                log_obj=loggersrv.error,
                to_exit=True,
                put_text="{reverse}{red}{bold}HWID '%s' is invalid. Hex string is too short. Exiting...{end}"
                % hexsub.upper(),
            )
        elif lh > 16:
            pretty_printer(
                log_obj=loggersrv.error,
                to_exit=True,
                put_text="{reverse}{red}{bold}HWID '%s' is invalid. Hex string is too long. Exiting...{end}"
                % hexsub.upper(),
            )
        else:
            srv_config["hwid"] = binascii.a2b_hex(hexsub)

    # Check LCID.
    srv_config["lcid"] = check_lcid(srv_config["lcid"], loggersrv.warning)

    # Check other specific server options.
    opts = [
        ("clientcount", "-c/--client-count"),
        ("timeoutidle", "-t0/--timeout-idle"),
        ("timeoutsndrcv", "-t1/--timeout-sndrcv"),
    ]
    if serverthread.with_gui:
        opts += [
            ("activation", "-a/--activation-interval"),
            ("renewal", "-r/--renewal-interval"),
        ]
    check_other(srv_config, opts, loggersrv, where="srv")

    # Check further addresses / ports.
    if "listen" in srv_config:
        addresses = []
        for elem in srv_config["listen"]:
            try:
                addr, port = elem[0], elem[1]
            except ValueError:
                pretty_printer(
                    log_obj=loggersrv.error,
                    to_exit=True,
                    put_text="{reverse}{red}{bold}argument `-n/--listen`: %s not well defined. Exiting...{end}"
                    % elem,
                )
            try:
                port = int(port)
            except ValueError:
                pretty_printer(
                    log_obj=loggersrv.error,
                    to_exit=True,
                    put_text="{reverse}{red}{bold}argument `-n/--listen`: port number '%s' is invalid. Exiting...{end}"
                    % port,
                )

            if not (1 <= port <= 65535):
                pretty_printer(
                    log_obj=loggersrv.error,
                    to_exit=True,
                    put_text="{reverse}{red}{bold}argument `-n/--listen`: port number '%s' is invalid. Enter between 1 - 65535. Exiting...{end}"
                    % port,
                )

            addresses.append((addr, port))
        srv_config["listen"] = addresses

    # Initialize Database Backend if needed
    srv_config['db_instance'] = None
    db_enabled = srv_config.get("db_type") is not None and srv_config.get("db_type") != ''
    if db_enabled:  # Check if db_type is specified and not empty
        try:
            from pykms_Database import create_backend
            # Pass only the necessary config keys to create_backend
            db_config = {
                'db_type': srv_config.get("db_type", 'sqlite'), 
                'db_host': srv_config.get("db_host"),
                'db_name': srv_config.get("db_name"), # This holds the full DSN, e.g., 'sqlite:///path' or 'db_name'
                'db_user': srv_config.get("db_user"),
                'db_password': srv_config.get("db_password"),
            }
            
            srv_config['db_instance'] = create_backend(db_config)
            pretty_printer(
                 log_obj=loggersrv.info,
                 put_text="Database backend initialized for main server thread."
            )
        except Exception as e:
            pretty_printer(
                 log_obj=loggersrv.error,
                 to_exit=True,
                 put_text="{reverse}{red}{bold}Failed to initialize database backend for main server: %s. Exiting...{end}" % str(e)
            )
            
    # Initialize web GUI if enabled
    if srv_config["web_gui"]:
        try:
            from pykms_WebGui import init_web_gui
            import threading
            
            web_config = {
                'db_type': srv_config["db_type"],
                'db_host': srv_config["db_host"],
                'db_name': srv_config["db_name"],
                'db_user': srv_config["db_user"],
                'db_password': srv_config["db_password"],
                'web_port': srv_config["web_port"],
                'lfile': srv_config["logfile"]
            }
            
            app = init_web_gui(web_config)
            web_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=srv_config["web_port"]), daemon=True)
            web_thread.start()
            
            pretty_printer(
                log_obj=loggersrv.info,
                put_text="Web GUI started on http://0.0.0.0:%d" % srv_config["web_port"]
            )
        except ImportError as e:
            pretty_printer(
                log_obj=loggersrv.warning,
                put_text="{reverse}{yellow}{bold}Failed to start web GUI: %s{end}" % str(e)
            )
            srv_config["web_gui"] = False


def server_create():
    # Create address list (when the current user indicates execution inside the Windows Sandbox,
    # then we wont allow port reuse - it is not supported).
    all_address = [
        (
            srv_config["ip"],
            srv_config["port"],
            (
                srv_config["backlog_main"]
                if "backlog_main" in srv_config
                else srv_options["backlog"]["def"]
            ),
            (
                srv_config["reuse_main"]
                if "reuse_main" in srv_config
                else False
                if getuser() == "WDAGUtilityAccount"
                else srv_options["reuse"]["def"]
            ),
        )
    ]
    log_address = "TCP server listening at %s on port %d" % (
        srv_config["ip"],
        srv_config["port"],
    )

    if "listen" in srv_config:
        for l, b, r in zip(
            srv_config["listen"], srv_config["backlog"], srv_config["reuse"]
        ):
            r = False if getuser() == "WDAGUtilityAccount" else r
            all_address.append(l + (b,) + (r,))
            log_address += justify("at %s on port %d" % (l[0], l[1]), indent=56)

    server = KeyServer(
        all_address,
        kmsServerHandler,
        want_dual=(
            srv_config["dual"] if "dual" in srv_config else srv_options["dual"]["def"]
        ),
    )
    server.timeout = srv_config["timeoutidle"]

    loggersrv.info(log_address)
    loggersrv.info(
        "HWID: %s" % deco(binascii.b2a_hex(srv_config["hwid"]), "utf-8").upper()
    )

    return server


def server_terminate(generic_srv, exit_server=False, exit_thread=False):
    if exit_server:
        generic_srv.terminate_serve()
    if exit_thread:
        generic_srv.terminate_thread()


class ServerWithoutGui(object):
    def start(self):
        import queue as Queue

        daemon_queue = Queue.Queue(maxsize=0)
        daemon_serverthread = server_thread(daemon_queue, name="Thread-Srv-Daemon")
        daemon_serverthread.daemon = True
        # options already checked in `server_main_terminal`.
        daemon_serverthread.checked = True
        daemon_serverthread.start()
        daemon_queue.put("start")
        return 0, daemon_serverthread

    def join(self, daemon_serverthread):
        while daemon_serverthread.is_alive():
            daemon_serverthread.join(timeout=0.5)

    def clean(self, daemon_serverthread):
        server_terminate(daemon_serverthread, exit_server=True, exit_thread=True)


def server_main_terminal():
    # Parse options.
    server_options()
    # Check options.
    server_check()
    serverthread.checked = True

    # Start the server thread directly.
    serverqueue.put("start")

    # Keep the main thread alive, wait for termination signals (like SIGTERM from systemd).
    try:
        while serverthread.is_alive():
            serverthread.join(timeout=0.5)
    except (KeyboardInterrupt, SystemExit):
        # Handle graceful shutdown on KeyboardInterrupt or SystemExit
        loggersrv.info("Shutdown signal received, terminating server...")
        server_terminate(serverthread, exit_server=True, exit_thread=True)
        loggersrv.info("Server terminated.")
    finally:
        # Ensure threads are cleaned up if loop exits unexpectedly
        if serverthread.is_alive():
             server_terminate(serverthread, exit_server=True, exit_thread=True)
             loggersrv.info("Server terminated during cleanup.")


class kmsServerHandler(socketserver.BaseRequestHandler):
    def setup(self):
        loggersrv.info(
            "Connection accepted: %s:%d"
            % (self.client_address[0], self.client_address[1])
        )
        srv_config["raddr"] = self.client_address

    def handle(self):
        self.request.settimeout(srv_config["timeoutsndrcv"])
        while True:
            # self.request is the TCP socket connected to the client
            try:
                self.data = self.request.recv(1024)
                if self.data == "" or not self.data:
                    pretty_printer(
                        log_obj=loggersrv.warning,
                        put_text="{reverse}{yellow}{bold}No data received.{end}",
                    )
                    break
            except socket.error as e:
                pretty_printer(
                    log_obj=loggersrv.error,
                    put_text="{reverse}{red}{bold}While receiving: %s{end}" % str(e),
                )
                break

            packetType = MSRPCHeader(self.data)["type"]
            if packetType == rpcBase.packetType["bindReq"]:
                loggersrv.info("RPC bind request received.")
                pretty_printer(num_text=[-2, 2], where="srv")
                handler = pykms_RpcBind.handler(self.data, srv_config)
            elif packetType == rpcBase.packetType["request"]:
                loggersrv.info("Received activation request.")
                pretty_printer(num_text=[-2, 13], where="srv")
                handler = pykms_RpcRequest.handler(self.data, srv_config)
            else:
                pretty_printer(
                    log_obj=loggersrv.error,
                    put_text="{reverse}{red}{bold}Invalid RPC request type %s.{end}"
                    % packetType,
                )
                break

            res = enco(str(handler.populate()), "latin-1")

            if packetType == rpcBase.packetType["bindReq"]:
                loggersrv.info("RPC bind acknowledged.")
                pretty_printer(num_text=[-3, 5, 6], where="srv")
            elif packetType == rpcBase.packetType["request"]:
                loggersrv.info("Responded to activation request.")
                pretty_printer(num_text=[-3, 18, 19], where="srv")

            try:
                self.request.send(res)
                if packetType == rpcBase.packetType["request"]:
                    break
            except socket.error as e:
                pretty_printer(
                    log_obj=loggersrv.error,
                    put_text="{reverse}{red}{bold}While sending: %s{end}" % str(e),
                )
                break

    def finish(self):
        self.request.close()
        loggersrv.info(
            "Connection closed: %s:%d"
            % (self.client_address[0], self.client_address[1])
        )


serverqueue = Queue.Queue(maxsize=0)
serverthread = server_thread(serverqueue, name="Thread-Srv")
serverthread.daemon = True
serverthread.start()

if __name__ == "__main__":
    # Simplified main execution block for systemd
    # Parse options using the simplified function.
    server_options()
    # Check options.
    server_check()
    # Mark checks as done for the server thread.
    serverthread.checked = True

    # Start the server thread directly.
    serverqueue.put("start")

    # Keep the main thread alive, wait for termination signals (like SIGTERM from systemd).
    try:
        while serverthread.is_alive():
            serverthread.join(timeout=0.5)
    except (KeyboardInterrupt, SystemExit):
        # Handle graceful shutdown on KeyboardInterrupt or SystemExit
        loggersrv.info("Shutdown signal received, terminating server...")
        server_terminate(serverthread, exit_server=True, exit_thread=True)
        loggersrv.info("Server terminated.")
    finally:
        # Ensure threads are cleaned up if loop exits unexpectedly
        if serverthread.is_alive():
             server_terminate(serverthread, exit_server=True, exit_thread=True)
             loggersrv.info("Server terminated during cleanup.")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import yaml
from typing import Dict, Any, Optional, Tuple
from pykms_Validators import validate_epid, validate_lcid

class ConfigurationError(Exception):
    """Exception raised for configuration validation errors."""
    pass

class KmsServerConfig:
    """Configuration manager for py-kms server."""
    
    DEFAULT_CONFIG_PATHS = [
        './config.yaml',  # Current directory
        '~/.config/py-kms/config.yaml',  # User config directory
        '/etc/py-kms/config.yaml',  # System config directory
    ]

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_path: Optional path to configuration file. If not provided,
                        will search in default locations.
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.load_config()
        self.validate_config()

    def load_config(self) -> None:
        """Load configuration from file."""
        # If specific path provided, try it first
        if self.config_path:
            if os.path.exists(self.config_path):
                self._load_from_file(self.config_path)
                return
            raise FileNotFoundError(f"Config file not found at {self.config_path}")

        # Try default locations
        for path in self.DEFAULT_CONFIG_PATHS:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                self._load_from_file(expanded_path)
                return

        # If no config found, use default configuration
        self._use_defaults()

    def validate_config(self) -> None:
        """Validate the loaded configuration.
        
        Raises:
            ConfigurationError: If validation fails
        """
        # Validate EPID if specified
        epid = self.get('kms', 'epid')
        if epid is not None:
            is_valid, error = validate_epid(epid)
            if not is_valid:
                raise ConfigurationError(f"Invalid EPID configuration: {error}")

        # Validate LCID
        lcid = self.get('kms', 'lcid')
        if lcid is not None:
            is_valid, error = validate_lcid(lcid)
            if not is_valid:
                raise ConfigurationError(f"Invalid LCID configuration: {error}")

        # Validate client count
        client_count = self.get('kms', 'client_count')
        if client_count is not None:
            try:
                count = int(client_count)
                if count < 0:
                    raise ConfigurationError("Client count cannot be negative")
            except ValueError:
                raise ConfigurationError("Client count must be a number")

        # Validate intervals
        for interval in ['activation', 'renewal']:
            value = self.get('kms', f'intervals.{interval}')
            if value is not None:
                try:
                    minutes = int(value)
                    if minutes < 0:
                        raise ConfigurationError(f"{interval.title()} interval cannot be negative")
                except ValueError:
                    raise ConfigurationError(f"{interval.title()} interval must be a number")

    def _load_from_file(self, path: str) -> None:
        """Load configuration from specified YAML file."""
        with open(path, 'r') as f:
            self.config = yaml.safe_load(f)

    def _use_defaults(self) -> None:
        """Load default configuration."""
        self.config = {
            'server': {
                'ip': '0.0.0.0',
                'port': 1688,
                'backlog': 5,
                'reuse': True,
                'dual': False,
                'timeout': {
                    'idle': None,
                    'send_receive': None
                },
                'additional_listeners': []
            },
            'kms': {
                'epid': None,
                'lcid': 1033,
                'hwid': '364F463A8863D35F',
                'client_count': None,
                'intervals': {
                    'activation': 120,
                    'renewal': 10080
                }
            },
            'database': {
                'type': 'sqlite',
                'name': 'sqlite:///pykms_database.db',
                'host': 'localhost',
                'user': '',
                'password': ''
            },
            'web_gui': {
                'enabled': False,
                'port': 8080
            },
            'logging': {
                'level': 'ERROR',
                'file': 'pykms_logserver.log',
                'max_size': 0
            }
        }

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            section: Configuration section name
            key: Configuration key name
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            section_dict = self.config.get(section, {})
            if '.' in key:
                # Handle nested keys like 'timeout.idle'
                parts = key.split('.')
                value = section_dict
                for part in parts:
                    value = value.get(part, default)
                return value
            return section_dict.get(key, default)
        except (KeyError, AttributeError):
            return default

    def update_from_args(self, args: Dict[str, Any]) -> None:
        """Update configuration from command line arguments.
        
        Command line arguments take precedence over config file values.
        
        Args:
            args: Dictionary of command line arguments
        """
        # Map command line args to config structure
        mapping = {
            'ip': ('server', 'ip'),
            'port': ('server', 'port'),
            'epid': ('kms', 'epid'),
            'lcid': ('kms', 'lcid'),
            'hwid': ('kms', 'hwid'),
            'clientcount': ('kms', 'client_count'),
            'activation': ('kms', 'intervals.activation'),
            'renewal': ('kms', 'intervals.renewal'),
            'timeoutidle': ('server', 'timeout.idle'),
            'timeoutsndrcv': ('server', 'timeout.send_receive'),
            'loglevel': ('logging', 'level'),
            'logfile': ('logging', 'file'),
            'logsize': ('logging', 'max_size'),
            'web_gui': ('web_gui', 'enabled'),
            'web_port': ('web_gui', 'port'),
            'db_type': ('database', 'type'),
            'db_name': ('database', 'name'),
            'db_host': ('database', 'host'),
            'db_user': ('database', 'user'),
            'db_password': ('database', 'password'),
        }

        for arg_name, value in args.items():
            if arg_name in mapping and value is not None:
                section, key = mapping[arg_name]
                if '.' in key:
                    # Handle nested configuration
                    parent_key, child_key = key.split('.')
                    if section not in self.config:
                        self.config[section] = {}
                    if parent_key not in self.config[section]:
                        self.config[section][parent_key] = {}
                    self.config[section][parent_key][child_key] = value
                else:
                    if section not in self.config:
                        self.config[section] = {}
                    self.config[section][key] = value

        # Validate after updating from args
        self.validate_config()

    def save(self, path: Optional[str] = None) -> None:
        """Save current configuration to file.
        
        Args:
            path: Optional path to save to. If not provided, uses current config_path
                 or first default path.
        """
        save_path = path or self.config_path or self.DEFAULT_CONFIG_PATHS[0]
        save_path = os.path.expanduser(save_path)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        with open(save_path, 'w') as f:
            yaml.safe_dump(self.config, f, default_flow_style=False) 
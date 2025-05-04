#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import socket
from typing import Optional, Tuple

def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
    """Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip: The IP address to validate
        
    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str])
    """
    if not ip:
        return False, "IP address cannot be empty"

    # Check for IPv4
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True, None
    except socket.error:
        pass

    # Check for IPv6
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True, None
    except socket.error:
        return False, f"'{ip}' does not appear to be an IPv4 or IPv6 address"

def validate_epid(epid: str) -> Tuple[bool, Optional[str]]:
    """Validate a KMS Enterprise ID (EPID).
    
    Format: XXXXX-XXXXX-XXX-XXXXXX-XX-XXXX-XXXX.XXXX-XXXXXXXX
    Where:
    - Part 1: Platform ID (5 digits)
    - Part 2: Group ID (5 digits)
    - Part 3: Product Key ID Part 1 (3 digits)
    - Part 4: Product Key ID Part 2 (6 digits)
    - Part 5: License Channel (2 digits, usually 03 for Volume)
    - Part 6: Language Code (4 digits)
    - Part 7: KMS Server OS Build (4 digits + .0000)
    - Part 8: Activation Date (3 digits for day + 4 digits for year)
    
    Args:
        epid: The EPID string to validate
        
    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str])
    """
    if not epid:
        return False, "EPID cannot be empty"

    # Basic format check with regex
    pattern = r'^\d{5}-\d{5}-\d{3}-\d{6}-\d{2}-\d{4}-\d{4}\.0000-\d{7}$'
    if not re.match(pattern, epid):
        return False, "EPID format invalid. Expected: XXXXX-XXXXX-XXX-XXXXXX-XX-XXXX-XXXX.0000-XXXXXXX"

    # Split into components
    try:
        parts = epid.replace('.0000-', '-').split('-')
        if len(parts) != 8:
            return False, "EPID must have 8 parts"

        platform_id = int(parts[0])
        group_id = int(parts[1])
        key_id1 = int(parts[2])
        key_id2 = int(parts[3])
        license_channel = int(parts[4])
        language_code = int(parts[5])
        build_number = int(parts[6])
        activation_date = int(parts[7])

        # Validate specific parts
        if license_channel != 3:
            return False, "License channel should be 03 for Volume licensing"

        # Validate activation date
        day = int(str(activation_date)[:3])
        year = int(str(activation_date)[3:])
        if not (1 <= day <= 366 and 2000 <= year <= 2099):
            return False, "Invalid activation date format"

        return True, None

    except (ValueError, IndexError):
        return False, "EPID contains invalid numeric values"

def validate_lcid(lcid: int) -> Tuple[bool, Optional[str]]:
    """Validate a Language Code ID (LCID).
    
    Args:
        lcid: The LCID to validate
        
    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str])
    """
    from pykms_Misc import ValidLcid

    if not isinstance(lcid, int):
        return False, "LCID must be an integer"

    if lcid not in ValidLcid:
        return False, f"Invalid LCID: {lcid}. Must be one of the valid Microsoft LCID values."

    return True, None 
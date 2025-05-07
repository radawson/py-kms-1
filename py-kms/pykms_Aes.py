#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# aes.py: implements AES - Advanced Encryption Standard
# from the SlowAES project, http://code.google.com/p/slowaes/
#
# Copyright (c) 2008    Josh Davis ( http://www.josh-davis.org )
#                       Alex Martelli ( http://www.aleax.it )
#
# Modified for py-kms, Python 2 / 3 compatible 
# Copyright (c) 2019    Matteo Fan  ( SystemRage@protonmail.com )
#
# Ported from C code written by Laurent Haan ( http://www.progressive-coding.com )

# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/
#

from __future__ import print_function, unicode_literals
import os
import math

def append_PKCS7_padding(val):
    """Applies PKCS#7 padding to the input byte string.

    PKCS#7 padding ensures that the data is a multiple of the block size (16 bytes for AES).
    It appends N bytes, each with the value N, where N is the number of bytes needed
    to reach the next block size multiple.

    Args:
        val (bytes or bytearray): The input data to be padded.

    Returns:
        bytes: The padded data.
    """
    numpads = 16 - (len(val) % 16)
    return val + bytes([numpads] * numpads) # Changed to bytes for compatibility

def strip_PKCS7_padding(val):
    """Removes PKCS#7 padding from a decrypted byte string.

    It checks if the padding is valid and removes it.

    Args:
        val (bytes or bytearray): The input data from which padding is to be stripped.

    Returns:
        bytes: The unpadded data.

    Raises:
        ValueError: If the input data is not a multiple of 16 bytes,
                    is empty, or has invalid padding.
    """
    if not isinstance(val, (bytes, bytearray)):
        raise TypeError("Input must be bytes or bytearray")
    if len(val) % 16 or not val:
        raise ValueError("Data of len %d can't be PKCS7-padded" % len(val))
    
    numpads = val[-1]
    
    # numpads must be an integer if val is bytes, directly accessible.
    # If val was bytearray, val[-1] would also be an int.
    if not (1 <= numpads <= 16):
        # More specific error for invalid padding byte value
        raise ValueError("Padding byte %r (value %d) is out of valid range [1, 16]" % (val[-1:], numpads))

    # Check if all padding bytes are correct
    for i in range(1, numpads + 1):
        if val[-i] != numpads:
            raise ValueError("Invalid PKCS#7 padding sequence.")

    return val[:-numpads]


class AES( object ):
    """
    Implements the Advanced Encryption Standard (AES) algorithm.

    This class provides the core AES encryption and decryption functionalities,
    including key expansion, S-box substitutions, row shifting, column mixing,
    and round key additions. It's based on the Rijndael algorithm.

    Attributes:
        v6 (bool): A flag related to KMS v6 protocol specifics, possibly affecting
                   certain AES operations or parameters. Default is False.
        KeySize (dict): A dictionary mapping symbolic key size names
                        (e.g., "SIZE_128") to their byte lengths (e.g., 16).
        sbox (list): The Rijndael S-box table used for byte substitution in encryption.
        rsbox (list): The Rijndael inverse S-box table used for byte substitution
                      in decryption.
        Rcon (list): The Rijndael round constant table used in the key expansion process.
    """
    
    #*py-kms*
    v6 = False

    # Valid key sizes
    KeySize = {
                "SIZE_128": 16,
                "SIZE_192": 24,
                "SIZE_256": 32
                }

    # Rijndael S-box
    sbox =  [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
              0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
              0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
              0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
              0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
              0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
              0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
              0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
              0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
              0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
              0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
              0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
              0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
              0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
              0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
              0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
              0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
              0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
              0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
              0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
              0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
              0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
              0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
              0x54, 0xbb, 0x16 ]

    # Rijndael Inverted S-box
    rsbox = [ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
              0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
              0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
              0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
              0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
              0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
              0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
              0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
              0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
              0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
              0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
              0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
              0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
              0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
              0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
              0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
              0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
              0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
              0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
              0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
              0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
              0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
              0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
              0x21, 0x0c, 0x7d ]

    # Rijndael Rcon
    Rcon = [ 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
             0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
             0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
             0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
             0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
             0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
             0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
             0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
             0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
             0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
             0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
             0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
             0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
             0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb ]

    def getSBoxValue(self,num):
        """Retrieves a value from the S-box.

        Args:
            num (int): The index (0-255) into the S-box.

        Returns:
            int: The S-box value at the given index.
        """
        return self.sbox[num]

    def getSBoxInvert(self,num):
        """Retrieves a value from the inverse S-box.

        Args:
            num (int): The index (0-255) into the inverse S-box.

        Returns:
            int: The inverse S-box value at the given index.
        """
        return self.rsbox[num]

    def rotate(self, word):
        """Performs a cyclic left shift on a 4-byte word.

        Example: rotate([0x1d, 0x2c, 0x3a, 0x4f]) == [0x2c, 0x3a, 0x4f, 0x1d]

        Args:
            word (list of int): A list of 4 bytes (integers 0-255).

        Returns:
            list of int: The rotated word.
        """
        return word[1:] + word[:1]

    def getRconValue(self, num):
        """Retrieves a value from the Rcon (round constant) table.

        Args:
            num (int): The index into the Rcon table.

        Returns:
            int: The Rcon value at the given index.
        """
        return self.Rcon[num]

    def core(self, word, iteration):
        """Performs the core schedule operation for AES key expansion.

        This involves rotating the word, applying S-box substitution to each byte,
        and XORing the first byte with a round constant from the Rcon table.

        Args:
            word (list of int): A 4-byte word (list of integers).
            iteration (int): The current Rcon iteration number.

        Returns:
            list of int: The processed 4-byte word.
        """
        # Rotate the 32-bit word 8 bits to the left.
        word = self.rotate(word)
        # Apply S-Box substitution on all 4 parts of the 32-bit word.
        for i in range(4):
            word[i] = self.getSBoxValue(word[i])
        # XOR the output of the rcon operation with i to the first part (leftmost) only.
        word[0] = word[0] ^ self.getRconValue(iteration)
        return word

    def expandKey(self, key, size, expandedKeySize):
        """Expands the initial AES key into a set of round keys.

        The expansion process differs slightly for different key sizes (128, 192, 256 bits).

        Args:
            key (list of int): The initial AES key as a list of bytes (integers).
            size (int): The size of the initial key in bytes (16, 24, or 32).
            expandedKeySize (int): The total size of the expanded key in bytes.
                                   (e.g., 176 for 128-bit key, 208 for 192-bit, 240 for 256-bit).

        Returns:
            list of int: The expanded key schedule as a list of bytes.
        """
        # Current expanded keySize, in bytes.
        currentSize = 0
        rconIteration = 1
        expandedKey = [0] * expandedKeySize

        # Set the 16, 24, 32 bytes of the expanded key to the input key.
        for j in range(size):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expandedKeySize:
            # Assign the previous 4 bytes to the temporary value t.
            t = list(expandedKey[currentSize - 4:currentSize]) # Ensure t is a mutable list

            # Every 16,24,32 bytes we apply the core schedule to t
            # and increment rconIteration afterwards.
            if currentSize % size == 0:
                t = self.core(t, rconIteration)
                rconIteration += 1
            # For 256-bit keys, we add an extra sbox to the calculation.
            if size == self.KeySize["SIZE_256"] and ((currentSize % size) == 16):
                for l_idx in range(4): # Renamed l to l_idx to avoid conflict
                    t[l_idx] = self.getSBoxValue(t[l_idx])

            # We XOR t with the four-byte block 16,24,32 bytes before the new
            # expanded key. This becomes the next four bytes in the expanded key.
            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[m]
                currentSize += 1
        return expandedKey

    def addRoundKey(self, state, roundKey):
        """XORs the current state with the round key.

        This is a step in each round of AES encryption and decryption.

        Args:
            state (list of int): The 16-byte state matrix as a flat list.
            roundKey (list of int): The 16-byte round key.

        Returns:
            list of int: The updated state matrix.
        """
        for i in range(16):
            state[i] ^= roundKey[i]
        return state

    def createRoundKey(self, expandedKey, roundKeyPointer):
        """Extracts a 16-byte round key from the expanded key schedule.

        The bytes are rearranged from the linear expanded key into the
        column-major order expected for a round key.

        Args:
            expandedKey (list of int): The full expanded key schedule.
            roundKeyPointer (int): The starting index in the expandedKey
                                   for the current round key.

        Returns:
            list of int: The 16-byte round key.
        """
        roundKey = [0] * 16
        for i in range(4): # columns
            for j in range(4): # rows
                roundKey[j * 4 + i] = expandedKey[roundKeyPointer + i * 4 + j]
        return roundKey

    def galois_multiplication(self, a, b):
        """Performs multiplication in the Galois Field GF(2^8).

        This operation is used in the MixColumns step of AES.
        The irreducible polynomial used is x^8 + x^4 + x^3 + x + 1 (0x11b).

        Args:
            a (int): An 8-bit integer.
            b (int): An 8-bit integer.

        Returns:
            int: The result of a * b in GF(2^8).
        """
        p = 0
        for _counter in range(8): # Renamed counter to _counter
            if b & 1: # if the LSB of b is 1
                p ^= a
            
            hi_bit_set = (a & 0x80) # Check if MSB of a is 1
            a <<= 1
            a &= 0xFF # Ensure 'a' remains 8-bit
            if hi_bit_set:
                a ^= 0x1b # XOR with the AES irreducible polynomial (0x11b becomes 0x1b after MSB is shifted out)
            
            b >>= 1
        return p

    def subBytes(self, state, isInv):
        """Applies the S-box (or inverse S-box) substitution to each byte of the state.

        Args:
            state (list of int): The 16-byte state matrix.
            isInv (bool): If True, uses the inverse S-box (for decryption).
                          If False, uses the forward S-box (for encryption).

        Returns:
            list of int: The state matrix after byte substitution.
        """
        if isInv:
            getter = self.getSBoxInvert
        else:
            getter = self.getSBoxValue
        for i in range(16):
            state[i] = getter(state[i])
        return state

    def shiftRows(self, state, isInv):
        """Cyclically shifts the bytes in each row of the state.

        The shifts are:
        - Row 0: No shift
        - Row 1: 1-byte cyclic left shift (or right for inverse)
        - Row 2: 2-byte cyclic left shift (or right for inverse)
        - Row 3: 3-byte cyclic left shift (or right for inverse)

        Args:
            state (list of int): The 16-byte state matrix (viewed as 4x4).
            isInv (bool): If True, performs right shifts (for decryption).
                          If False, performs left shifts (for encryption).

        Returns:
            list of int: The state matrix after row shifting.
        """
        # The state is a flat list of 16 bytes.
        # It's treated conceptually as a 4x4 matrix where columns are contiguous:
        # s0 s4 s8  s12
        # s1 s5 s9  s13
        # s2 s6 s10 s14
        # s3 s7 s11 s15
        #
        # Rows for shifting are:
        # Row 0: s0, s4, s8,  s12
        # Row 1: s1, s5, s9,  s13
        # Row 2: s2, s6, s10, s14
        # Row 3: s3, s7, s11, s15

        for r in range(4): # r is the row number
            row_indices = [r + 4*c for c in range(4)] # Indices for the current row
            row_values = [state[i] for i in row_indices]
            
            num_shifts = r # Shift amount for this row
            
            if num_shifts == 0:
                continue

            if isInv: # Right shift for decryption
                shifted_row = row_values[-num_shifts:] + row_values[:-num_shifts]
            else: # Left shift for encryption
                shifted_row = row_values[num_shifts:] + row_values[:num_shifts]
            
            for i_idx, original_idx in enumerate(row_indices): # Renamed i to i_idx
                state[original_idx] = shifted_row[i_idx]
                
        return state

    def shiftRow(self, state, statePointer, nbr, isInv):
        """DEPRECATED/INTERNAL: Original shiftRow implementation.
        
        This method appears to be an older way of performing row shifts,
        operating on a flat state list with a pointer and assuming rows
        are contiguous, which is not the standard AES state representation.
        The `shiftRows` method is the more standard implementation.
        
        Args:
            state (list of int): The state.
            statePointer (int): Starting index of the 4-byte row in the state.
            nbr (int): The number of shifts to perform.
            isInv (bool): True for inverse shift (right), False for forward (left).
            
        Returns:
            list of int: The modified state.
        """
        # This implementation assumes rows are laid out contiguously in the state array,
        # which is not how the AES state matrix is typically handled for ShiftRows.
        # Standard ShiftRows operates on rows taken from columns.
        # For example, row 1 is state[1], state[5], state[9], state[13].
        # This function treats a 4-byte slice starting at statePointer as a "row".
        # Given its direct use in an older `shiftRows_orig` and not in `aes_round`,
        # it might be part of a different interpretation or an artifact.
        # For py-kms, the main `shiftRows` function above is what aligns with standard AES.
        row = state[statePointer : statePointer + 4]
        if nbr == 0:
            return state # No change

        if isInv: # Right circular shift
            for _i in range(nbr): # Renamed i to _i
                row = [row[-1]] + row[:-1]
        else: # Left circular shift
            for _i in range(nbr): # Renamed i to _i
                row = row[1:] + [row[0]]
        
        state[statePointer : statePointer + 4] = row
        return state
        
    #*py-kms* (old implementation)
    #def shiftRows_orig(self, state, isInv):\n    #    \"\"\" Method to iterate over the 4 rows and call shiftRow(...) with that row. \"\"\"\n    #    for i in range(4):\n    #        state = self.shiftRow(state, i * 4, i, isInv)\n    #    return state

    def mixColumns(self, state, isInv):
        """Performs the MixColumns transformation on the AES state.

        Each column of the state is treated as a polynomial over GF(2^8) and
        multiplied by a fixed polynomial modulo x^4 + 1.

        Args:
            state (list of int): The 16-byte state matrix.
            isInv (bool): If True, performs the inverse MixColumns operation.
                          If False, performs the forward MixColumns operation.

        Returns:
            list of int: The state matrix after the MixColumns transformation.
        """
        # iterate over the 4 columns
        for i in range(4):
            # construct one column by taking one value from each row
            column = [state[i + 4*j] for j in range(4)]
            # apply the mixColumn on one column
            column = self.mixColumn(column, isInv)
            # put the values back into the state
            for j in range(4):
                state[i + 4*j] = column[j]
        return state

    def mixColumn(self, column, isInv):
        """Performs the MixColumns operation on a single column.

        Args:
            column (list of int): A 4-byte column from the state matrix.
            isInv (bool): If True, uses the inverse MixColumns matrix.
                          If False, uses the forward MixColumns matrix.

        Returns:
            list of int: The transformed 4-byte column.
        """
        if isInv:
            mult = [14, 9, 13, 11]
        else:
            mult = [2, 1, 1, 3]
        
        # Store temporarily for calculation
        c = list(column) # Ensure we're working with a copy

        column[0] = self.galois_multiplication(c[0], mult[0]) ^ \
                    self.galois_multiplication(c[1], mult[3]) ^ \
                    self.galois_multiplication(c[2], mult[2]) ^ \
                    self.galois_multiplication(c[3], mult[1])
        column[1] = self.galois_multiplication(c[0], mult[1]) ^ \
                    self.galois_multiplication(c[1], mult[0]) ^ \
                    self.galois_multiplication(c[2], mult[3]) ^ \
                    self.galois_multiplication(c[3], mult[2])
        column[2] = self.galois_multiplication(c[0], mult[2]) ^ \
                    self.galois_multiplication(c[1], mult[1]) ^ \
                    self.galois_multiplication(c[2], mult[0]) ^ \
                    self.galois_multiplication(c[3], mult[3])
        column[3] = self.galois_multiplication(c[0], mult[3]) ^ \
                    self.galois_multiplication(c[1], mult[2]) ^ \
                    self.galois_multiplication(c[2], mult[1]) ^ \
                    self.galois_multiplication(c[3], mult[0])
        return column

    def aes_round(self, state, roundKey):
        """Performs one round of AES encryption.

        Consists of SubBytes, ShiftRows, MixColumns, and AddRoundKey.
        The MixColumns step is skipped in the final round.

        Args:
            state (list of int): The 16-byte state matrix.
            roundKey (list of int): The 16-byte round key for this round.

        Returns:
            list of int: The state matrix after one encryption round.
        """
        state = self.subBytes(state, False)
        state = self.shiftRows(state, False)
        # MixColumns is not performed on the last round
        # This check should ideally be handled by the caller (aes_main)
        # or this function needs to know if it's the last round.
        # For py-kms, kms.v6 seems to control this.
        if not self.v6: # Original condition was: if not roundKms
            state = self.mixColumns(state, False)
        state = self.addRoundKey(state, roundKey)
        return state

    def aes_invRound(self, state, roundKey):
        """Performs one round of AES decryption.

        Consists of Inverse ShiftRows, Inverse SubBytes, AddRoundKey,
        and (if not the first round of decryption) Inverse MixColumns.
        Order differs from encryption.

        Args:
            state (list of int): The 16-byte state matrix.
            roundKey (list of int): The 16-byte round key for this round.

        Returns:
            list of int: The state matrix after one decryption round.
        """
        state = self.shiftRows(state, True)
        state = self.subBytes(state, True)
        state = self.addRoundKey(state, roundKey)
        # Inverse MixColumns is not performed on the first round of decryption (last round of encryption)
        # This check, like in aes_round, depends on context (is it the round that corresponds
        # to the one before the final AddRoundKey in encryption?).
        # The v6 flag appears to be the control mechanism here.
        if not self.v6: # Original condition was: if not roundKms
            state = self.mixColumns(state, True)
        return state

    def aes_main(self, state, expandedKey, nbrRounds):
        """Performs the main AES encryption process over multiple rounds.

        Args:
            state (list of int): The initial 16-byte plaintext state.
            expandedKey (list of int): The expanded key schedule.
            nbrRounds (int): The number of rounds to perform (10, 12, or 14).

        Returns:
            list of int: The 16-byte ciphertext state.
        """
        # Initial AddRoundKey
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        
        # Main rounds
        i = 1
        while i < nbrRounds:
            state = self.aes_round(state, self.createRoundKey(expandedKey, 16 * i))
            i += 1
            
        # Final round (SubBytes, ShiftRows, AddRoundKey - no MixColumns)
        state = self.subBytes(state, False)
        state = self.shiftRows(state, False)
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 16 * nbrRounds))
        return state

    def aes_invMain(self, state, expandedKey, nbrRounds):
        """Performs the main AES decryption process over multiple rounds.

        Args:
            state (list of int): The initial 16-byte ciphertext state.
            expandedKey (list of int): The expanded key schedule.
            nbrRounds (int): The number of rounds to perform (10, 12, or 14).

        Returns:
            list of int: The 16-byte plaintext state.
        """
        # Initial AddRoundKey (using the last round key from encryption)
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 16 * nbrRounds))
        
        # Main rounds (in reverse order)
        i = nbrRounds - 1
        while i > 0:
            state = self.aes_invRound(state, self.createRoundKey(expandedKey, 16 * i))
            i -= 1
            
        # Final round of decryption (Inverse ShiftRows, Inverse SubBytes, AddRoundKey - no InvMixColumns)
        state = self.shiftRows(state, True)
        state = self.subBytes(state, True)
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        return state

    def encrypt(self, iput, key, size):
        """Encrypts a 16-byte block of data using AES.

        Args:
            iput (list of int or bytes/bytearray): The 16-byte plaintext block.
                                                    If bytes/bytearray, it's converted to a list of ints.
            key (list of int or bytes/bytearray): The AES key (16, 24, or 32 bytes).
                                                  If bytes/bytearray, converted to list of ints.
            size (int): The key size in bytes (16, 24, or 32).

        Returns:
            list of int: The 16-byte ciphertext block as a list of integers.

        Raises:
            ValueError: If input or key length is incorrect.
        """
        if len(iput) != 16:
            raise ValueError("Input data block must be 16 bytes long.")
        if len(key) != size:
            raise ValueError("Key length must match the specified key size (%d bytes)." % size)

        # Convert input and key to list of integers if they are bytes/bytearray
        if isinstance(iput, (bytes, bytearray)):
            plain_state = list(iput)
        elif isinstance(iput, list) and all(isinstance(x, int) for x in iput):
            plain_state = list(iput) # Ensure it's a mutable copy
        else:
            raise TypeError("Input 'iput' must be bytes, bytearray, or a list of integers.")

        if isinstance(key, (bytes, bytearray)):
            key_list = list(key)
        elif isinstance(key, list) and all(isinstance(x, int) for x in key):
            key_list = list(key)
        else:
            raise TypeError("Input 'key' must be bytes, bytearray, or a list of integers.")


        output = [0] * 16
        # Number of rounds.
        if size == self.KeySize["SIZE_128"]:
            nbrRounds = 10
        elif size == self.KeySize["SIZE_192"]:
            nbrRounds = 12
        elif size == self.KeySize["SIZE_256"]:
            nbrRounds = 14
        else:
            raise ValueError("Invalid key size: %d bytes" % size)

        # The expanded keySize depends on the number of rounds. (nbrRounds+1) * 16 bytes
        expandedKeySize = 16 * (nbrRounds + 1)
        
        expandedKey = self.expandKey(key_list, size, expandedKeySize)

        # Encrypt the block.
        output = self.aes_main(plain_state, expandedKey, nbrRounds)
        return output

    def decrypt(self, iput, key, size):
        """Decrypts a 16-byte block of data using AES.

        Args:
            iput (list of int or bytes/bytearray): The 16-byte ciphertext block.
                                                    If bytes/bytearray, converted to list of ints.
            key (list of int or bytes/bytearray): The AES key (16, 24, or 32 bytes).
                                                  If bytes/bytearray, converted to list of ints.
            size (int): The key size in bytes (16, 24, or 32).

        Returns:
            list of int: The 16-byte plaintext block as a list of integers.
            
        Raises:
            ValueError: If input or key length is incorrect.
        """
        if len(iput) != 16:
            raise ValueError("Input data block must be 16 bytes long.")
        if len(key) != size:
            raise ValueError("Key length must match the specified key size (%d bytes)." % size)

        # Convert input and key to list of integers if they are bytes/bytearray
        if isinstance(iput, (bytes, bytearray)):
            cipher_state = list(iput)
        elif isinstance(iput, list) and all(isinstance(x, int) for x in iput):
            cipher_state = list(iput) # Ensure it's a mutable copy
        else:
            raise TypeError("Input 'iput' must be bytes, bytearray, or a list of integers.")

        if isinstance(key, (bytes, bytearray)):
            key_list = list(key)
        elif isinstance(key, list) and all(isinstance(x, int) for x in key):
            key_list = list(key)
        else:
            raise TypeError("Input 'key' must be bytes, bytearray, or a list of integers.")


        output = [0] * 16
        # Number of rounds.
        if size == self.KeySize["SIZE_128"]:
            nbrRounds = 10
        elif size == self.KeySize["SIZE_192"]:
            nbrRounds = 12
        elif size == self.KeySize["SIZE_256"]:
            nbrRounds = 14
        else:
            raise ValueError("Invalid key size: %d bytes" % size)

        # The expanded keySize depends on the number of rounds. (nbrRounds+1) * 16 bytes
        expandedKeySize = 16 * (nbrRounds + 1)

        expandedKey = self.expandKey(key_list, size, expandedKeySize)
        
        # Decrypt the block.
        output = self.aes_invMain(cipher_state, expandedKey, nbrRounds)
        return output


class AESModeOfOperation( object ):
    """
    Implements common AES modes of operation like CBC, CFB, OFB, and ECB.

    This class wraps the core AES algorithm to provide block cipher modes.
    It handles Initialization Vectors (IVs) and chaining of blocks as required
    by the specific mode.

    Attributes:
        aes (AES): An instance of the AES core algorithm class.
        ModeOfOperation (dict): Maps mode names (e.g., "CBC") to internal identifiers.
        KMS_RNG_CHOICES (tuple): A tuple of characters used for generating
                                 a pseudo-random salt in KMS v6 context.
    """
    
    aes = AES()

    # Supported modes of operation.
    ModeOfOperation = {
                        "OFB":1,    # Output Feedback
                        "CFB":2,    # Cipher Feedback
                        "CBC":3,    # Cipher-Block Chaining
                        "ECB":4     # Electronic Code Book (not recommended for general use)
                       }
    
    # KMS_RNG from kms-v6.c
    KMS_RNG_CHOICES = tuple("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

    def convertString(self, string, start, end, mode):
        """Converts a part of a string/bytes to a list of integers (byte values).

        Args:
            string (bytes or bytearray): The input byte string.
            start (int): The starting index in the string.
            end (int): The ending index (exclusive) in the string.
            mode: Unused parameter (artifact?).

        Returns:
            list of int: A list of byte values from the specified part of the string.
        """
        if end - start > 16: 
            end = start + 16
        # Ensure string is bytes or bytearray before slicing
        if not isinstance(string, (bytes, bytearray)):
            raise TypeError("Input 'string' must be bytes or bytearray.")
        return list(string[start:end])

    def encrypt(self, stringIn, mode, key, size, IV):
        """Encrypts an input string using AES with a specified mode of operation.

        Handles padding (PKCS#7) for modes that require it (CBC).

        Args:
            stringIn (bytes or bytearray): The plaintext data to encrypt.
            mode (int): The AES mode of operation (from ModeOfOperation dict).
            key (bytes or bytearray): The AES key.
            size (int): The key size in bytes (16, 24, or 32).
            IV (bytes or bytearray): The Initialization Vector (16 bytes).
                                     Required for CBC, CFB, OFB. Ignored for ECB.

        Returns:
            bytes: The encrypted ciphertext.

        Raises:
            ValueError: If an unsupported mode is specified or IV is missing/invalid.
        """
        if not isinstance(stringIn, (bytes, bytearray)):
            raise TypeError("Input 'stringIn' must be bytes or bytearray")
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Input 'key' must be bytes or bytearray")
        if IV is not None and not isinstance(IV, (bytes, bytearray)):
            raise TypeError("Input 'IV' must be bytes or bytearray, or None for ECB")

        if len(key) != size:
            raise ValueError("Key length %d does not match specified size %d" % (len(key), size))
        if IV is not None and len(IV) != 16 and mode != self.ModeOfOperation["ECB"]:
            raise ValueError("IV length must be 16 bytes for this mode.")


        # Pad the input stringIn
        # if mode == self.ModeOfOperation["CBC"]: # Padding is typically always applied for block ciphers unless handled externally
        stringIn = append_PKCS7_padding(stringIn)
        
        inputSize = len(stringIn)
        cipher = [0] * inputSize
        # ivec is mutable list of ints
        ivec = list(IV) if IV else [0] * 16 # Default IV for ECB, though not used by it

        # Key as list of ints
        key_list = list(key)

        for start_idx in range(0, inputSize, 16): # Renamed start to start_idx
            block = self.convertString(stringIn, start_idx, start_idx + 16, mode)
            
            if mode == self.ModeOfOperation["CBC"]:
                for i in range(16):
                    block[i] ^= ivec[i]
                block = self.aes.encrypt(block, key_list, size)
                ivec = list(block) # CBC: next IV is current ciphertext block
            elif mode == self.ModeOfOperation["CFB"]:
                # CFB encrypt: Encrypt IV, XOR with plaintext to get ciphertext.
                # Next IV is current ciphertext.
                temp_ivec = self.aes.encrypt(ivec, key_list, size)
                for i in range(16):
                    block[i] ^= temp_ivec[i]
                ivec = list(block) # Update IV with ciphertext
            elif mode == self.ModeOfOperation["OFB"]:
                # OFB: Encrypt IV, XOR with plaintext.
                # Next IV is the *encrypted IV* (output of AES before XOR).
                ivec = self.aes.encrypt(ivec, key_list, size) # Encrypt IV
                for i in range(16):
                    block[i] ^= ivec[i] # XOR with plaintext
                # ivec for next round is already set (output of self.aes.encrypt)
            elif mode == self.ModeOfOperation["ECB"]:
                block = self.aes.encrypt(block, key_list, size)
            else:
                raise ValueError("Unsupported AES mode of operation: %d" % mode)

            for i in range(16):
                cipher[start_idx + i] = block[i]
                
        return bytes(cipher) # Convert list of ints back to bytes

    def decrypt(self, cipherIn, originalsize, mode, key, size, IV):
        """Decrypts an input string using AES with a specified mode of operation.

        Handles stripping of PKCS#7 padding for modes like CBC.

        Args:
            cipherIn (bytes or bytearray): The ciphertext data to decrypt.
            originalsize: This parameter seems unused in the current implementation logic,
                          padding removal relies on PKCS#7. Might be an artifact.
            mode (int): The AES mode of operation (from ModeOfOperation dict).
            key (bytes or bytearray): The AES key.
            size (int): The key size in bytes (16, 24, or 32).
            IV (bytes or bytearray): The Initialization Vector (16 bytes).
                                     Required for CBC, CFB, OFB. Ignored for ECB.

        Returns:
            bytes: The decrypted plaintext.

        Raises:
            ValueError: If an unsupported mode is specified, IV is missing/invalid,
                        or padding is invalid.
        """
        # Type checks
        if not isinstance(cipherIn, (bytes, bytearray)):
            raise TypeError("Input 'cipherIn' must be bytes or bytearray")
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Input 'key' must be bytes or bytearray")
        if IV is not None and not isinstance(IV, (bytes, bytearray)):
            raise TypeError("Input 'IV' must be bytes or bytearray, or None for ECB")

        if len(key) != size:
            raise ValueError("Key length %d does not match specified size %d" % (len(key), size))
        if IV is not None and len(IV) != 16 and mode != self.ModeOfOperation["ECB"]:
            raise ValueError("IV length must be 16 bytes for this mode.")
        if len(cipherIn) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of 16.")

        inputSize = len(cipherIn)
        clear = [0] * inputSize
        # ivec and temp_block are mutable lists of ints
        ivec = list(IV) if IV else [0] * 16
        key_list = list(key)

        for start_idx in range(0, inputSize, 16): # Renamed start to start_idx
            block = self.convertString(cipherIn, start_idx, start_idx + 16, mode)
            
            if mode == self.ModeOfOperation["CBC"]:
                temp_block = list(block) # Store current ciphertext block for next IV
                block = self.aes.decrypt(block, key_list, size)
                for i in range(16):
                    block[i] ^= ivec[i]
                ivec = temp_block # Next IV is previous ciphertext block
            elif mode == self.ModeOfOperation["CFB"]:
                # CFB decrypt: Encrypt IV, XOR with ciphertext to get plaintext.
                # Next IV is the *previous* ciphertext block.
                temp_ivec = self.aes.encrypt(ivec, key_list, size) # Encrypt current IV
                prev_cipher_block = list(block) # Store current ciphertext block
                for i in range(16):
                    block[i] ^= temp_ivec[i] # XOR with encrypted IV
                ivec = prev_cipher_block # Update IV with previous ciphertext
            elif mode == self.ModeOfOperation["OFB"]:
                # OFB: Encrypt IV, XOR with ciphertext.
                # Next IV is the *encrypted IV* (output of AES before XOR).
                ivec = self.aes.encrypt(ivec, key_list, size) # Encrypt IV
                for i in range(16):
                    block[i] ^= ivec[i] # XOR with ciphertext
            elif mode == self.ModeOfOperation["ECB"]:
                block = self.aes.decrypt(block, key_list, size)
            else:
                raise ValueError("Unsupported AES mode of operation: %d" % mode)

            for i in range(16):
                clear[start_idx + i] = block[i]
        
        clear_bytes = bytes(clear)
        
        # Strip padding
        # if mode == self.ModeOfOperation["CBC"]: # Padding stripping is usually done after all blocks
        try:
            return strip_PKCS7_padding(clear_bytes)
        except ValueError as e:
            # This can happen if the key is wrong or data is corrupted,
            # leading to incorrect decrypted padding bytes.
            # Propagate the error.
            raise ValueError("Failed to strip PKCS#7 padding. Possible incorrect key or corrupted data. Error: %s" % str(e))

    def kms_v6_rng(self, seed):
        """KMS v6 specific pseudo-random number generator (PRNG) logic.

        This PRNG is used to generate a salt for AES encryption in KMS v6 requests.
        It's a linear congruential generator (LCG) variant.

        Args:
            seed (int): The initial seed value for the PRNG.

        Returns:
            int: The next pseudo-random number in the sequence.
        """
        # kmsrng from kms-v6.c
        # unsigned int kmsrng (unsigned int *seed)
        # {
        #   *seed = (*seed * 0x343FD) + 0x269EC3;  // LCG
        #   return (*seed >> 0x10) & 0x7FFF;
        # }
        seed = (seed * 0x343FD) + 0x269EC3
        # Ensure seed stays within typical integer limits if it were C unsigned int,
        # though Python handles large integers automatically.
        # This helps mimic C behavior if overflow was a factor, but Python won't overflow.
        # seed &= 0xFFFFFFFF 
        return (seed >> 0x10) & 0x7FFF # Return the upper 15 bits of the middle 16 bits

    def generate_kms_v6_salt(self, size=16):
        """Generates a salt for KMS v6 using a specific PRNG.

        The salt is typically 16 bytes long. The PRNG is seeded with a value
        derived from the current system time and a random byte.

        Args:
            size (int): The desired length of the salt in bytes. Default is 16.

        Returns:
            bytes: The generated salt.
        """
        # generateSalt() from kms-v6.c
        # Uses time() and a random byte to seed the PRNG.
        # Python's time.time() returns float seconds since epoch.
        # os.urandom(1) gives a random byte.
        current_time_ms = int(time.time() * 1000) # Milliseconds
        random_byte = os.urandom(1)[0]
        
        # Initial seed incorporates time and a random byte.
        # The C code might be doing something like `(unsigned int)time(0) ^ rand_byte_or_similar_entropy`
        # Here we combine them simply.
        seed = current_time_ms ^ (random_byte << 24) # A way to mix them
        seed &= 0xFFFFFFFF # Keep it 32-bit like for consistency with C unsigned int
        
        salt = bytearray(size)
        for i in range(size):
            rand_val = self.kms_v6_rng(seed)
            seed = (rand_val << 0x10) | (seed & 0xFFFF) # Update seed based on C logic
            salt[i] = ord(self.KMS_RNG_CHOICES[rand_val % len(self.KMS_RNG_CHOICES)])
        
        return bytes(salt)

#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

def encryptData(key, data, mode=AESModeOfOperation.ModeOfOperation["CBC"], iv=None):
    """Encrypts data using AES with the specified key, mode, and IV.

    This is a convenience wrapper around AESModeOfOperation.
    The key size is assumed to be 128 bits (16 bytes) if not implicitly defined
    by the length of the `key` argument itself.
    If an IV is not provided for CBC, CFB, or OFB mode, a random 16-byte IV is generated.

    Args:
        key (bytes or bytearray): The AES key (typically 16 bytes for AES-128).
        data (bytes or bytearray): The plaintext data to encrypt.
        mode (int, optional): The AES mode of operation.
                              Defaults to CBC (Cipher-Block Chaining).
        iv (bytes or bytearray, optional): The Initialization Vector. If None and
                                           mode requires an IV, one will be generated.

    Returns:
        bytes: The encrypted ciphertext. If an IV was generated (for CBC, CFB, OFB),
               the IV is prepended to the ciphertext (IV + ciphertext).
               For ECB, only ciphertext is returned.

    Raises:
        ValueError: If the key length is not a supported AES key size.
    """
    # Assume key size from the key length itself.
    # AES class's encrypt method will validate if len(key) is 16, 24, or 32.
    keysize = len(key)
    if keysize not in [AES.KeySize["SIZE_128"], AES.KeySize["SIZE_192"], AES.KeySize["SIZE_256"]]:
        raise ValueError("Invalid key size: %d bytes. Must be 16, 24, or 32." % keysize)

    # Generate IV if not provided and mode requires it
    generated_iv = False
    if iv is None and mode in [AESModeOfOperation.ModeOfOperation["CBC"],
                               AESModeOfOperation.ModeOfOperation["CFB"],
                               AESModeOfOperation.ModeOfOperation["OFB"]]:
        iv = os.urandom(16)
        generated_iv = True
    
    moo = AESModeOfOperation()
    cipher = moo.encrypt(data, mode, key, keysize, iv)
    
    if generated_iv and mode != AESModeOfOperation.ModeOfOperation["ECB"]:
        # Prepend IV to ciphertext if it was generated by this function
        return iv + cipher
    else:
        return cipher

def decryptData(key, data, mode=AESModeOfOperation.ModeOfOperation["CBC"], iv=None):
    """Decrypts data using AES with the specified key, mode, and IV.

    This is a convenience wrapper around AESModeOfOperation.
    The key size is assumed from the length of the `key` argument.
    If an IV is not provided for CBC, CFB, or OFB mode, it's assumed that the
    IV is prepended to the `data` (ciphertext).

    Args:
        key (bytes or bytearray): The AES key.
        data (bytes or bytearray): The ciphertext. If `iv` is None and mode requires an IV,
                                  this should be IV + actual_ciphertext.
        mode (int, optional): The AES mode of operation.
                              Defaults to CBC.
        iv (bytes or bytearray, optional): The Initialization Vector. If None for
                                           modes requiring an IV, it's extracted
                                           from the beginning of `data`.

    Returns:
        bytes: The decrypted plaintext.

    Raises:
        ValueError: If key length is invalid, or if data is too short to contain
                    IV when IV is expected to be prepended.
    """
    keysize = len(key)
    if keysize not in [AES.KeySize["SIZE_128"], AES.KeySize["SIZE_192"], AES.KeySize["SIZE_256"]]:
        raise ValueError("Invalid key size: %d bytes. Must be 16, 24, or 32." % keysize)

    actual_cipher = data
    if iv is None and mode in [AESModeOfOperation.ModeOfOperation["CBC"],
                               AESModeOfOperation.ModeOfOperation["CFB"],
                               AESModeOfOperation.ModeOfOperation["OFB"]]:
        if len(data) < 16:
            raise ValueError("Data is too short to contain a prepended IV.")
        iv = data[:16]
        actual_cipher = data[16:]
        
    moo = AESModeOfOperation()
    # The 'originalsize' parameter for moo.decrypt seems unused/artifact.
    # PKCS#7 padding handles determining original size.
    return moo.decrypt(actual_cipher, 0, mode, key, keysize, iv)

#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Test class, not typically used by py-kms server/client logic directly.
class Test(object):
    """A simple class for testing the AES implementation. (Not used by py-kms runtime)"""
    def generateRandomKey(self, keysize):
        """Generates a random key of the specified size.
        
        Args:
            keysize (int): Desired key size in bytes (16, 24, or 32).
        
        Returns:
            bytes: A random key.
        """
        return os.urandom(keysize)

    def testString(self, cleartext, keysize = 16, modeName = "CBC"):
        """Tests encryption and decryption of a string.
        
        Args:
            cleartext (str): The string to test.
            keysize (int, optional): Key size in bytes. Defaults to 16 (AES-128).
            modeName (str, optional): AES mode of operation string ("CBC", "ECB", etc.).
                                      Defaults to "CBC".
                                      
        Returns:
            bool: True if test passes (decrypted text matches original), False otherwise.
        """
        # Convert cleartext string to bytes
        cleartext_bytes = cleartext.encode('utf-8')

        key = self.generateRandomKey(keysize)
        mode = AESModeOfOperation.ModeOfOperation[modeName]

        # For CBC, CFB, OFB, IV is needed. encryptData will generate if None.
        # For ECB, IV is ignored.
        iv = None
        if modeName != "ECB":
            iv = os.urandom(16) 
            
        print("Plaintext: '%s'" % cleartext)
        print("Key: %s" % repr(key))
        if iv:
            print("IV: %s" % repr(iv))
            
        cipher = encryptData(key, cleartext_bytes, mode, iv=iv)
        print("Cipher: %s" % repr(cipher))
        
        # If IV was generated by encryptData and prepended, decryptData will handle it.
        # If we passed an IV to encryptData, we should pass the same to decryptData.
        # If IV was prepended by encryptData, decryptData will extract it if iv=None is passed.
        # To be explicit for testing:
        retrieved_iv_for_decrypt = None
        actual_ciphertext_for_decrypt = cipher
        if modeName != "ECB":
            if iv: # We provided an IV
                retrieved_iv_for_decrypt = iv
            else: # encryptData prepended its generated IV
                retrieved_iv_for_decrypt = cipher[:16]
                actual_ciphertext_for_decrypt = cipher[16:]

        print("Cipher for decrypt: %s" % repr(actual_ciphertext_for_decrypt))
        if retrieved_iv_for_decrypt:
            print("IV for decrypt: %s" % repr(retrieved_iv_for_decrypt))

        decrypted_bytes = decryptData(key, cipher, mode, iv=retrieved_iv_for_decrypt if modeName !="ECB" else None)
        decrypted = decrypted_bytes.decode('utf-8')
        print("Decrypted: '%s'" % decrypted)
        
        return cleartext == decrypted

#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    # Some internal self-tests, not for library use.
    print("pykms_Aes.py self-test:")
    
    # Test padding functions
    test_data_pad = b"This is a test"
    padded = append_PKCS7_padding(test_data_pad)
    print("Original: %s, Padded: %s" % (repr(test_data_pad), repr(padded)))
    stripped = strip_PKCS7_padding(padded)
    print("Stripped: %s" % repr(stripped))
    assert stripped == test_data_pad, "PKCS7 Padding/Stripping failed"
    print("PKCS7 Padding OK")

    # Test AES core encryption/decryption (ECB-like, single block)
    aes_core = AES()
    test_key_core = os.urandom(16)
    test_plain_core = list(b"Sixteen byte blk") # Must be 16 bytes
    
    cipher_block = aes_core.encrypt(test_plain_core, test_key_core, 16)
    print("Core Encrypt: %s -> %s" % (repr(bytes(test_plain_core)), repr(bytes(cipher_block))))
    
    decrypted_block = aes_core.decrypt(cipher_block, test_key_core, 16)
    print("Core Decrypt: %s -> %s" % (repr(bytes(cipher_block)), repr(bytes(decrypted_block))))
    assert decrypted_block == test_plain_core, "AES Core encrypt/decrypt failed"
    print("AES Core OK")

    # Test modes of operation with helper functions
    t = Test()
    print("\nTesting AES-128 CBC...")
    assert t.testString("This is a test message for AES-128 CBC.", 16, "CBC")
    print("\nTesting AES-128 ECB...")
    assert t.testString("This is for ECB.", 16, "ECB") # ECB encrypts repeating blocks identically.
    
    # Test specific KMS v6 salt generation (just to see it run)
    moo = AESModeOfOperation()
    salt = moo.generate_kms_v6_salt()
    print("\nKMS v6 salt example: %s (len %d)" % (repr(salt), len(salt)))
    assert len(salt) == 16

    print("\nSelf-tests completed.")

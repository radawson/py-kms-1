#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pykms_Aes2.py: implements AES using the 'cryptography' library
# Based on the interface of pykms_Aes.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
import time # For KMS v6 salt generation

def append_PKCS7_padding(data_bytes):
    """Applies PKCS#7 padding to the input byte string.

    Args:
        data_bytes (bytes): The input data to be padded.

    Returns:
        bytes: The padded data.
    """
    if not isinstance(data_bytes, bytes):
        raise TypeError("Input must be bytes.")
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data_bytes) + padder.finalize()

def strip_PKCS7_padding(data_bytes):
    """Removes PKCS#7 padding from a decrypted byte string.

    Args:
        data_bytes (bytes): The input data from which padding is to be stripped.

    Returns:
        bytes: The unpadded data.

    Raises:
        ValueError: If padding is invalid.
    """
    if not isinstance(data_bytes, bytes):
        raise TypeError("Input must be bytes.")
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return unpadder.update(data_bytes) + unpadder.finalize()
    except ValueError as e:
        # Propagate ValueErrors from padding, often indicating bad decrypt/key
        raise ValueError("Invalid PKCS#7 padding: %s" % str(e))


class AES(object):
    """
    Implements AES block encryption/decryption using the 'cryptography' library.
    This class provides a raw AES block operation (ECB-like without explicit mode).
    """
    KeySize = {
        "SIZE_128": 16,
        "SIZE_192": 24,
        "SIZE_256": 32
    }
    # No v6 flag, Sbox, Rcon, or manual round implementations. Standard AES is used.

    def encrypt(self, iput, key, size):
        """Encrypts a single 16-byte block of data using AES (ECB mode).

        Args:
            iput (list of int or bytes): The 16-byte plaintext block.
            key (list of int or bytes): The AES key.
            size (int): The key size in bytes (16, 24, or 32). For compatibility,
                        but actual key length of 'key' is used.

        Returns:
            list of int: The 16-byte ciphertext block as a list of integers.
        """
        plain_bytes = bytes(iput) if isinstance(iput, list) else iput
        key_bytes = bytes(key) if isinstance(key, list) else key

        if not isinstance(plain_bytes, bytes) or len(plain_bytes) != 16:
            raise ValueError("Input 'iput' must be 16 bytes.")
        if not isinstance(key_bytes, bytes) or len(key_bytes) not in self.KeySize.values():
            raise ValueError("Invalid key or key size.")
        if len(key_bytes) != size:
            # This check maintains compatibility if the caller relies on 'size'
            # but cryptography.algorithms.AES uses the actual len(key_bytes).
            pass # Or raise ValueError if strict adherence to 'size' is desired

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(plain_bytes) + encryptor.finalize()
        return list(ct)

    def decrypt(self, iput, key, size):
        """Decrypts a single 16-byte block of data using AES (ECB mode).

        Args:
            iput (list of int or bytes): The 16-byte ciphertext block.
            key (list of int or bytes): The AES key.
            size (int): The key size in bytes (16, 24, or 32). For compatibility.

        Returns:
            list of int: The 16-byte plaintext block as a list of integers.
        """
        cipher_bytes = bytes(iput) if isinstance(iput, list) else iput
        key_bytes = bytes(key) if isinstance(key, list) else key

        if not isinstance(cipher_bytes, bytes) or len(cipher_bytes) != 16:
            raise ValueError("Input 'iput' must be 16 bytes.")
        if not isinstance(key_bytes, bytes) or len(key_bytes) not in self.KeySize.values():
            raise ValueError("Invalid key or key size.")
        if len(key_bytes) != size:
            pass

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        pt = decryptor.update(cipher_bytes) + decryptor.finalize()
        return list(pt)


class AESModeOfOperation(object):
    """
    Implements AES modes of operation using the 'cryptography' library.
    """
    aes = AES() # Instantiates the new AES class

    ModeOfOperation = {
        "OFB": 1,
        "CFB": 2,
        "CBC": 3,
        "ECB": 4
    }
    
    KMS_RNG_CHOICES = tuple("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

    def convertString(self, string, start, end, mode):
        """Converts a part of a string/bytes to a list of integers (byte values).
           Maintained for compatibility if used by other parts of py-kms.
        """
        if end - start > 16:
            end = start + 16
        if not isinstance(string, (bytes, bytearray)):
            raise TypeError("Input 'string' must be bytes or bytearray.")
        return list(string[start:end])

    def encrypt(self, stringIn_bytes, mode_int, key_bytes, size, iv_bytes):
        """Encrypts data using AES with a specified mode.

        Args:
            stringIn_bytes (bytes): Plaintext data.
            mode_int (int): Mode of operation (from ModeOfOperation dict).
            key_bytes (bytes): AES key.
            size (int): Key size (for compatibility, len(key_bytes) is used).
            iv_bytes (bytes or None): Initialization Vector (16 bytes).

        Returns:
            bytes: Encrypted ciphertext.
        """
        if not isinstance(stringIn_bytes, bytes): raise TypeError("'stringIn_bytes' must be bytes")
        if not isinstance(key_bytes, bytes): raise TypeError("'key_bytes' must be bytes")
        if iv_bytes is not None and not isinstance(iv_bytes, bytes):
            raise TypeError("'iv_bytes' must be bytes or None")
        if len(key_bytes) not in AES.KeySize.values(): raise ValueError("Invalid key length")


        actual_mode = None
        if mode_int == self.ModeOfOperation["ECB"]:
            actual_mode = modes.ECB()
        elif mode_int == self.ModeOfOperation["CBC"]:
            if iv_bytes is None or len(iv_bytes) != 16: raise ValueError("CBC mode requires a 16-byte IV.")
            actual_mode = modes.CBC(iv_bytes)
        elif mode_int == self.ModeOfOperation["CFB"]:
            if iv_bytes is None or len(iv_bytes) != 16: raise ValueError("CFB mode requires a 16-byte IV.")
            actual_mode = modes.CFB(iv_bytes)
        elif mode_int == self.ModeOfOperation["OFB"]:
            if iv_bytes is None or len(iv_bytes) != 16: raise ValueError("OFB mode requires a 16-byte IV.")
            actual_mode = modes.OFB(iv_bytes)
        else:
            raise ValueError("Unsupported AES mode of operation: %d" % mode_int)

        # Original implementation always padded. We replicate this.
        padded_data = append_PKCS7_padding(stringIn_bytes)
            
        cipher = Cipher(algorithms.AES(key_bytes), actual_mode, backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct

    def decrypt(self, cipherIn_bytes, originalsize, mode_int, key_bytes, size, iv_bytes):
        """Decrypts data using AES with a specified mode.

        Args:
            cipherIn_bytes (bytes): Ciphertext data.
            originalsize (int): Unused (padding handles original size).
            mode_int (int): Mode of operation.
            key_bytes (bytes): AES key.
            size (int): Key size (for compatibility).
            iv_bytes (bytes or None): Initialization Vector.

        Returns:
            bytes: Decrypted plaintext.
        """
        if not isinstance(cipherIn_bytes, bytes): raise TypeError("'cipherIn_bytes' must be bytes")
        if not isinstance(key_bytes, bytes): raise TypeError("'key_bytes' must be bytes")
        if iv_bytes is not None and not isinstance(iv_bytes, bytes):
            raise TypeError("'iv_bytes' must be bytes or None")
        if len(key_bytes) not in AES.KeySize.values(): raise ValueError("Invalid key length")


        actual_mode = None
        if mode_int == self.ModeOfOperation["ECB"]:
            actual_mode = modes.ECB()
        elif mode_int == self.ModeOfOperation["CBC"]:
            if iv_bytes is None or len(iv_bytes) != 16: raise ValueError("CBC mode requires a 16-byte IV.")
            actual_mode = modes.CBC(iv_bytes)
        elif mode_int == self.ModeOfOperation["CFB"]:
            if iv_bytes is None or len(iv_bytes) != 16: raise ValueError("CFB mode requires a 16-byte IV.")
            actual_mode = modes.CFB(iv_bytes)
        elif mode_int == self.ModeOfOperation["OFB"]:
            if iv_bytes is None or len(iv_bytes) != 16: raise ValueError("OFB mode requires a 16-byte IV.")
            actual_mode = modes.OFB(iv_bytes)
        else:
            raise ValueError("Unsupported AES mode of operation: %d" % mode_int)

        cipher = Cipher(algorithms.AES(key_bytes), actual_mode, backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Data must be multiple of block size for modes other than CFB/OFB for raw decrypt
        # However, since original always padded, we expect padded data here.
        # Decrypt first, then unpad.
        pt_padded = decryptor.update(cipherIn_bytes) + decryptor.finalize()
        
        # Original implementation always stripped padding after decrypt.
        return strip_PKCS7_padding(pt_padded)

    def kms_v6_rng(self, seed):
        """KMS v6 specific pseudo-random number generator (PRNG) logic.
           Copied from original pykms_Aes.py.
        """
        seed = (seed * 0x343FD) + 0x269EC3
        seed &= 0xFFFFFFFF # Mimic C unsigned int behavior
        return (seed >> 0x10) & 0x7FFF

    def generate_kms_v6_salt(self, size=16):
        """Generates a salt for KMS v6 using a specific PRNG.
           Copied from original pykms_Aes.py.
        """
        current_time_ms = int(time.time() * 1000)
        random_byte = os.urandom(1)[0]
        
        seed = current_time_ms ^ (random_byte << 24) 
        seed &= 0xFFFFFFFF
        
        salt = bytearray(size)
        for i in range(size):
            # In C, the seed for next round is updated by the kmsrng call.
            # The original python version's seed update was slightly different.
            # Replicating the structure from kms-v6.c more closely:
            # rand_val = self.kms_v6_rng(&seed_ptr); where seed_ptr is updated.
            # Python equivalent:
            # temp_seed = seed
            # rand_val = self.kms_v6_rng(temp_seed) # kms_v6_rng uses the value
            # seed = temp_seed # if kms_v6_rng modified its arg by pointer
            # The original python code:
            # rand_val = self.kms_v6_rng(seed)
            # seed = (rand_val << 0x10) | (seed & 0xFFFF) # This was the update rule

            # Let's analyze the original Python implementation's kms_v6_rng and generate_kms_v6_salt interaction carefully.
            # Original `generate_kms_v6_salt`:
            #   for i in range(size):
            #       rand_val = self.kms_v6_rng(seed)
            #       seed = (rand_val << 0x10) | (seed & 0xFFFF) # <--- This IS the seed update for the NEXT iteration
            #       salt[i] = ord(self.KMS_RNG_CHOICES[rand_val % len(self.KMS_RNG_CHOICES)])
            # The `kms_v6_rng` function ITSELF updates the seed and returns a part of it.
            # So the call to `self.kms_v6_rng(seed)` should be passing `seed` and expect `kms_v6_rng` to return
            # the new seed for the next round, or for `kms_v6_rng` to use the result of its own calculation
            # to update an internal state if it were a class designed that way.
            # The C code `*seed = (*seed * 0x343FD) + 0x269EC3; return (*seed >> 0x10) & 0x7FFF;`
            # implies that `kms_v6_rng` modifies the seed passed by reference and returns the value.
            # The Python `kms_v6_rng` takes seed by value, modifies its local copy, and returns the derived value.
            # The `generate_kms_v6_salt` in the original `pykms_Aes.py` then had its own separate seed update logic:
            #   `seed = (rand_val << 0x10) | (seed & 0xFFFF)`
            # This is different from the LCG update `seed = (seed * 0x343FD) + 0x269EC3`.
            # For a faithful copy of the *original Python behavior* for salt generation,
            # we must keep this two-stage seed update.

            rand_val_from_lcg_step = (seed * 0x343FD) + 0x269EC3
            rand_val_from_lcg_step &= 0xFFFFFFFF
            
            # This is the value used for choosing the char
            returned_rng_val = (rand_val_from_lcg_step >> 0x10) & 0x7FFF
            
            salt[i] = ord(self.KMS_RNG_CHOICES[returned_rng_val % len(self.KMS_RNG_CHOICES)])
            
            # This is the seed for the next iteration, as per original pykms_Aes.py generate_kms_v6_salt
            seed = (returned_rng_val << 0x10) | (rand_val_from_lcg_step & 0xFFFF)
            seed &= 0xFFFFFFFF

        return bytes(salt)

# Convenience functions (adapted to use new AESModeOfOperation and bytes i/o)
def encryptData(key, data, mode=AESModeOfOperation.ModeOfOperation["CBC"], iv=None):
    """Encrypts data using AES. IV is prepended if generated.
    Args:
        key (bytes): AES key.
        data (bytes): Plaintext data.
        mode (int, optional): AES mode. Defaults to CBC.
        iv (bytes, optional): IV. If None and mode requires it, one is generated.
    Returns:
        bytes: Ciphertext (IV prepended if generated by this function for relevant modes).
    """
    if not isinstance(key, bytes): raise TypeError("Key must be bytes.")
    if not isinstance(data, bytes): raise TypeError("Data must be bytes.")

    keysize = len(key)
    if keysize not in AES.KeySize.values():
        raise ValueError("Invalid key size: %d bytes. Must be 16, 24, or 32." % keysize)

    generated_iv = False
    current_iv = iv
    if current_iv is None and mode in [AESModeOfOperation.ModeOfOperation["CBC"],
                                     AESModeOfOperation.ModeOfOperation["CFB"],
                                     AESModeOfOperation.ModeOfOperation["OFB"]]:
        current_iv = os.urandom(16)
        generated_iv = True
    
    moo = AESModeOfOperation()
    cipher_payload = moo.encrypt(data, mode, key, keysize, current_iv)
    
    if generated_iv and mode != AESModeOfOperation.ModeOfOperation["ECB"]:
        return current_iv + cipher_payload
    else:
        return cipher_payload

def decryptData(key, data, mode=AESModeOfOperation.ModeOfOperation["CBC"], iv=None):
    """Decrypts data using AES. Assumes IV is prepended if not provided.
    Args:
        key (bytes): AES key.
        data (bytes): Ciphertext. If iv is None and mode requires it,
                      this should be IV + actual_ciphertext.
        mode (int, optional): AES mode. Defaults to CBC.
        iv (bytes, optional): IV. If None and mode needs it, extracted from data.
    Returns:
        bytes: Decrypted plaintext.
    """
    if not isinstance(key, bytes): raise TypeError("Key must be bytes.")
    if not isinstance(data, bytes): raise TypeError("Data must be bytes.")

    keysize = len(key)
    if keysize not in AES.KeySize.values():
        raise ValueError("Invalid key size: %d bytes. Must be 16, 24, or 32." % keysize)

    actual_cipher = data
    current_iv = iv

    if current_iv is None and mode in [AESModeOfOperation.ModeOfOperation["CBC"],
                                     AESModeOfOperation.ModeOfOperation["CFB"],
                                     AESModeOfOperation.ModeOfOperation["OFB"]]:
        if len(data) < 16:
            raise ValueError("Data is too short to contain a prepended IV.")
        current_iv = data[:16]
        actual_cipher = data[16:]
        
    moo = AESModeOfOperation()
    # originalsize (0) is unused by the new moo.decrypt
    return moo.decrypt(actual_cipher, 0, mode, key, keysize, current_iv) 
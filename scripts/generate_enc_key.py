#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

"""
Generate the device encryption key record for the firmware loader.

The record is placed in the last ENC_KEY_AREA_SIZE bytes of the boot partition, where the firmware
loader reads it (see enc_image_key.h in the firmware loader). The build fails if MCUboot has grown
into that area.
"""

import argparse
import os
import pathlib
import pickle
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from intelhex import IntelHex

# Keep in sync with enc_image_key.h of the firmware loader.
# 48 byte key, 8 byte header, consisting of 4 byte magic and 4 byte DER length
ENC_KEY_AREA_SIZE = 0x100
ENC_KEY_RECORD_MAGIC = 0x4B434E45
ENC_KEY_RECORD_HEADER = struct.Struct('<II')  # magic, DER length
X25519_PKCS8_DER_LEN = 48
RRAM_WORD_SIZE = 16


def parse_args():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--build-dir', required=True, type=pathlib.Path,
                        help='Sysbuild build directory.')
    parser.add_argument('--loader-dir', required=True, type=pathlib.Path,
                        help='Build directory of the firmware loader image.')
    parser.add_argument('--mcuboot-hex', required=True, type=pathlib.Path,
                        help='MCUboot hex file, used to check that it does not reach the key area.')
    parser.add_argument('--key-file', required=True, type=pathlib.Path,
                        help='Device private key, PEM, X25519.')
    parser.add_argument('--output', type=pathlib.Path,
                        help='Output hex file, default <build-dir>/enc_key.hex.')

    return parser.parse_args()


def read_cmake_cache(path):
    configs = {}

    with open(path) as cache:
        for line in cache:
            if line.startswith(('#', '//')) or ':' not in line or '=' not in line:
                continue

            name_type, value = line.split('=', 1)
            configs[name_type.split(':', 1)[0]] = value.strip()

    return configs


def boot_partition(loader_dir, zephyr_base):
    sys.path.insert(0, os.path.join(zephyr_base, 'scripts', 'dts', 'python-devicetree', 'src'))

    with open(loader_dir / 'zephyr' / 'edt.pickle', 'rb') as f:
        edt = pickle.load(f)

    for node in edt.nodes:
        if 'boot_partition' in node.labels:
            start, size = node.props['reg'].val[:2]
            return start, size

    sys.exit('error: boot_partition not found in the firmware loader devicetree')


def key_der(key_file):
    try:
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as err:
        sys.exit(f'error: cannot read encryption key {key_file}: {err}')

    if not isinstance(key, x25519.X25519PrivateKey):
        sys.exit(f'error: {key_file} is not an X25519 private key')

    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())

    # MCUboot's parse_priv_enckey() accepts exactly this layout.
    if len(der) != X25519_PKCS8_DER_LEN:
        sys.exit(f'error: unexpected key encoding length {len(der)}')

    return der


def main():
    args = parse_args()

    cache_file = args.build_dir / 'CMakeCache.txt'

    for path in (cache_file, args.mcuboot_hex, args.key_file):
        if not path.exists():
            sys.exit(f'error: {path} does not exist')

    area_size = ENC_KEY_AREA_SIZE
    zephyr_base = read_cmake_cache(cache_file)['ZEPHYR_BASE']
    boot_start, boot_size = boot_partition(args.loader_dir, zephyr_base)
    boot_end = boot_start + boot_size
    area_start = boot_end - area_size

    der = key_der(args.key_file)
    record = ENC_KEY_RECORD_HEADER.pack(ENC_KEY_RECORD_MAGIC, len(der)) + der
    used = len(record)

    if used > area_size:
        sys.exit(f'error: key record of {used} bytes does not fit the {area_size} byte key area')

    # RRAM is programmed in whole words.
    record += bytes(-len(record) % RRAM_WORD_SIZE)

    mcuboot = IntelHex(str(args.mcuboot_hex))
    mcuboot_end = boot_start

    for start, end in mcuboot.segments():
        if start >= boot_end:
            continue

        if end > area_start:
            sys.exit(f'error: MCUboot reaches {end:#x}, into the encryption key area '
                     f'{area_start:#x}-{boot_end:#x}. Reduce the MCUboot size.')

        mcuboot_end = max(mcuboot_end, end)

    output = args.output or args.build_dir / 'enc_key.hex'
    key_hex = IntelHex()
    key_hex.frombytes(record, offset=area_start)
    key_hex.write_hex_file(str(output))

    print(f'Encryption key record: {used} of {area_size} bytes used at {area_start:#x} '
          f'(boot partition {boot_start:#x}-{boot_end:#x})')
    print(f'MCUboot ends at {mcuboot_end:#x}, {area_start - mcuboot_end} bytes free before the '
          f'key area')


if __name__ == '__main__':
    main()

#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ble_mcumgr)

target_sources(app PRIVATE
  src/main.c
)

if(CONFIG_APP_FIRMWARE_LOADER_IMAGE_DECRYPTION)
  set(mcuboot_bootutil_src ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/bootutil/src)

  # MCUboot sources used as is for the encrypted image handling.
  set(mcuboot_enc_sources
    ${mcuboot_bootutil_src}/encrypted.c      # boot_enc_load(), boot_enc_set_key(), boot_enc_decrypt()
    ${mcuboot_bootutil_src}/encrypted_psa.c  # boot_decrypt_key(), AES-CTR over PSA
    ${mcuboot_bootutil_src}/tlv.c            # bootutil_tlv_iter_begin(), bootutil_tlv_iter_next()
  )

  # MCUboot is configured with these preprocessor symbols; in MCUboot itself they are derived from
  # its own Kconfig options, which do not exist in this application.
  # KK To use HMAC_SHA256, TLV 0x33 we can exclude the MCUBOOT_HMAC_SHA512 define.
  # KK To use HMAC_SHA512, add define: MCUBOOT_HMAC_SHA512         # key exchange uses SHA512, TLV ENCX25519_SHA512
  set(mcuboot_enc_defines
    MCUBOOT_ENC_IMAGES
    MCUBOOT_ENCRYPT_X25519
    MCUBOOT_AES_128
    MCUBOOT_USE_PSA_CRYPTO
    MCUBOOT_FIRMWARE_LOADER
    CONFIG_BOOT_ED25519_PSA=1   # selects the PSA implementation in encrypted.c
  )

  target_sources(app PRIVATE
    src/enc_image.c
    ${mcuboot_enc_sources}
  )

  set_source_files_properties(src/enc_image.c ${mcuboot_enc_sources}
    PROPERTIES COMPILE_DEFINITIONS "${mcuboot_enc_defines}"
  )

  target_include_directories(app PRIVATE ${mcuboot_bootutil_src})
  target_link_libraries(app PRIVATE MCUBOOT_BOOTUTIL)
endif()

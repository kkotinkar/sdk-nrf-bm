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
    ${ZEPHYR_MCUBOOT_MODULE_DIR}/boot/zephyr/keys.c # bootutil_enc_key
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

  # The device private key is compiled in as enc_priv_key[] like it is in MCUboot.
  set(enc_key_file ${CONFIG_APP_FIRMWARE_LOADER_ENC_KEY_FILE})
  if(NOT IS_ABSOLUTE ${enc_key_file})
    set(enc_key_file ${CMAKE_CURRENT_SOURCE_DIR}/${enc_key_file})
  endif()

  if(enc_key_file STREQUAL "${ZEPHYR_MCUBOOT_MODULE_DIR}/enc-x25519-priv.pem")
    message(WARNING "Using the default MCUboot encryption key, it is for debug use only and is not secure!")
  endif()

  set(enc_key_c ${ZEPHYR_BINARY_DIR}/autogen-enckey.c)
  add_custom_command(
    OUTPUT ${enc_key_c}
    COMMAND ${PYTHON_EXECUTABLE} ${ZEPHYR_MCUBOOT_MODULE_DIR}/scripts/imgtool.py
            getpriv -k ${enc_key_file} > ${enc_key_c}
    DEPENDS ${enc_key_file}
  )

  target_sources(app PRIVATE
    src/enc_image.c
    ${mcuboot_enc_sources}
    ${enc_key_c}
  )

  set_source_files_properties(src/enc_image.c ${mcuboot_enc_sources}
    PROPERTIES COMPILE_DEFINITIONS "${mcuboot_enc_defines}"
  )

  target_include_directories(app PRIVATE ${mcuboot_bootutil_src})
  target_link_libraries(app PRIVATE MCUBOOT_BOOTUTIL)
endif()

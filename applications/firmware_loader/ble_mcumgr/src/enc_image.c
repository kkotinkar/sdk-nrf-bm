/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/devicetree.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <bm/storage/bm_storage.h>
#include <bm/storage/bm_storage_backends.h>

#include <bootutil/image.h>
#include <bootutil/bootutil_public.h>
#include <bootutil/enc_key.h>
#include <bootutil_priv.h>

#include "enc_image.h"

LOG_MODULE_REGISTER(enc_image, CONFIG_APP_LOG_LEVEL);

/*
 * Glue between the firmware loader and the MCUboot encrypted image code.
 *
 * All image parsing and cryptography is done by MCUboot's bootutil:
 *  - boot_image_load_header()  bootutil_public.c
 *  - boot_enc_load()           encrypted.c, which uses
 *      bootutil_tlv_iter_begin() and bootutil_tlv_iter_next()   tlv.c  to find the ENC TLV and
 *      boot_decrypt_key()                                       encrypted_psa.c  to unwrap the key
 *  - boot_enc_set_key(), boot_enc_decrypt(), boot_enc_zeroize()  encrypted.c
 *
 * This file adds what MCUboot does not provide here: the decision whether the payload really needs
 * decrypting, and the write loop through bm_storage, which is the SoftDevice aware flash path.
 */

#define SLOT0_START FIXED_PARTITION_ADDRESS(slot0_partition)
#define SLOT0_SIZE FIXED_PARTITION_SIZE(slot0_partition)

#define SRAM_NODE DT_NODELABEL(cpuapp_sram)

#define WRITE_TIMEOUT_MS 2000

BUILD_ASSERT(CONFIG_APP_FIRMWARE_LOADER_ENC_CHUNK_SIZE % BOOT_ENC_BLOCK_SIZE == 0,
	     "Chunk size must be a multiple of the AES block size");

/* Flash area of slot0 for the bootutil functions, as in MCUboot's firmware_loader_bm.c. */
static const struct flash_area slot0_area = {
	.fa_id = 1,
	.fa_off = FIXED_PARTITION_OFFSET(slot0_partition),
	.fa_size = FIXED_PARTITION_SIZE(slot0_partition),
	.fa_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller)),
};

static struct image_header hdr;
static struct boot_loader_state state;
static struct boot_status bs;

static struct bm_storage slot0_storage;
static volatile bool write_done;
static volatile int write_result;

/* Source of the SoftDevice write requests, which must stay valid until the write event. */
static uint8_t work_buf[CONFIG_APP_FIRMWARE_LOADER_ENC_CHUNK_SIZE] __aligned(4);

static void storage_evt_handler(struct bm_storage_evt *evt)
{
	if (evt->id == BM_STORAGE_EVT_WRITE_RESULT) {
		write_result = evt->result;
		write_done = true;
	}
}

static const struct bm_storage_config slot0_storage_config = {
#if defined(CONFIG_BM_STORAGE_BACKEND_SD)
	.api = &bm_storage_sd_api,
#else
	.api = &bm_storage_rram_api,
#endif
	.evt_handler = storage_evt_handler,
	.addr = SLOT0_START,
	.size = SLOT0_SIZE,
};

static int slot0_write(uint32_t off, const void *src, uint32_t len)
{
	int64_t deadline = k_uptime_get() + WRITE_TIMEOUT_MS;
	int err;

	write_done = false;

    /* write request handed over to SoftDevice backend, which cuts down chunks into 32 bytes  - this is due to BLE/SD scheduling behavior */
	err = bm_storage_write(&slot0_storage, off, src, len, NULL);
	if (err) {
		LOG_ERR("Write at %#x failed, err %d", off, err);
		return err;
	}

	while (!write_done) {
		if (k_uptime_get() > deadline) {
			LOG_ERR("Write at %#x timed out", off);
			return -ETIMEDOUT;
		}

		log_flush();
		k_cpu_idle();
	}

	return write_result;
}

/* The first words of an application image are its Cortex-M vector table: the initial stack pointer
 * in RAM and the reset vector, with the Thumb bit set, in the slot.
 */
static bool vector_table_plausible(const uint8_t *block)
{
	uint32_t sp = sys_get_le32(&block[0]);
	uint32_t reset = sys_get_le32(&block[4]);
	uint32_t ram_start = DT_REG_ADDR(SRAM_NODE);
	uint32_t ram_end = ram_start + DT_REG_SIZE(SRAM_NODE);

	if (sp <= ram_start || sp > ram_end || (sp & 0x3) != 0) {
		return false;
	}

	if ((reset & 1) == 0) {
		return false;
	}

	reset &= ~1U;

	return reset >= SLOT0_START && reset < SLOT0_START + SLOT0_SIZE;
}

int enc_image_decrypt_slot0(void)
{
	struct enc_key_data *enc = BOOT_CURR_ENC_SLOT(&state, BOOT_SLOT_PRIMARY);
	uint32_t payload_off;
	uint32_t payload_size;
	uint32_t done;
	uint8_t first_block[BOOT_ENC_BLOCK_SIZE];
	int rc;

	rc = bm_storage_init(&slot0_storage, &slot0_storage_config);
	if (rc && rc != -EPERM) {
		LOG_ERR("Storage init failed, err %d", rc);
		return rc;
	}

	/* Check the image header: magic, bootable, size within the slot. */
	rc = boot_image_load_header(&slot0_area, &hdr);
	if (rc) {
		LOG_ERR("No valid image header in slot0, err %d", rc);
		return -EBADMSG;
	}

	if (!IS_ENCRYPTED(&hdr)) {
        LOG_INF("Image is not encrypted");
		return ENC_IMAGE_NOT_ENCRYPTED;
	}

	/* The key size is fixed at build time, as in MCUboot. */
	if ((hdr.ih_flags & IMAGE_F_ENCRYPTED_AES256) != 0 ||
	    (hdr.ih_flags & IMAGE_F_ENCRYPTED_AES128) == 0) {
		LOG_ERR("Unsupported encryption, flags %#x", hdr.ih_flags);
		return -ENOTSUP;
	}

	/* Writes are done in whole blocks, and the nonce is derived from the block index. */
	payload_off = hdr.ih_hdr_size;
	payload_size = hdr.ih_img_size;

	if ((payload_off % BOOT_ENC_BLOCK_SIZE) != 0 || (payload_size % BOOT_ENC_BLOCK_SIZE) != 0) {
		LOG_ERR("Unaligned image, header %u, size %u", payload_off, payload_size);
		return -EBADMSG;
	}

	/*
	 * Key exchange, all in boot_enc_load() and boot_decrypt_key():
	 *  1. find the ENC TLV, it holds the ephemeral public key, the MAC tag and the wrapped
	 *     AES key
	 *  2. import the device private key, enc_priv_key[], into PSA
	 *  3. ECDH of the device key and the ephemeral public key gives the shared secret
	 *  4. HKDF-SHA512 of the shared secret, with info "MCUBoot_ECIES_v1", gives the key
	 *     encryption key and the HMAC key
	 *  5. import the HMAC key and verify the MAC tag over the wrapped key
	 *  6. import the key encryption key and unwrap the AES key with AES-CTR
	 * The AES key that encrypts the image payload ends up in bs.enckey.
	 */
	rc = boot_enc_load(&state, BOOT_SLOT_PRIMARY, &hdr, &slot0_area, &bs);
	if (rc != 0) {
		LOG_ERR("Could not load the image encryption key, err %d", rc);
		rc = -EACCES;
		goto out;
	}

	rc = boot_enc_set_key(enc, bs.enckey[BOOT_SLOT_PRIMARY]);
	if (rc != 0) {
		LOG_ERR("Could not set the image encryption key");
		rc = -EIO;
		goto out;
	}

	/*
	 * The encrypted flag is also set in an image that is not encrypted, for example the one
	 * programmed with the production image. Decrypt the first block in RAM and continue only
	 * if it is a vector table, so nothing is written for such an image.
	 */
	rc = flash_area_read(&slot0_area, payload_off, first_block, sizeof(first_block));
	if (rc) {
		rc = -EIO;
		goto out;
	}

	boot_enc_decrypt(enc, 0, sizeof(first_block), 0, first_block);

	if (!vector_table_plausible(first_block)) {
		LOG_WRN("Image payload is not encrypted, leaving it as is");
		rc = ENC_IMAGE_ALREADY_PLAINTEXT;
		goto out;
	}

	LOG_INF("Decrypting %u bytes in place", payload_size);

	/* Only the payload is encrypted, the header and the TLVs are left as they are. */
	for (done = 0; done < payload_size; done += sizeof(work_buf)) {
		uint32_t len = MIN(sizeof(work_buf), payload_size - done);

		rc = flash_area_read(&slot0_area, payload_off + done, work_buf, len);
		if (rc) {
			rc = -EIO;
			goto out;
		}

		boot_enc_decrypt(enc, done, len, done % BOOT_ENC_BLOCK_SIZE, work_buf);

		rc = slot0_write(payload_off + done, work_buf, len);
		if (rc) {
			LOG_ERR("Decryption failed, err %d, image is invalid", rc);
			goto out;
		}
	}

	rc = ENC_IMAGE_DECRYPTED;
out:
	boot_enc_zeroize(BOOT_CURR_ENC(&state));
	memset(&bs, 0, sizeof(bs));

	return rc;
}

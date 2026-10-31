/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef ENC_IMAGE_H_
#define ENC_IMAGE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The image in slot0 was encrypted and has been decrypted in place. */
#define ENC_IMAGE_DECRYPTED 0
/** The image in slot0 is not flagged as encrypted; nothing was changed. */
#define ENC_IMAGE_NOT_ENCRYPTED 1
/** The image is flagged as encrypted but its payload is already plaintext; nothing was changed. */
#define ENC_IMAGE_ALREADY_PLAINTEXT 2

/**
 * In-place decrypt the image in slot0/app slot if it is a valid MCUboot encrypted image.
 *
 * Hook after the image upload has completed and all writes have finished. The decryption is done
 * with MCUboot's bootutil code and the private key from the key record at the end of the boot
 * partition. An interruption leaves a partly decrypted image: MCUboot rejects it at the next boot
 * and starts the firmware loader, which waits for a new upload.
 *
 * @retval ENC_IMAGE_DECRYPTED, ENC_IMAGE_NOT_ENCRYPTED or ENC_IMAGE_ALREADY_PLAINTEXT on success.
 * @retval -errno on failure.
 */
int enc_image_decrypt_slot0(void);

#ifdef __cplusplus
}
#endif

#endif /* ENC_IMAGE_H_ */

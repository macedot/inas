#ifndef AES_APPLE_H_
#define AES_APPLE_H_

/*
   Copyright (C) 2025 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "aes_apple.h"

#ifdef __APPLE__

#include <CommonCrypto/CommonCrypto.h>
#include <pthread.h>
#include <string.h>

#define AES128_KEY_LEN 16
#define AES128_BLOCK_SIZE 16

/*
 * The ECB primitive is called once per 16-byte block by the CMAC and CCM
 * constructions. Creating and releasing a CCCryptor per call dominated the
 * profile on sealed sessions (~65k create/release cycles per MB per crypto
 * pass). ECB with padding disabled carries no state between updates, so a
 * small cache of keyed cryptors is safe and keeps the function signature.
 * A mutex guards the cache and the shared cryptors; the lock is uncontended
 * in the common single-thread path and far cheaper than the churn it
 * replaces.
 */
#define AES_APPLE_CACHE_SLOTS 8
static struct {
        uint8_t key[AES128_KEY_LEN];
        CCCryptorRef cryptor;
} aes_apple_cache[AES_APPLE_CACHE_SLOTS];
static pthread_mutex_t aes_apple_lock = PTHREAD_MUTEX_INITIALIZER;
static int aes_apple_next_slot;

void AES128_ECB_encrypt_apple(const uint8_t *input, const uint8_t *key, uint8_t *output) {
    CCCryptorRef cryptor = NULL;
    int slot = -1;
    int i;

    pthread_mutex_lock(&aes_apple_lock);
    for (i = 0; i < AES_APPLE_CACHE_SLOTS; i++) {
        if (aes_apple_cache[i].cryptor != NULL &&
            memcmp(aes_apple_cache[i].key, key, AES128_KEY_LEN) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        slot = aes_apple_next_slot;
        aes_apple_next_slot = (aes_apple_next_slot + 1) % AES_APPLE_CACHE_SLOTS;
        if (aes_apple_cache[slot].cryptor != NULL) {
            CCCryptorRelease(aes_apple_cache[slot].cryptor);
            aes_apple_cache[slot].cryptor = NULL;
        }
        if (CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode,
                            key, AES128_KEY_LEN, NULL,
                            &aes_apple_cache[slot].cryptor) == kCCSuccess) {
            memcpy(aes_apple_cache[slot].key, key, AES128_KEY_LEN);
        } else {
            aes_apple_cache[slot].cryptor = NULL;
        }
    }
    cryptor = aes_apple_cache[slot].cryptor;
    if (cryptor != NULL) {
        size_t dataOutMoved = 0;
        (void)CCCryptorUpdate(cryptor, input, AES128_BLOCK_SIZE,
                              output, AES128_BLOCK_SIZE, &dataOutMoved);
    }
    pthread_mutex_unlock(&aes_apple_lock);
}

#endif

#endif

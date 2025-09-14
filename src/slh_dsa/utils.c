#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "../../sphincsplus/ref/randombytes.h"
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/fors.h"
#include "../../sphincsplus/ref/hash.h"
#include "../../sphincsplus/ref/thash.h"
#include "../../sphincsplus/ref/utils.h"
#include "../../sphincsplus/ref/address.h"
#include "libbitcoinpqc/slh_dsa.h"

/*
 * This file implements utility functions for SLH-DSA-Shake-128s (SPHINCS+)
 * particularly related to random data handling
 */

/* Provide a custom random bytes function that uses user-provided entropy */
static const uint8_t *g_random_data = NULL;
static size_t g_random_data_size = 0;
static size_t g_random_data_offset = 0;

/* Initialize the random data source */
void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size) {
    g_random_data = random_data;
    g_random_data_size = random_data_size;

    /* Always reset offset to ensure deterministic behavior */
    g_random_data_offset = 0;

    /* Note: For truly deterministic behavior across multiple calls,
     * we should hash the random data with some constant seed, but
     * for this implementation we'll just use the raw data.
     */
}

/* Setup custom random function - this is called before keygen/sign */
void slh_dsa_setup_custom_random() {
    /* Nothing to do here, as we can't replace the function */
}

/* Restore original random function - this is called after keygen/sign */
void slh_dsa_restore_original_random() {
    /* Clear the global state */
    g_random_data = NULL;
    g_random_data_size = 0;
    g_random_data_offset = 0;
}

/* This function is called from our custom randombytes implementation */
void custom_slh_randombytes_impl(uint8_t *out, size_t outlen) {
    /* If we don't have custom random data, use system randomness */
    if (g_random_data == NULL || g_random_data_size == 0) {
        /* Fall back to system randomness */
        FILE *f = fopen("/dev/urandom", "r");
        if (!f) {
            /* If we can't open /dev/urandom, just fill with zeros */
            memset(out, 0, outlen);
            return;
        }

        if (fread(out, 1, outlen, f) != outlen) {
            /* If we can't read enough data, fill remaining with zeros */
            memset(out, 0, outlen);
        }

        fclose(f);
        return;
    }

    /* Otherwise use our provided random data */
    size_t remaining = g_random_data_size - g_random_data_offset;

    if (outlen > remaining) {
        /* If we need more random bytes than available, we cycle through the provided data */
        size_t position = 0;

        while (position < outlen) {
            size_t to_copy = (outlen - position < remaining) ? outlen - position : remaining;
            memcpy(out + position, g_random_data + g_random_data_offset, to_copy);

            position += to_copy;
            g_random_data_offset = (g_random_data_offset + to_copy) % g_random_data_size;
            remaining = g_random_data_size - g_random_data_offset;
        }
    } else {
        /* We have enough random data */
        memcpy(out, g_random_data + g_random_data_offset, outlen);
        g_random_data_offset = (g_random_data_offset + outlen) % g_random_data_size;
    }
}

/* Simple implementation of deterministic randomness from message and key */
void slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    /* Create a buffer to hold combined data */
    size_t combined_len = mlen + CRYPTO_SECRETKEYBYTES;
    uint8_t *combined = malloc(combined_len);

    if (combined) {
        /* Combine secret key and message */
        memcpy(combined, sk, CRYPTO_SECRETKEYBYTES);
        memcpy(combined + CRYPTO_SECRETKEYBYTES, m, mlen);

        /* Use custom hash function (simple XOR of message with key for each block) */
        uint8_t buffer[64] = {0};
        for (size_t i = 0; i < combined_len; i++) {
            buffer[i % 64] ^= combined[i];
        }

        /* Ensure the randomness looks random enough */
        for (size_t i = 0; i < 10; i++) {
            for (size_t j = 0; j < 64; j++) {
                buffer[j] = buffer[(j + 1) % 64] ^ buffer[(j + 7) % 64] ^ buffer[(j + 13) % 64];
            }
        }

        /* Copy the result */
        memcpy(seed, buffer, 64);

        /* Clean up */
        memset(combined, 0, combined_len);
        free(combined);
    } else {
        /* Fallback if memory allocation fails */
        memset(seed, 0, 64);
    }
}

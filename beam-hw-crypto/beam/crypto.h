// Copyright 2019 The Beam Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.#include "misc.h"

#ifndef _BEAM_CRYPTO_
#define _BEAM_CRYPTO_

#if defined(LEDGER_SDK)
#include "os.h"
#include "cx.h"
#endif // LEDGER_SDK
#include "debug.h"
#include "beam/definitions.h"
#if defined(TREZOR_CRYPTO_MOD) || defined(LEDGER_SDK) || defined(DESKTOP_SDK)
#include "lib/aes/aes.h"
#endif // TREZOR_CRYPTO_MOD
#ifdef DESKTOP_SDK
#   define USE_BASIC_CONFIG
#   include "secp256k1-zkp/src/basic-config.h"
#   include "secp256k1-zkp/include/secp256k1.h"
#   include "secp256k1-zkp/src/scalar.h"
#   include "secp256k1-zkp/src/group.h"
#   include "secp256k1-zkp/src/hash.h"
#endif // DESKTOP_SDK

#define BIP32_PATH 5

#if defined(LEDGER_SDK)
typedef cx_sha256_t beam_sha256_ctx;
typedef cx_hmac_sha256_t beam_hmac_sha256_ctx;
#elif defined(TREZOR_CRYPTO_MOD)
#include "crypto_trezor/hmac.h"
typedef SHA256_CTX beam_sha256_ctx;
typedef HMAC_SHA256_CTX beam_hmac_sha256_ctx;
#elif defined(DESKTOP_SDK)
    typedef secp256k1_sha256_t beam_sha256_ctx;
    typedef secp256k1_hmac_sha256_t beam_hmac_sha256_ctx;
#else
#error "Define your own SHA256 and HMAC_SHA256 contexts!"
#endif

// AES/DES/RSA are not available for non genuine Ledger applications.
// This is because of some law concerning cryptography export between France and foreing country.
#if defined(LEDGER_NATIVE_CRYPT)
typedef cx_aes_key_t beam_aes_ctx;
#else
typedef aes_encrypt_ctx beam_aes_ctx;
#endif // LEDGER_NATIVE_CRYPT | ..


typedef struct
{
  uint8_t margin;
  uint8_t x[32];
  uint8_t y[32];
} pxy_t;

void beam_rng(uint8_t* dest, uint32_t len);
void beam_gej_to_pxy(const secp256k1_gej* gej, pxy_t* pxy);
void beam_pxy_to_point(const pxy_t* pxy, point_t* pt);
void beam_pxy_to_gej(const pxy_t *pxy, secp256k1_gej *pt);
void beam_pxy_mul_scalar(pxy_t *pxy, const secp256k1_scalar *sk);

void beam_pbkdf2_sha512(const uint8_t *password, unsigned short passwordlen, uint8_t *salt,
                        unsigned short saltlen, unsigned int iterations, uint8_t *out, unsigned int outLength);

void beam_hash_sha256_write_8(beam_sha256_ctx *hasher, uint8_t b);
void beam_hash_sha256_write_64(beam_sha256_ctx *hasher, uint64_t v);

void beam_hash_sha256_init(beam_sha256_ctx *hasher);
void beam_hash_sha256_update(beam_sha256_ctx *hasher, const uint8_t *buf, unsigned int len);
int beam_hash_sha256_final(beam_sha256_ctx *hasher, uint8_t *out);

void beam_hash_hmac_sha256_init(beam_hmac_sha256_ctx *hasher, const uint8_t *key, const uint32_t keylen);
void beam_hash_hmac_sha256_update(beam_hmac_sha256_ctx *hasher, const uint8_t *buf, unsigned int len);
int beam_hash_hmac_sha256_final(beam_hmac_sha256_ctx *hasher, uint8_t *out);

void beam_get_private_key_data(uint8_t *data);

void beam_aes_init(beam_aes_ctx *ctx, const uint8_t *key32);
void beam_aes_encrypt(const beam_aes_ctx *ctx, const uint8_t *iv, const uint8_t *in, uint8_t *out, uint32_t len);

#endif //_BEAM_CRYPTO_

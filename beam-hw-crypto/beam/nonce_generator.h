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

#ifndef _NONCE_GENERATOR_H_
#define _NONCE_GENERATOR_H_

#include "crypto.h"
#include "internal.h"

typedef struct {
  beam_hmac_sha256_ctx hash;
  uint8_t prk[32];
  uint8_t okm[32];
  uint8_t number;
} nonce_generator_t;

int is_scalar_valid(uint8_t *scalar);

void nonce_generator_init(nonce_generator_t *nonce, const uint8_t *salt,
                          uint8_t salt_size);

void nonce_generator_write(nonce_generator_t *nonce, const uint8_t *seed,
                           uint8_t seed_size);

void nonce_generator_get_first_output_key_material(nonce_generator_t *nonce,
                                                   const uint8_t *context,
                                                   size_t context_size);

void nonce_generator_get_rest_output_key_material(nonce_generator_t *nonce,
                                                  const uint8_t *context,
                                                  size_t context_size);

uint8_t nonce_generator_export_output_key(nonce_generator_t *nonce,
                                          const uint8_t *context,
                                          uint8_t context_size, uint8_t *okm32);

uint8_t nonce_generator_export_scalar(nonce_generator_t *nonce,
                                      const uint8_t *context,
                                      uint8_t context_size,
                                      secp256k1_scalar *out_scalar);

#endif  // _NONCE_GENERATOR_H_

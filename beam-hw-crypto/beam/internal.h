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

#ifndef _INTERNAL_FUNCTIONS_
#define _INTERNAL_FUNCTIONS_

#include "definitions.h"
#include "crypto.h"

int memis0(const void* p, const size_t n);
void memxor(uint8_t* pDst, const uint8_t* pSrc, const size_t n);
void assign_aligned(uint8_t* dest, uint8_t* src, const size_t bytes);
#if defined(LEDGER_SDK)
void memzero(uint8_t* dest, const size_t bytes);
#endif // LEDGER_SDK

int scalar_import_nnz(secp256k1_scalar *scalar, const uint8_t *data32);
int export_gej_to_point(const secp256k1_gej *native_point, point_t *out_point);
void generator_mul_scalar(secp256k1_gej *res, const secp256k1_gej *pPts, const secp256k1_scalar *sk);
void gej_mul_scalar(const secp256k1_gej *pt, const secp256k1_scalar *sk, secp256k1_gej *res);
void scalar_create_nnz(beam_sha256_ctx *oracle, secp256k1_scalar *out_scalar);

void generate_HKdfPub(const uint8_t *secret_key, const secp256k1_scalar *cofactor,
                      const secp256k1_gej *G_pts, const secp256k1_gej *J_pts,
                      HKdf_pub_packed_t *packed);

void xcrypt(const uint8_t *secret_digest, uint8_t *data, size_t mac_value_size,
            size_t data_size);

uint32_t export_encrypted(const void *p, size_t size, uint8_t code,
                           const uint8_t *secret, size_t secret_size,
                           const uint8_t *meta, size_t meta_size, uint8_t *out);

int point_import_nnz(secp256k1_gej *gej, const point_t *point);
int point_import(secp256k1_gej *gej, const point_t *point);
void point_create_nnz(beam_sha256_ctx* oracle, secp256k1_gej *out_gej);

#endif  //_INTERNAL_FUNCTIONS_

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

#ifndef _ORACLE_H_
#define _ORACLE_H_

#include "definitions.h"
#include "crypto.h"

void sha256_oracle_update_gej(beam_sha256_ctx* oracle, const secp256k1_gej* gej);

void sha256_oracle_update_pt(beam_sha256_ctx* oracle, const point_t* pt);

void sha256_oracle_update_sk(beam_sha256_ctx* oracle, const secp256k1_scalar* sk);

void sha256_oracle_create(beam_sha256_ctx* oracle, uint8_t* out32);

#endif  //_ORACLE_H_

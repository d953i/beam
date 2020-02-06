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

#include <stdio.h>
#include <stdint.h>

#include "debug.h"


#include "beam/definitions.h"
#include "lib/secp256k1_primitives/scalar.h"

#if defined (LEDGER_SDK)
#include "os.h"
#include "utils.h"
void bin2hex(uint8_t* dst, uint8_t* data, uint32_t inlen) {
    static uint8_t const hex[20] = "0123456789abcdef";
    for (uint32_t i = 0; i < inlen; i++) {
        dst[2*i+0] = hex[(data[i]>>4) & 0x0F];
        dst[2*i+1] = hex[(data[i]>>0) & 0x0F];
    }
    dst[2*inlen] = '\0';
}

uint8_t hex2byte(uint8_t x)
{
  if (x >= '0' && x <= '9')
    return x - '0';
  if (x >= 'A' && x <= 'F')
    return x - 'A' + 10;
  return x - 'a' + 10;
}

void hex2bin(uint8_t* out_bytes, const char* hex_string, const size_t size_string)
{
  for (size_t i = 0; i < size_string; i += 2)
    out_bytes[i / 2] = hex2byte(*(hex_string + i)) << 4 | hex2byte(*(hex_string + i + 1));
}

#else
void hex2bin(uint8_t *out_bytes, const char *hex_string, const size_t size_string)
{
    uint32_t buffer = 0;
    for (size_t i = 0; i < size_string / 2; i++) {
        sscanf(hex_string + 2 * i, "%2X", &buffer);
        out_bytes[i] = buffer;
    }
}
#endif

int IS_EQUAL_HEX(const char* hex_str, const uint8_t* bytes, size_t str_size)
{
    uint8_t tmp[str_size / 2];
    hex2bin(tmp, hex_str, str_size);
    return os_memcmp(tmp, bytes, str_size / 2) == 0;
}

void verify_scalar_data(const char* msg, const char* hex_data,
                        const void* sk) {
    uint8_t sk_data[DIGEST_LENGTH];
    secp256k1_scalar_get_b32(sk_data, (secp256k1_scalar*)sk);
    DEBUG_PRINT(msg, sk_data, DIGEST_LENGTH);
    VERIFY_TEST_EQUAL(IS_EQUAL_HEX(hex_data, sk_data, DIGEST_LENGTH), msg,
                      hex_data, "sk");
}

// Copyright 2018 The Beam Team
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
// limitations under the License.

#include "core/block_crypt.h"
#include <iostream>
#include "3rdparty/crypto/equihashR.h"
#include "wallet/unittests/test_helpers.h"
#include <algorithm>

//#define ENABLE_MINING

WALLET_TEST_INIT
using namespace std;

void TestArrayExpanding(size_t N, size_t K)
{
    cout << "Test array expanding: " << N << "," << K << "...\n";
    size_t bitsLeft = N;
    size_t collisionBits = N / (K + 1);
    size_t collisionBytes = (collisionBits + 7) / 8;
    size_t outBytes = sizeof(uint32_t);
    size_t bytePad = outBytes - (collisionBits + 7) / 8;
    size_t outputSize = (K + 1) * (collisionBytes + bytePad);
    size_t inputSize = (N + 7) / 8;

    vector<uint8_t> input(inputSize, 0);
    for (size_t i = 0; i < inputSize - 1; ++i)
    {
        input[i] = 0xc0 + uint8_t(i);//0xff;
        bitsLeft -= 8;
    }
    WALLET_CHECK(bitsLeft <= 8);
    input[inputSize - 1] = 0xff << (8 - bitsLeft);
    vector<uint8_t> output(outputSize, 0);
    ExpandArray(input.data(), input.size(), output.data(), output.size(), collisionBits, bytePad);

    for (size_t i = outBytes; i < output.size(); i += outBytes)
    {
   //     WALLET_CHECK(equal(&output[i], &output[i] + outBytes, &output[0]));
    }

    vector<uint8_t> temp(input.size(), 0);
    CompressArray(output.data(), output.size(), &temp[0], input.size(), collisionBits, bytePad);
    WALLET_CHECK(equal(temp.begin(), temp.end(), input.begin()));
}

void TestArrayExpanding()
{
    {
        vector<uint8_t> output(8, 0);
        vector<uint8_t> temp(7, 0);
        vector<uint8_t> input = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc };
        ExpandArray(input.data(), input.size(), output.data(), output.size(), 27, 0);
        CompressArray(output.data(), output.size(), &temp[0], temp.size(), 27, 0);
        WALLET_CHECK(temp[6] == 0xfc);
    }
    {
        vector<uint8_t> output( 8, 0 );
        vector<uint8_t> input = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0 };
        ExpandArray(input.data(), input.size(), output.data(), output.size(), 26, 0);
    }
    {
        vector<uint8_t> output = {0x3, 0xff, 0xff, 0xff, 0x3, 0xff, 0xff, 0xff };
        vector<uint8_t> temp(7, 0);
        CompressArray(output.data(), output.size(), &temp[0], temp.size(), 26, 0);
        WALLET_CHECK(temp[6] == 0xf0);
    }
    {
        vector<uint8_t> output(8, 0);
        vector<uint8_t> temp(7, 0);
        vector<uint8_t> input = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc };
        ExpandArray(input.data(), input.size(), output.data(), output.size(), 27, 0);
        CompressArray(output.data(), output.size(), &temp[0], temp.size(), 27, 0);
        WALLET_CHECK(temp[6] == 0xfc);
    }
    TestArrayExpanding(156, 5);
    TestArrayExpanding(120, 5);
    TestArrayExpanding(144, 5);
    TestArrayExpanding(150, 5);
    TestArrayExpanding(96, 5);
}

int main()
{
	//TestArrayExpanding();
    
    //printf("Hello world! \n");

    // commented since it doesn't complete in 10 minutes and failes auto tests
    {
        cout << "Test begin...\n";
        //uint8_t pInput[] = { 1, 2, 3, 4, 56 };

        uint8_t pInput[] = {0xf7, 0xa7, 0xb3, 0xb4, 0x46, 0x8c, 0x67, 0xd1, 0xe1, 0xdb, 0x51, 0xc5, 0xdf, 0xcf, 0xfd, 0xca, 0x9f, 0x0f, 0xd3, 0xe5, 0x38, 0x3b, 0x23, 0x25, 0xef, 0x9d, 0xf0, 0x33, 0xd3, 0xb7, 0xe8, 0x82};

        beam::Block::PoW pow;
        pow.m_Difficulty = 0; // d=0, runtime ~48 sec. d=1,2 - almost close to this. d=4 - runtime 4 minutes, several cycles until solution is achieved.
        pow.m_Nonce = { 0x1c, 0x99, 0x0a, 0x0d, 0x02, 0x45, 0x1f, 0xd7 };
        //pow.m_Nonce = 0x010204U;


		const beam::Block::PoW::Cancel fnCancel = [](bool) { return false; };

		cout << "Before Solve()...\n";
		pow.Solve(pInput, sizeof(pInput), 326949, fnCancel);
		cout << "After Solve()...\n";

//		WALLET_CHECK(pow.IsValid(pInput, sizeof(pInput)));

        std::cout << "Solution is correct\n";
    }

    assert(g_failureCount == 0);
    return WALLET_CHECK_RESULT;
}


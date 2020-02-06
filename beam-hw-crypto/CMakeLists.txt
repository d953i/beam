set(HW_WALLET_TEST_SRC
    hw_wallet_test.cpp
    beam/crypto.c
    beam/debug.c
    beam/definitions.c
    beam/definitions_ipp.c
    beam/functions.c
    beam/inner_product.c
    beam/internal.c
    beam/kernel.c
    beam/misc.c
    beam/multi_mac.c
    beam/nonce_generator.c
    beam/oracle.c
    beam/rangeproof.c
    beam/sign.c
    lib/aes/aescrypt.c
    lib/aes/aes_modes.c
    lib/aes/aeskey.c
    lib/aes/aestab.c
# ~etc
)


add_executable(hw_wallet_test ${HW_WALLET_TEST_SRC})
add_test(NAME hw_wallet_test COMMAND $<TARGET_FILE:hw_wallet_test>)

target_include_directories(hw_wallet_test PUBLIC beam)
target_include_directories(hw_wallet_test PUBLIC ./)

add_definitions(-DDESKTOP_SDK)

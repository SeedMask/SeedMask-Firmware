/* Embedded / Arduino build: CMake would generate this. Values follow libsecp256k1 defaults. */
#ifndef LIBSECP256K1_CONFIG_H
#define LIBSECP256K1_CONFIG_H

#define ECMULT_WINDOW_SIZE 15
#define ECMULT_GEN_PREC_BITS 4

/* ESP32 (Xtensa): no reliable __int128; use 64-bit wide multiplication + 10x26 field. */
#if !defined(SECP256K1_WIDEMUL_INT128) && !defined(SECP256K1_WIDEMUL_INT64)
#define SECP256K1_WIDEMUL_INT64 1
#endif

#endif /* LIBSECP256K1_CONFIG_H */

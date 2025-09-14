{
  "targets": [
    {
      "target_name": "bitcoinpqc",
      "sources": [
        "src/native/bitcoinpqc_addon.cc",
        "../src/bitcoinpqc.c",
        "../src/ml_dsa/keygen.c",
        "../src/ml_dsa/sign.c",
        "../src/ml_dsa/verify.c",
        "../src/ml_dsa/utils.c",
        "../src/slh_dsa/keygen.c",
        "../src/slh_dsa/sign.c",
        "../src/slh_dsa/verify.c",
        "../src/slh_dsa/utils.c",
        "../src/fn_dsa/keygen.c",
        "../src/fn_dsa/sign.c",
        "../src/fn_dsa/verify.c",
        "../src/fn_dsa/utils.c",
        "../dilithium/ref/sign.c",
        "../dilithium/ref/packing.c",
        "../dilithium/ref/polyvec.c",
        "../dilithium/ref/poly.c",
        "../dilithium/ref/ntt.c",
        "../dilithium/ref/reduce.c",
        "../dilithium/ref/rounding.c",
        "../dilithium/ref/fips202.c",
        "../dilithium/ref/symmetric-shake.c",
        "../dilithium/ref/randombytes_custom.c",
        "../sphincsplus/ref/address.c",
        "../sphincsplus/ref/fors.c",
        "../sphincsplus/ref/hash_shake.c",
        "../sphincsplus/ref/merkle.c",
        "../sphincsplus/ref/sign.c",
        "../sphincsplus/ref/thash_shake_simple.c",
        "../sphincsplus/ref/utils.c",
        "../sphincsplus/ref/utilsx1.c",
        "../sphincsplus/ref/wots.c",
        "../sphincsplus/ref/wotsx1.c",
        "../sphincsplus/ref/fips202.c",
        "../falcon/codec.c",
        "../falcon/common.c",
        "../falcon/falcon.c",
        "../falcon/fft.c",
        "../falcon/fpr.c",
        "../falcon/keygen.c",
        "../falcon/shake.c",
        "../falcon/sign.c",
        "../falcon/vrfy.c",
        "../falcon/rng.c"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "../include",
        "../dilithium/ref",
        "../sphincsplus/ref",
        "../falcon"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "cflags": [ "-Wno-sign-compare", "-Wno-unused-variable", "-Wno-implicit-function-declaration" ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "DILITHIUM_MODE=2",
        "CRYPTO_ALGNAME=\"SPHINCS+-shake-128s\"",
        "PARAMS=sphincs-shake-128s",
        "FALCON_LOGN_512=9",
        "CUSTOM_RANDOMBYTES=1"
      ],
      "conditions": [
        ["OS=='win'", {
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1
            }
          }
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "GCC_SYMBOLS_PRIVATE_EXTERN": "YES",
            "OTHER_CFLAGS": [
              "-Wno-sign-compare",
              "-Wno-unused-variable",
              "-Wno-implicit-function-declaration"
            ]
          },
          "defines": [
            "FALCON_FPEMU=1"
          ]
        }]
      ]
    }
  ]
}

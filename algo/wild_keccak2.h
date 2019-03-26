// Copyright (c) 2014-2018 Zano Project
// Copyright (c) 2014-2018 Zano Project
// Copyright (c) 2014-2018 The Louisdor Project
// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// keccak.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>
// A baseline Keccak (3rd round) implementation.

// Memory-hard extension of keccak for PoW
// Copyright (c) 2014 The Boolberry developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WILD_KECCAK2_H
#define WILD_KECCAK2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void wild_keccak2_hash(char* output, const char* input, uint32_t input_len);
bool wildkeccak2_generate_scratchpad(const char *seed_data, uint64_t height);
uint64_t wildkeccak2_scratchpad_size(uint64_t h);

#ifdef __cplusplus
}
#endif

#endif

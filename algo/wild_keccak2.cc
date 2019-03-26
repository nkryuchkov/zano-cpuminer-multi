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

#include "miner.h"

#include "wild_keccak2.h"
#include "crypto/wild_keccak2.h"

#include <iostream>

#define CURRENCY_SCRATCHPAD_BASE_SIZE           16777210 //count in crypto::hash, to get size in bytes x32
#define CURRENCY_SCRATCHPAD_REBUILD_INTERVAL    720 //once a day if block goes once in 2 minute
#define DIFFICULTY_POS_TARGET                   120 // seconds
#define DIFFICULTY_POW_TARGET                   120 // seconds
#define DIFFICULTY_TOTAL_TARGET                 ((DIFFICULTY_POS_TARGET + DIFFICULTY_POW_TARGET) / 4)
#define DIFFICULTY_WINDOW                       720 // blocks
#define DIFFICULTY_LAG                          15  // !!!
#define DIFFICULTY_CUT                          60  // timestamps to cut after sorting
#define DIFFICULTY_BLOCKS_COUNT                 (DIFFICULTY_WINDOW + DIFFICULTY_LAG)
#define CURRENCY_BLOCKS_PER_DAY                 ((60*60*24)/(DIFFICULTY_TOTAL_TARGET))

extern pthread_mutex_t rpc2_scratchpad_lock;

extern "C" {

void wild_keccak2_hash_impl(char *output, const char *input, uint32_t input_len, const char *scratchpad, uint64_t spad_length) {
    crypto::get_wild_keccak2(std::string(input, input_len), *((crypto::hash *) output), (const uint64_t*) scratchpad, spad_length / 8);
}

void wild_keccak2_hash(char* output, const char* input, uint32_t input_len) {
    if (!pscratchpad_buff) {
        return;
    }
    pthread_mutex_lock(&rpc2_scratchpad_lock);

    wild_keccak2_hash_impl(output, input, input_len, pscratchpad_buff, scratchpad_size);
    pthread_mutex_unlock(&rpc2_scratchpad_lock);
}

int scanhash_wildkeccak2(int thr_id, struct work *work, uint32_t max_nonce, unsigned long *hashes_done) {
    uint64_t *nonceptr = (uint64_t * )(((char *) work->data) + 1);
    uint64_t n = *nonceptr - 1;
    const uint64_t first_nonce = n + 1;
    char hash[HASH_SIZE] __attribute__((aligned(32)));

    if (work->job_len == 0) {
        return 0;
    }

    do {
        *nonceptr = ++n;
        wild_keccak2_hash((char *) hash, (char *) work->data, work->job_len);
        //if (unlikely(  *((uint64_t*)&hash[6])    <   *((uint64_t*)&work->target[6]) ))
        if (unlikely(((uint32_t *)hash)[7] < work->target[7])) {
            *hashes_done = n - first_nonce + 1;
            return true;
        }
    } while (likely((n <= max_nonce && !work_restart[thr_id].restart)));

    *hashes_done = n - first_nonce + 1;
    return 0;
}

uint64_t get_scratchpad_last_update_rebuild_height(uint64_t h) {
    return h - (h % CURRENCY_SCRATCHPAD_REBUILD_INTERVAL);
}

uint64_t get_scratchpad_size_for_height(uint64_t h){
    if (h < CURRENCY_BLOCKS_PER_DAY * 7)
    {
        return 100;
    }
    //let's have ~250MB/year if block interval is 2 minutes
    return CURRENCY_SCRATCHPAD_BASE_SIZE + get_scratchpad_last_update_rebuild_height(h)*30;
}


bool wildkeccak2_generate_scratchpad(const char *seed_data, uint64_t height) {
    crypto::hash seed = *(crypto::hash *) seed_data;
    std::vector <crypto::hash> result;
    uint64_t len = get_scratchpad_size_for_height(height);
    bool ret = crypto::generate_scratchpad(seed, result, len);
    if (!ret) {
        return false;
    }
    if (pscratchpad_buff) {
        free(pscratchpad_buff);
    }
    pscratchpad_buff = (char *) malloc(len);
    memcpy(pscratchpad_buff, result.data(), len);
    scratchpad_size = len;
    return true;
}

uint64_t wildkeccak2_scratchpad_size(uint64_t h) {
    return get_scratchpad_size_for_height(h);
}

}
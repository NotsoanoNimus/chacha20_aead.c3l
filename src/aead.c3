/**
 * Copyright (c) 2025 Zack Puhl (@NotsoanoNimus) - https://github.com/NotsoanoNimus/chacha20_aead.c3l
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
module chacha20_poly1305;

import chacha20;
import poly1305;


enum CryptMode : char
{
    ENCRYPT,
    DECRYPT,
    DECRYPT_NO_AUTH,
}

alias FnHeapAllocate = chacha20::FnHeapAllocate;
alias FnHeapFree = fn(void*);

struct CryptoAllocator
{
    FnHeapAllocate  allocate;
    FnHeapFree      free;
}

faultdef
    DATA_NOT_AUTHENTICATED, OUT_OF_RESOURCES;


fn char[poly1305::KEY_SIZE] poly1305_key_gen(char[] key, char[] nonce) @local
{
    char[poly1305::KEY_SIZE] result;
    char[chacha20::BLOCK_SIZE] dummy;

    // We want to know the key_stream value after one set of ChaCha20 on a block, whose data doesn't matter..
    //   That key_stream is used as the input key to Poly1305.
    ChaCha20 c @noinit;
    c.init(key, nonce, 0);   // NOTE: '0' counter value is important here.
    c.xor(dummy[..]);

    for (int i = 0; i < poly1305::KEY_SIZE; ++i) result[i] = ((char*)(&c.key_stream[0]))[i];
    return result;
}


<*
    @require result.len >= input.len : `The "result" slice cannot be smaller than the "input" slice.`
    @require tag.len >= poly1305::TAG_SIZE : `The "tag" field must be large enough for a Poly1305 hash.`
    @require key.len == chacha20::KEY_SIZE : `The "key" slice must be exactly 32 bytes long.`
    @require nonce.len == chacha20::IV_SIZE : `The "nonce" slice must be exactly 12 bytes long.`
*>
fn void? crypt_and_tag(CryptMode mode, char[] result, char[] tag, char[] input,
                        char[] additional_input, char[] key, char[] nonce,
                        CryptoAllocator allocator)
{
    switch (mode) {
        // See: RFC8439, section 2.8
        case CryptMode.ENCRYPT: {
            char[poly1305::KEY_SIZE] gen_key = poly1305_key_gen(key, nonce);

            chacha20::encrypt_into(input, result, key, nonce, 1)!;

            usz padding1_len = (additional_input.len % 16) ? (16 - (additional_input.len % 16)) : 0;
            usz padding2_len = (input.len % 16) ? (16 - (input.len % 16)) : 0;

            // The "scratch" buffer will be digested by Poly1305 with the generated key in order to generate the authentication tag.
            usz scratch_len = additional_input.len + padding1_len + input.len + padding2_len + (2 * ulong.sizeof);

            void* scratch = allocator.allocate(scratch_len);
            if (null == scratch) return OUT_OF_RESOURCES?;

            defer allocator.free(scratch);

            // Fill in the scratch buffer...
            char* scroll = (char*)scratch;
            usz i = 0;
            usz j = 0;

            if (additional_input.len) {
                for (; i < additional_input.len; ++i) scroll[i] = additional_input[i];
            }
            if (padding1_len) {
                for (; j < padding1_len; ++j, ++i) scroll[i + j] = 0;
            }
            if (padding2_len) {
                for (j = 0; j < padding2_len; ++j, ++i) scroll[i + j] = 0;
            }

            char[poly1305::TAG_SIZE] returned_tag = poly1305::hash(((char*)scratch)[:scratch_len], gen_key);

            for (usz i = 0; i < poly1305::TAG_SIZE; ++i) tag[i] = returned_tag[i];
        }

        case CryptMode.DECRYPT: nextcase;
        case CryptMode.DECRYPT_NO_AUTH: {
            //
        }
    }
}



// -----------------------------------------------------------------------------------
// TESTS
import libc;


fn void chacha20_poly1305__rfc8439_s2_6_2() @test
{
    char[] key = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    char[] nonce = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

    uint[16] expected_initial_state = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c,
        0x93929190, 0x97969594, 0x9b9a9998, 0x9f9e9d9c,
        0x00000000, 0x00000000, 0x03020100, 0x07060504,
    };

    uint[16] expected_poly1305_key = {
        0x8ba0d58a, 0xcc815f90, 0x27405081, 0x7194b24a,
        0x37b633a8, 0xa50dfde3, 0xe2b8db08, 0x46a6d1fd,
        0x7da03782, 0x9183a233, 0x148ad271, 0xb46773d1,
        0x3cc1875a, 0x8607def1, 0xca5c3086, 0x7085eb87,
    };

    ChaCha20 c @noinit;
    c.init(key, nonce, 0);

    assert(0 != libc::memcmp(&c.state[0], &expected_poly1305_key[0], 16 * uint.sizeof), "ChaCha20 initial state comparison sanity check.");
    assert(0 == libc::memcmp(&c.state[0], &expected_initial_state[0], 16 * uint.sizeof), "Invalid ChaCha20 initial state.");

    char[chacha20::BLOCK_SIZE] dummy;
    c.xor(dummy[..]);

    assert(0 != libc::memcmp(&c.key_stream[0], &expected_initial_state[0], 16 * uint.sizeof), "ChaCha20 key_stream comparison sanity check.");
    assert(0 == libc::memcmp(&c.key_stream[0], &expected_poly1305_key[0], 16 * uint.sizeof), "Invalid ChaCha20 key_stream after single run.");

    // Finally, assert that the local 'gen_key' function follows the same exact behavior.
    char[poly1305::KEY_SIZE] gen_key = poly1305_key_gen(key, nonce);
    assert(0 == libc::memcmp(&gen_key[0], &expected_poly1305_key[0], poly1305::KEY_SIZE), "`poly1305_key_gen` returned the wrong one-time key.");
}

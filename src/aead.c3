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
alias FnHeapFree = fn void*(void*);

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


fn char[]? make_scratch_buffer(char[] input, char[] additional_input, CryptoAllocator allocator) @local
{
    usz padding1_len = (additional_input.len % 16) ? (16 - (additional_input.len % 16)) : 0;
    usz padding2_len = (input.len % 16) ? (16 - (input.len % 16)) : 0;

    // The "scratch" buffer will be digested by Poly1305 with the generated key in order to generate the authentication tag.
    usz scratch_len = additional_input.len + padding1_len + input.len + padding2_len + (2 * ulong.sizeof);

    void* scratch = allocator.allocate(scratch_len);
    if (null == scratch) return OUT_OF_RESOURCES?;

    // Fill in the scratch buffer...
    char* scroll = (char*)scratch;
    usz i, j;

    for (i = 0; i < additional_input.len; ++i) scroll[i] = additional_input[i];
    for (j = 0; j < padding1_len; ++j, ++i) scroll[i] = 0;
    for (j = 0; j < input.len; ++j, ++i) scroll[i] = input[j];
    for (j = 0; j < padding2_len; ++j, ++i) scroll[i] = 0;

    *(ulong*)(&scroll[i]) = (ulong)additional_input.len;
    i += ulong.sizeof;
    *(ulong*)(&scroll[i]) = (ulong)input.len;
    i += ulong.sizeof;

    return ((char*)scratch)[:scratch_len];
}


import std::io;
<*
    @require result.len >= input.len : `The "result" slice cannot be smaller than the "input" slice.`
    @require tag.len >= poly1305::TAG_SIZE : `The "tag" field must be large enough for a Poly1305 hash.`
    @require key.len == chacha20::KEY_SIZE : `The "key" slice must be exactly 32 bytes long.`
    @require nonce.len == chacha20::IV_SIZE : `The "nonce" slice must be exactly 12 bytes long.`
*>
fn void? crypt_and_tag(CryptMode mode, char[] result, char[] tag, char[] input,
                        char[] additional_input, char[] key, char[] nonce,
                        CryptoAllocator allocator, uint counter = 1)
{
    bool must_validate = true;

    switch (mode) {
        // See: RFC8439, section 2.8
        case CryptMode.ENCRYPT: {
            char[poly1305::KEY_SIZE] gen_key = poly1305_key_gen(key, nonce);

            chacha20::encrypt_into(input, result, key, nonce, counter)!;

            // NOTE: The allocator's 'free' here should ideally wrap the normative 'free' and scramble/wipe the memory before doing so.
            // Also note: The CIPHERTEXT is used to make the scratch buffer here, NOT the plaintext. See RFC8439, section 2.8.
            char[] scratch = make_scratch_buffer(result, additional_input, allocator)!;
            defer allocator.free(scratch.ptr);

            char[poly1305::TAG_SIZE] returned_tag = poly1305::hash(scratch, gen_key[..]);

            for (usz i = 0; i < poly1305::TAG_SIZE; ++i) tag[i] = returned_tag[i];
        }

        case CryptMode.DECRYPT_NO_AUTH:
            must_validate = false;
            nextcase;

        case CryptMode.DECRYPT: {
            //
        }
    }
}



// -----------------------------------------------------------------------------------
// TESTS
import libc;
// import std::io;


fn void test__rfc8439_s2_6_2() @test
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

    assert(c.state != expected_poly1305_key, "ChaCha20 initial state comparison sanity check.");
    assert(c.state == expected_initial_state, "Invalid ChaCha20 initial state.");

    char[chacha20::BLOCK_SIZE] dummy;
    c.xor(dummy[..]);

    assert(c.key_stream != expected_initial_state, "ChaCha20 key_stream comparison sanity check.");
    assert(c.key_stream == expected_poly1305_key, "Invalid ChaCha20 key_stream after single run.");

    // Finally, assert that the local 'gen_key' function follows the same exact behavior.
    char[poly1305::KEY_SIZE] gen_key = poly1305_key_gen(key, nonce);
    // NOTE: memcmp is used here to avoid dancing with different slice types.
    assert(0 == libc::memcmp(&gen_key[0], &expected_poly1305_key[0], poly1305::KEY_SIZE), "`poly1305_key_gen` returned the wrong one-time key.");
}


fn void test__crypt_and_tag__encrypt__rfc8439_s2_8_2() @test
{
    char[] key = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    char[] nonce = { 0x07, 0x00, 0x00, 0x00, '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G' };

    char[] plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."[..^1];
    assert(plaintext.len == 114, "The plaintext's length is not correct.");

    char[] aad = { 'P', 'Q', 'R', 'S', 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

    uint[] expected_gen_key = {
        0x252bac7b, 0xaf47b42d, 0x557ab609, 0x8455e9a4,
        0x73d6e10a, 0xebd97510, 0x7875932a, 0xff53d53e,
        0xdecc7ea2, 0xb44ddbad, 0xe49c17d1, 0xd8430bc9,
        0x8c94b7bc, 0x8b7d4b4b, 0x3927f67d, 0x1669a432,
    };
    char[poly1305::KEY_SIZE] gen_key = poly1305_key_gen(key, nonce);

    char[] ciphertext = ((char*)libc::malloc(plaintext.len))[:plaintext.len];
    defer libc::free(ciphertext.ptr);

    char[] tag = ((char*)libc::malloc(poly1305::TAG_SIZE))[:poly1305::TAG_SIZE];
    defer libc::free(tag.ptr);

    crypt_and_tag(CryptMode.ENCRYPT, ciphertext, tag, plaintext, aad, key, nonce, { .allocate = &libc::malloc, .free = &libc::free })!!;

    char[] expected_ciphertext = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    assert(ciphertext == expected_ciphertext, "Expected ciphertext mismatch.");

    // Briefly check to ensure the 'scratch' buffer is right according to the spec.
    char[] expected_scratch_buffer = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0x00, 0x00, 0x00, 0x00,
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    char[] scratch = make_scratch_buffer(ciphertext, aad, { .allocate = &libc::malloc, .free = &libc::free })!!;

    for (usz i = 0; i < scratch.len; ++i) io::printf("%02x%c", scratch[i], (i+1) % 16 ? ' ' : '\n');
    io::printn("\n\n");

    assert(scratch == expected_scratch_buffer, "Expected scratch buffer (AEAD construct) mismatch.");
    libc::free(scratch.ptr);

    char[] expected_tag = { 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91 };
    assert(tag == expected_tag, "Expected tag value mismatch.");
}

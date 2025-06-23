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
module chacha20_tests @test;

import chacha20;

import libc;
import std::io;


fn void chacha20__encrypt_clone()
{
    // Test values. Note that the key is exactly 256 bits and the IV is exactly 12 bytes.
	char[] key = "this is a test key for chacha20.";
	char[] iv = "1234567890ab";

    // Need to copy this string into a buffer that's R/W. Trying to modify this buffer in-place is a recipe for disaster.
    char[] constant =
        "this is a stream of data which should be encrypted with chacha20."
        " It's not authenticated yet, but it works to hide valuable data cost-effectively.";
    usz buflen = libc::strlen((ZString)constant.ptr);

    char[] data = chacha20::encrypt_clone(constant, key, iv, &libc::malloc)!!;

    // Print out the result of the encryption.
    foreach (z : data) io::printf("%02x", z);
    io::printn("\n");

    assert(data.ptr != constant.ptr, "The cloned buffer's pointer should NOT equal the const buffer's pointer.");
    assert(data.len == buflen, "`chacha20::encrypt_clone` should only encrypt and clone the exact length of the const string buffer (got '%s'; expected '%s').", data.len, buflen);
	assert(0 == libc::memcmp(data, &&(char[*]){ 0x38, 0xFD, 0x77, 0x63, 0x06, 0x79, 0x06, 0xF6, 0x44, 0x50, 0x9F, 0xE8, 0x7F, 0x2E, 0xFC, 0x91, 0x68, 0xA9, 0x23, 0x44, 0xDC, 0x33, 0x72, 0x0F, 0x07, 0x97, 0x18, 0x1B, 0x1B, 0x01, 0xE9, 0x35, 0xB9, 0x0C, 0x23, 0x09, 0x68, 0x18, 0x76, 0x80, 0xF7, 0xB5, 0xE1, 0x49, 0x6B, 0x67, 0x56, 0x55, 0xEE, 0x29, 0x3F, 0x62, 0xF7, 0xCC, 0xEE, 0xAA, 0x4D, 0xC7, 0x10, 0x64, 0x9F, 0xAB, 0x06, 0x6E, 0xF4, 0x89, 0x44, 0xF1, 0x37, 0x9E, 0x03, 0x65, 0xCF, 0x41, 0x32, 0x51, 0x2B, 0x53, 0x7B, 0xBB, 0x04, 0x70, 0x4B, 0x40, 0x8B, 0x82, 0xF9, 0xBF, 0xCE, 0xE5, 0x5E, 0xF0, 0x0C, 0x68, 0x90, 0xA3, 0x54, 0x79, 0xD3, 0xF8, 0x3E, 0x79, 0xB8, 0x27, 0x4A, 0x8E, 0x21, 0x74, 0x7B, 0x77, 0x5C, 0xB5, 0xD8, 0xC2, 0x4A, 0x5A, 0x31, 0x4D, 0xEA, 0x55, 0x20, 0x51, 0x3B, 0x62, 0x24, 0x8E, 0x0F, 0x5E, 0x05, 0xBF, 0xFA, 0x0B, 0xF2, 0x93, 0x0A, 0xAD, 0xAF, 0x56, 0x35, 0x9F, 0x33, 0xAB, 0x01, 0x1F, 0x53, 0x4B }, data.len), "ChaCha20 encryption failed: mismatch on expected ciphertext.");
}

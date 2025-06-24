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
module chacha20;


const BLOCK_SIZE = 64;
const KEY_SIZE = 32;
const IV_SIZE = 12;

const char[] MAGIC = "expand 32-byte k";


struct ChaCha20
{
    uint[16] key_stream;
    usz position;

    char[32] key;
    char[12] nonce;
    ulong counter;

    uint[16] state;
}


faultdef
	OUT_OF_RESOURCES, INVALID_KEY_SIZE, INVALID_IV_SIZE, INVALID_BUFFER_SIZE;


macro uint rot(uint x, int n) @local => (x << n) | (x >> (32 - n));

macro uint pack4(char* a) @local
{
    uint res = 0;
	res |= (uint)a[0] << 0 * 8;
	res |= (uint)a[1] << 1 * 8;
	res |= (uint)a[2] << 2 * 8;
	res |= (uint)a[3] << 3 * 8;
	return res;
}

fn void quarter_round(uint* x, int a, int b, int c, int d) @local @inline
{
    x[a] += x[b]; x[d] = rot(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rot(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rot(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rot(x[b] ^ x[c], 7);
}


fn void ChaCha20.next_block(&self) @local
{
    int i;

    for (i = 0; i < 16; ++i) self.key_stream[i] = self.state[i];

    for (i = 0; i < 10; ++i) 
	{
		quarter_round(&self.key_stream[0],   0,  4,  8, 12);
		quarter_round(&self.key_stream[0],   1,  5,  9, 13);
		quarter_round(&self.key_stream[0],   2,  6, 10, 14);
		quarter_round(&self.key_stream[0],   3,  7, 11, 15);
		quarter_round(&self.key_stream[0],   0,  5, 10, 15);
		quarter_round(&self.key_stream[0],   1,  6, 11, 12);
		quarter_round(&self.key_stream[0],   2,  7,  8, 13);
		quarter_round(&self.key_stream[0],   3,  4,  9, 14);
	}

	for (i = 0; i < 16; ++i) self.key_stream[i] += self.state[i];

	uint* counter = &self.state[12];
	counter[0]++;

	if (!counter[0]) counter[1]++;
}

fn void ChaCha20.init(&self, char[] key, char[] nonce, ulong counter)
{
    // Init block.
    for (int i = 0; i < 32; ++i) self.key[i] = key[i];
    for (int i = 0; i < 12; ++i) self.nonce[i] = nonce[i];

	self.state[0]  = pack4(&MAGIC[0 * 4]);
	self.state[1]  = pack4(&MAGIC[1 * 4]);
	self.state[2]  = pack4(&MAGIC[2 * 4]);
	self.state[3]  = pack4(&MAGIC[3 * 4]);
	self.state[4]  = pack4(&key[0 * 4]);
	self.state[5]  = pack4(&key[1 * 4]);
	self.state[6]  = pack4(&key[2 * 4]);
	self.state[7]  = pack4(&key[3 * 4]);
	self.state[8]  = pack4(&key[4 * 4]);
	self.state[9]  = pack4(&key[5 * 4]);
	self.state[10] = pack4(&key[6 * 4]);
	self.state[11] = pack4(&key[7 * 4]);
	self.state[12] = (uint)counter;
	self.state[13] = pack4(&nonce[0 * 4]) + (uint)(counter >> 32);
	self.state[14] = pack4(&nonce[1 * 4]);
	self.state[15] = pack4(&nonce[2 * 4]);

    self.counter = counter;
    self.position = 64;
}


fn void ChaCha20.xor(&self, char[] data)
{
    char* keystream8 = (char*)(&self.key_stream[0]);
    usz len = data.len;

	for (usz i = 0; i < len; ++i) 
	{
		if (self.position >= 64) 
		{
			self.next_block();
			self.position = 0;
		}
		data[i] ^= keystream8[self.position];
		self.position++;
	}
}


fn void? transform_data(char[] data, char[] key, char[] iv, uint counter) @local
{
	switch {
		case 0 == data.len: return;
		case 12 != iv.len: return INVALID_IV_SIZE?;
		case 32 != key.len: return INVALID_KEY_SIZE?;
	}

	ChaCha20 c @noinit;
	c.init(key, iv, counter);
	c.xor(data);
}

fn void? encrypt_mut(char[] data, char[] key, char[] iv, uint counter = 1) => transform_data(data, key, iv, counter);
fn void? decrypt_mut(char[] data, char[] key, char[] iv, uint counter = 1) => transform_data(data, key, iv, counter);


// Cloning transformed data requires the allocation of a new buffer of equal or greater size. We don't want a STDLIB dependency here.
alias FnHeapAllocate = fn void*(usz);

fn char[]? transform_clone(char[] data, char[] key, char[] iv, FnHeapAllocate allocator_func, uint counter = 1) @local
{
	if (!data.len) return {};

	void* pool = allocator_func(data.len);
	if (null == pool) return OUT_OF_RESOURCES?;

	for (usz i = 0; i < data.len; ++i) ((char*)pool)[i] = data[i];   // poor man's [unoptimized] memcpy
	char[] pool_data = ((char*)pool)[:data.len];

	if (catch err = transform_data(pool_data, key, iv, counter)) return err?;

	return pool_data;
}

fn char[]? encrypt_clone(char[] data, char[] key, char[] iv, FnHeapAllocate allocator_func, uint counter = 1)
	=> transform_clone(data, key, iv, allocator_func, counter);

fn char[]? decrypt_clone(char[] data, char[] key, char[] iv, FnHeapAllocate allocator_func, uint counter = 1)
	=> transform_clone(data, key, iv, allocator_func, counter);


fn void? encrypt_into(char[] data, char[] into, char[] key, char[] iv, uint counter = 1)
{
	if (into.len < data.len) return INVALID_BUFFER_SIZE?;
	for (usz i = 0; i < data.len; ++i) into[i] = data[i];   // poor man's [unoptimized] memcpy

	return transform_data(into, key, iv, counter);
}

fn void? decrypt_into(char[] data, char[] into, char[] key, char[] iv, uint counter = 1)
{
	if (into.len < data.len) return INVALID_BUFFER_SIZE?;
	for (usz i = 0; i < data.len; ++i) into[i] = data[i];   // poor man's [unoptimized] memcpy

	return transform_data(into, key, iv, counter);
}



// -----------------------------------------------------------------------------------
// TESTS
import libc;


fn void chacha20__encrypt_clone() @test
{
    // Test values. Note that the key is exactly 256 bits and the IV is exactly 12 bytes.
	char[] key = "this is a test key for chacha20.";
	char[] iv = "1234567890ab";

    // Need to copy this string into a buffer that's R/W. Trying to modify this buffer in-place is a recipe for disaster.
    char[] constant =
        "this is a stream of data which should be encrypted with chacha20."
        " It's not authenticated yet, but it works to hide valuable data cost-effectively.";

    char[] data = encrypt_clone(constant, key, iv, &libc::malloc)!!;

    assert(data.ptr != constant.ptr, "The cloned buffer's pointer should NOT equal the const buffer's pointer.");
    assert(data.len == constant.len, "`encrypt_clone` should only encrypt and clone the exact length of the const string buffer (got '%s'; expected '%s').", data.len, constant.len);
	assert(data == ((char[*]){ 0x38, 0xFD, 0x77, 0x63, 0x06, 0x79, 0x06, 0xF6, 0x44, 0x50, 0x9F, 0xE8, 0x7F, 0x2E, 0xFC, 0x91, 0x68, 0xA9, 0x23, 0x44, 0xDC, 0x33, 0x72, 0x0F, 0x07, 0x97, 0x18, 0x1B, 0x1B, 0x01, 0xE9, 0x35, 0xB9, 0x0C, 0x23, 0x09, 0x68, 0x18, 0x76, 0x80, 0xF7, 0xB5, 0xE1, 0x49, 0x6B, 0x67, 0x56, 0x55, 0xEE, 0x29, 0x3F, 0x62, 0xF7, 0xCC, 0xEE, 0xAA, 0x4D, 0xC7, 0x10, 0x64, 0x9F, 0xAB, 0x06, 0x6E, 0xF4, 0x89, 0x44, 0xF1, 0x37, 0x9E, 0x03, 0x65, 0xCF, 0x41, 0x32, 0x51, 0x2B, 0x53, 0x7B, 0xBB, 0x04, 0x70, 0x4B, 0x40, 0x8B, 0x82, 0xF9, 0xBF, 0xCE, 0xE5, 0x5E, 0xF0, 0x0C, 0x68, 0x90, 0xA3, 0x54, 0x79, 0xD3, 0xF8, 0x3E, 0x79, 0xB8, 0x27, 0x4A, 0x8E, 0x21, 0x74, 0x7B, 0x77, 0x5C, 0xB5, 0xD8, 0xC2, 0x4A, 0x5A, 0x31, 0x4D, 0xEA, 0x55, 0x20, 0x51, 0x3B, 0x62, 0x24, 0x8E, 0x0F, 0x5E, 0x05, 0xBF, 0xFA, 0x0B, 0xF2, 0x93, 0x0A, 0xAD, 0xAF, 0x56, 0x35, 0x9F, 0x33, 0xAB, 0x01, 0x1F, 0x53, 0x4B })[..], "ChaCha20 encryption failed: mismatch on expected ciphertext.");
}


fn void chacha20__decrypt_mut() @test
{
    // Test values. Note that the key is exactly 256 bits and the IV is exactly 12 bytes.
	char[] key = "this is a test key for chacha20.";
	char[] iv = "1234567890ab";

    char[] constant =
        "this is a stream of data which should be encrypted with chacha20."
        " It's not authenticated yet, but it works to hide valuable data cost-effectively.";

    // This input should decrypt to the expected plaintext above.
    char[] input_enc = { 0x38, 0xFD, 0x77, 0x63, 0x06, 0x79, 0x06, 0xF6, 0x44, 0x50, 0x9F, 0xE8, 0x7F, 0x2E, 0xFC, 0x91, 0x68, 0xA9, 0x23, 0x44, 0xDC, 0x33, 0x72, 0x0F, 0x07, 0x97, 0x18, 0x1B, 0x1B, 0x01, 0xE9, 0x35, 0xB9, 0x0C, 0x23, 0x09, 0x68, 0x18, 0x76, 0x80, 0xF7, 0xB5, 0xE1, 0x49, 0x6B, 0x67, 0x56, 0x55, 0xEE, 0x29, 0x3F, 0x62, 0xF7, 0xCC, 0xEE, 0xAA, 0x4D, 0xC7, 0x10, 0x64, 0x9F, 0xAB, 0x06, 0x6E, 0xF4, 0x89, 0x44, 0xF1, 0x37, 0x9E, 0x03, 0x65, 0xCF, 0x41, 0x32, 0x51, 0x2B, 0x53, 0x7B, 0xBB, 0x04, 0x70, 0x4B, 0x40, 0x8B, 0x82, 0xF9, 0xBF, 0xCE, 0xE5, 0x5E, 0xF0, 0x0C, 0x68, 0x90, 0xA3, 0x54, 0x79, 0xD3, 0xF8, 0x3E, 0x79, 0xB8, 0x27, 0x4A, 0x8E, 0x21, 0x74, 0x7B, 0x77, 0x5C, 0xB5, 0xD8, 0xC2, 0x4A, 0x5A, 0x31, 0x4D, 0xEA, 0x55, 0x20, 0x51, 0x3B, 0x62, 0x24, 0x8E, 0x0F, 0x5E, 0x05, 0xBF, 0xFA, 0x0B, 0xF2, 0x93, 0x0A, 0xAD, 0xAF, 0x56, 0x35, 0x9F, 0x33, 0xAB, 0x01, 0x1F, 0x53, 0x4B };

    decrypt_mut(input_enc, key, iv)!!;
	assert(input_enc == constant, "ChaCha20 decryption failed: mismatch on expected plaintext.");

    // Replaced the first 4 bytes (uint) with 0. This should still decrypt, but must fail.
    char[] bad_input_enc = { 0, 0, 0, 0, 0x06, 0x79, 0x06, 0xF6, 0x44, 0x50, 0x9F, 0xE8, 0x7F, 0x2E, 0xFC, 0x91, 0x68, 0xA9, 0x23, 0x44, 0xDC, 0x33, 0x72, 0x0F, 0x07, 0x97, 0x18, 0x1B, 0x1B, 0x01, 0xE9, 0x35, 0xB9, 0x0C, 0x23, 0x09, 0x68, 0x18, 0x76, 0x80, 0xF7, 0xB5, 0xE1, 0x49, 0x6B, 0x67, 0x56, 0x55, 0xEE, 0x29, 0x3F, 0x62, 0xF7, 0xCC, 0xEE, 0xAA, 0x4D, 0xC7, 0x10, 0x64, 0x9F, 0xAB, 0x06, 0x6E, 0xF4, 0x89, 0x44, 0xF1, 0x37, 0x9E, 0x03, 0x65, 0xCF, 0x41, 0x32, 0x51, 0x2B, 0x53, 0x7B, 0xBB, 0x04, 0x70, 0x4B, 0x40, 0x8B, 0x82, 0xF9, 0xBF, 0xCE, 0xE5, 0x5E, 0xF0, 0x0C, 0x68, 0x90, 0xA3, 0x54, 0x79, 0xD3, 0xF8, 0x3E, 0x79, 0xB8, 0x27, 0x4A, 0x8E, 0x21, 0x74, 0x7B, 0x77, 0x5C, 0xB5, 0xD8, 0xC2, 0x4A, 0x5A, 0x31, 0x4D, 0xEA, 0x55, 0x20, 0x51, 0x3B, 0x62, 0x24, 0x8E, 0x0F, 0x5E, 0x05, 0xBF, 0xFA, 0x0B, 0xF2, 0x93, 0x0A, 0xAD, 0xAF, 0x56, 0x35, 0x9F, 0x33, 0xAB, 0x01, 0x1F, 0x53, 0x4B };

    decrypt_mut(bad_input_enc, key, iv)!!;
    assert(bad_input_enc != constant, "ChaCha20 decryption succeeded when it should not have.");
}

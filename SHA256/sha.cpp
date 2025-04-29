#include "sha.h"

#include <array>
#include <fstream>
#include <sstream>

namespace sha {
	namespace constants {
		// Initial hash values
		std::array<uint32_t, 8> H = {
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19
		};

		// K constants
		std::array<uint32_t, 64> K = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};
	}
}

void sha::rightrotate(uint32_t &value, uint8_t shift, uint32_t &target) {
	uint32_t looped = (value & ((1 << shift) - 1)) << (32 - shift);
	uint32_t otherPart = value >> shift;
	target = looped + otherPart;
}

void sha::readFromFile(std::ifstream& file, std::string& outputString) {
	// Use a stringstream to read string directly
	std::stringstream buffer;
	buffer << file.rdbuf();
	outputString = buffer.str();
}

void sha::sha256(std::string &input, std::string &result) {
	// Clear result
	result.clear();

	// Convert input into bits
	std::vector<uint8_t> inputData;
	sha::convertStringToBytes(input, inputData);

	// Run SHA-256 Algorithm
	std::array<uint32_t, 8> wordResult;
	sha::sha256Bytes(inputData, wordResult);

	// Convert result into hex
	sha::convertWordsToString(wordResult, result);
}

void sha::convertStringToBytes(std::string &inputString, std::vector<uint8_t> &bytes) {
	// Allocate memory to bytes
	size_t stringSize = inputString.size();
	bytes.resize(stringSize);

	// Copy data from string to vector
	std::copy(inputString.begin(), inputString.end(), bytes.begin());
}

void sha::convertWordsToString(std::array<uint32_t, 8> &words, std::string &result) {
	// Allocate space first
	result.reserve(64);

	for (size_t i = 0; i < 8; i++) {
		// Use a c-string as a buffer
		char buffer[9];
		std::sprintf(buffer, "%08x", words[i]);
		result.append(buffer);
	}
}

void sha::sha256Bytes(std::vector<uint8_t> &inputBytes, std::array<uint32_t, 8> &result) {
	// First step: Add padding and preprocess the data

	// Get the size of the input
	size_t inputBytesSize = inputBytes.size();
	size_t inputBytesSizeBits = inputBytesSize << 3;

	// Get the current size of the message, in bits
	size_t currentMessageSize = (inputBytesSize << 3) + 65;

	// Get the number of padding '0's and total size
	size_t padding0s = 512 - currentMessageSize & 0x1ff;
	size_t messageSize = (currentMessageSize + padding0s) >> 3;

	// Reallocate the memory of the message
	inputBytes.resize(messageSize);

	// Add the extra '1' and size bytes to the message
	inputBytes[inputBytesSize] = 0x80;
	for (size_t i = 0; i < 8; i++) {
		inputBytes[messageSize - 8 + i] = (inputBytesSizeBits >> (56 - 8 * i)) & 0xff;
	}

	// Second step: Prepare the blocks and pass it to the expander

	// Get number of blocks in the message
	size_t numBlocks = messageSize >> 6;
	size_t currentPosition = 0;
	
	// Prepare message schedule array
	std::array<uint32_t, 64> messageSchedule{};

	// Initialise hash values
	result = sha::constants::H;

	for (size_t i = 0; i < numBlocks; i++) {
		// Third step: Expander
		currentPosition = i << 6;
		sha::expander(inputBytes, currentPosition, messageSchedule);

		// Fourth step: Compressor
		sha::compressor(messageSchedule, result);
	}
}

void sha::expander(std::vector<uint8_t> &inputBytes, size_t &startPosition, std::array<uint32_t, 64> &messageSchedule) {
	// Copy the 16 words from inputBytes into messageSchedule
	for (size_t i = 0; i < 16; ++i) {
		messageSchedule[i] =
			(static_cast<uint32_t>(inputBytes[startPosition + 4 * i]) << 24) |
			(static_cast<uint32_t>(inputBytes[startPosition + 4 * i + 1]) << 16) |
			(static_cast<uint32_t>(inputBytes[startPosition + 4 * i + 2]) << 8) |
			(static_cast<uint32_t>(inputBytes[startPosition + 4 * i + 3]) << 0);
	}

	// Run the singular expander operation 48 times on the rest of the message schedule
	for (size_t i = 16; i < 64; i++) {
		uint32_t w0 = messageSchedule[i - 16];
		uint32_t w1 = messageSchedule[i - 15];
		uint32_t w9 = messageSchedule[i - 7];
		uint32_t w14 = messageSchedule[i - 2];

		uint32_t r0, r1;
		sha::rightrotate(w1, 7, r0);
		sha::rightrotate(w1, 18, r1);
		uint32_t r2 = w1 >> 3;

		uint32_t s0 = r0 ^ r1 ^ r2;

		uint32_t r3, r4;
		sha::rightrotate(w14, 17, r3);
		sha::rightrotate(w14, 19, r4);
		uint32_t r5 = w14 >> 10;

		uint32_t s1 = r3 ^ r4 ^ r5;

		messageSchedule[i] = w0 + s0 + w9 + s1;
	}
}

void sha::compressor(std::array<uint32_t, 64> &messageSchedule, std::array<uint32_t, 8> &hashValues) {
	// Initialise working values
	uint32_t a = hashValues[0];
	uint32_t b = hashValues[1];
	uint32_t c = hashValues[2];
	uint32_t d = hashValues[3];
	uint32_t e = hashValues[4];
	uint32_t f = hashValues[5];
	uint32_t g = hashValues[6];
	uint32_t h = hashValues[7];

	// Run the singular compressor operation 64 times on the entire message schedule
	for (size_t i = 0; i < 64; i++) {
		uint32_t k0 = sha::constants::K[i];
		uint32_t w0 = messageSchedule[i];

		uint32_t choice = (e & f) ^ (~e & g);
		uint32_t majority = (a & b) ^ (a & c) ^ (b & c);

		uint32_t r0, r1, r2;
		sha::rightrotate(e, 6, r0);
		sha::rightrotate(e, 11, r1);
		sha::rightrotate(e, 25, r2);

		uint32_t s1 = r0 ^ r1 ^ r2;

		uint32_t r3, r4, r5;
		sha::rightrotate(a, 2, r3);
		sha::rightrotate(a, 13, r4);
		sha::rightrotate(a, 22, r5);

		uint32_t s0 = r3 ^ r4 ^ r5;

		uint32_t temp1 = h + s1 + choice + k0 + w0;
		uint32_t temp2 = s0 + majority;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	// Add the working values to the hash values
	hashValues[0] += a;
	hashValues[1] += b;
	hashValues[2] += c;
	hashValues[3] += d;
	hashValues[4] += e;
	hashValues[5] += f;
	hashValues[6] += g;
	hashValues[7] += h;
}
#include "sha.h"

void sha::rightrotate(uint32_t &value, uint8_t shift, uint32_t &target) {
	uint32_t looped = (value & (1 << shift - 1)) << (32 - shift);
	uint32_t otherPart = value >> shift;
	target = looped + otherPart;
}

void sha::sha256(std::vector<uint8_t> &inputBytes, std::array<uint32_t, 8> &result) {
	// First step: Add padding and preprocess the data

	// Get the size of the input
	size_t inputBytesSize = inputBytes.size();
	size_t inputBytesSizeBits = inputBytesSize << 3;

	// Get the current size of the message, in bits
	size_t currentMessageSize = (inputBytesSize << 3) + 65;

	// Get the number of padding '0's and total size
	size_t padding0s = 512 - currentMessageSize & 511;
	size_t messageSize = (currentMessageSize + padding0s) >> 3;

	// Reallocate the memory of the message
	inputBytes.resize(messageSize);

	// Add the extra '1' and size bytes to the message
	inputBytes[inputBytesSize] = 1;
	std::memcpy(inputBytes.data() + messageSize - 8, &inputBytesSizeBits, sizeof(inputBytesSizeBits));

	// Second step: Prepare the blocks and pass it to the expander

	// Get number of blocks in the message
	size_t numBlocks = messageSize >> 6;
	size_t currentPosition = 0;
	
	// Prepare message schedule array
	std::vector<uint32_t> messageSchedule(64);

	for (size_t i = 0; i < numBlocks; i++) {
		// Third step: expander
		currentPosition = i << 6;
		sha::expander(inputBytes, currentPosition, messageSchedule);
	}
}

void sha::expander(std::vector<uint8_t> &inputBytes, size_t &startPosition, std::vector<uint32_t> &messageSchedule) {
	// Copy the 16 words from inputBytes into messageSchedule
	std::memcpy(&messageSchedule[0], &inputBytes[startPosition], 64);

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
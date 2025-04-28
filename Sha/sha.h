#ifndef SHA_H
#define SHA_H

#include <vector>

namespace sha {
	// Rightrotate function
	void rightrotate(uint32_t &value, uint8_t shift, uint32_t &target);

	// Runs the SHA-256 algorithm
	void sha256(std::vector<uint8_t> &inputBytes, std::array<uint32_t, 8> &result);

	// Expander
	void expander(std::vector<uint8_t> &inputBytes, size_t &startPosition, std::vector<uint32_t> &messageSchedule);
}

#endif
#ifndef SHA_H
#define SHA_H

#include <array>
#include <fstream>
#include <string>
#include <vector>

namespace sha {
	// Rightrotate function
	void rightrotate(uint32_t &value, uint8_t shift, uint32_t &target);

	// Extracts entire file contents
	void readFromFile(std::ifstream &file, std::string &outputString);

	// Runs the SHA-256 alrogithm, taking in a string of length up to 2^64 and calculating the resulting hash
	void sha256(std::string &input, std::string &result);

	// Converts a string into a std::vector<uint8_t> for further processing.
	void convertStringToBytes(std::string &inputString, std::vector<uint8_t> &bytes);

	// Converts the final 8 hashes into a hex code.
	void convertWordsToString(std::array<uint32_t, 8> &words, std::string &result);

	// Runs the SHA-256 algorithm on bytes
	void sha256Bytes(std::vector<uint8_t> &inputBytes, std::array<uint32_t, 8> &result);

	// Expander
	void expander(std::vector<uint8_t> &inputBytes, size_t &startPosition, std::array<uint32_t, 64> &messageSchedule);

	// Compressor
	void compressor(std::array<uint32_t, 64> &messageSchedule, std::array<uint32_t, 8> &hashValues);
}

#endif
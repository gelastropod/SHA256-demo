#include "sha.h"

#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#include <algorithm>
#include <array>

namespace sha {
	// Extracts entire file contents
	void readFromFile(std::ifstream &file, std::string &outputString) {
		// Use a stringstream to read string directly
		std::stringstream buffer;
		buffer << file.rdbuf();
		outputString = buffer.str();
	}

	// Converts a string into a std::vector<uint8_t> for further processing.
	void convertStringToBytes(std::string &inputString, std::vector<uint8_t> &bytes) {
		// Allocate memory to bytes
		size_t stringSize = inputString.size();
		bytes.resize(stringSize);

		// Copy data from string to vector
		std::copy(inputString.begin(), inputString.end(), bytes.begin());
	}

	// Converts the final 8 hashes into a hex code.
	void convertWordsToString(std::array<uint32_t, 8> &words, std::string &result) {
		// Allocate space first
		result.reserve(64);

		for (size_t i = 0; i < 8; i++) {
			// Use a c-string as a buffer
			char buffer[9];
			std::sprintf(buffer, "%08x", words[i]);
			result.append(buffer);
		}
	}
}

int main(int argc, char* argv[]) {
	// Prepare input
	if (argc != 3) {
		std::cerr << "Invalid number of arguments!\n"
			"Correct usage: Sha.exe [input file] [output file]" << std::endl;
		return -1;
	}

	std::ifstream infile(argv[1]);
	std::ofstream outfile(argv[2]);

	if (!infile.is_open()) {
		std::cerr << "Error opening input file." << std::endl;
		return -2;
	}

	if (!outfile.is_open()) {
		std::cerr << "Error opening output file." << std::endl;
		return -3;
	}

	// Extract input data as string
	std::string rawData;
	sha::readFromFile(infile, rawData);

	// Convert input into bits
	std::vector<uint8_t> inputData;
	sha::convertStringToBytes(rawData, inputData);

	// Run SHA-256 Algorithm
	std::array<uint32_t, 8> wordResult;
	sha::sha256(inputData, wordResult);

	// Convert result into hex
	std::string result;
	sha::convertWordsToString(wordResult, result);

	// Write hex to output file
	outfile << result << std::endl;
	outfile.close();

	return 0;
}
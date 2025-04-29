#include "sha.h"

#include <fstream>
#include <iostream>
#include <string>

// Checks if a string is blank or not
bool isBlank(std::string input) {
	bool result = true;

	for (char i : input) {
		if (!isblank(i)) {
			result = false;
		}
	}
	
	return result;
}

int main(int argc, char* argv[]) {
	// Interactive mode
	if (argc == 1) {
		std::string input = ".", output;

		while (true) {
			std::getline(std::cin, input);

			if (isBlank(input)) break;

			sha::sha256(input, output);

			std::cout << output << std::endl;
		}

		return 0;
	}

	if (argc == 2) {
		std::string input = argv[1];
		std::string output;

		sha::sha256(input, output);
		
		std::cout << output << std::endl;

		return 0;
	}

	// Prepare input
	if (argc != 3) {
		std::cerr << "Invalid number of arguments!\n"
			"Correct usage: SHA256.exe [input file] [output file]" << std::endl;
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

	// Run the SHA-256 algorithm
	std::string result;
	sha::sha256(rawData, result);

	// Write hex to output file
	outfile << result << std::endl;
	outfile.close();

	return 0;
}
#ifndef CRACKER_H
#define CRACKER_H

#include <string>
#include <vector>

std::vector<std::string> generate_mutations(const std::string& word);

std::vector<std::string> load_wordlist();

std::vector<std::string> generate_suffixes();

std::string crack_password(const std::string& target_hash, const std::string& hash_type);

#endif // CRACKER_H

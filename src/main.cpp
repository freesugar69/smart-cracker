#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "cracker.h"

std::string compute_md5(const std::string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, input.c_str(), input.size());
    MD5_Final(digest, &ctx);
    char mdString[33];
    for (int i = 0; i < 16; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    return std::string(mdString);
}

std::string compute_sha1(const std::string& input) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, input.c_str(), input.size());
    SHA1_Final(digest, &ctx);
    char shaString[41];
    for (int i = 0; i < 20; i++)
        sprintf(&shaString[i*2], "%02x", (unsigned int)digest[i]);
    return std::string(shaString);
}

std::vector<std::string> generate_mutations(const std::string& word) {
    std::vector<std::string> mutations;
    mutations.push_back(word);

    // Variazioni di caso
    std::string upper = word;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    mutations.push_back(upper);

    std::string lower = word;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    mutations.push_back(lower);

    // Leet speak semplice
    std::string leet = word;
    for (char& c : leet) {
        if (c == 'a' || c == 'A') c = '4';
        else if (c == 'e' || c == 'E') c = '3';
        else if (c == 'i' || c == 'I') c = '1';
        else if (c == 'o' || c == 'O') c = '0';
        else if (c == 's' || c == 'S') c = '5';
        else if (c == 't' || c == 'T') c = '7';
    }
    mutations.push_back(leet);

    // Combinazioni (es. Pr0MpT)
    std::string mixed = word;
    for (size_t i = 0; i < mixed.size(); ++i) {
        if (i % 2 == 0) mixed[i] = ::toupper(mixed[i]);
        else mixed[i] = ::tolower(mixed[i]);
    }
    mutations.push_back(mixed);

    return mutations;
}

std::vector<std::string> load_wordlist() {
    // Lista breve built-in (aggiungi più parole se necessario)
    return {
        "prompt", "prisma", "primordiale", "primavera", "primo", "prato",
        "predator", "predatore", "preda", "tor", "toro", "torta",
        "password", "admin", "root", "user", "test", "ciao", "hello"
    };
}

std::vector<std::string> generate_suffixes() {
    // Suffissi comuni (numeri, simboli)
    return {
        ".123", ".369", "/*-+", ".abc", ".xyz", "123", "369", "/*-+",
        "!@#", "$%^", "&*()", "qwerty", "asdf", "zxcv"
    };
}

std::string crack_password(const std::string& target_hash, const std::string& hash_type) {
    auto wordlist = load_wordlist();
    auto suffixes = generate_suffixes();

    // Caratteri per brute-force iniziale
    std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-/*";

    // Fase 1: Brute-force per prefissi brevi (lunghezza 1-3)
    for (size_t len = 1; len <= 3; ++len) {
        std::string prefix(len, ' ');
        for (size_t i = 0; i < chars.size(); ++i) {
            prefix[0] = chars[i];
            if (len > 1) {
                for (size_t j = 0; j < chars.size(); ++j) {
                    prefix[1] = chars[j];
                    if (len > 2) {
                        for (size_t k = 0; k < chars.size(); ++k) {
                            prefix[2] = chars[k];
                            // Controlla se il prefisso matcha inizio di parole in wordlist
                            for (const auto& word : wordlist) {
                                if (word.substr(0, len) == prefix) {
                                    // Genera mutazioni della parola completa
                                    auto mutations = generate_mutations(word);
                                    for (const auto& mut : mutations) {
                                        // Aggiungi suffissi
                                        for (const auto& suff : suffixes) {
                                            std::string candidate = mut + suff;
                                            std::string hash;
                                            if (hash_type == "md5") hash = compute_md5(candidate);
                                            else if (hash_type == "sha1") hash = compute_sha1(candidate);
                                            if (hash == target_hash) return candidate;
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // Stesso per len=2
                        for (const auto& word : wordlist) {
                            if (word.substr(0, len) == prefix) {
                                auto mutations = generate_mutations(word);
                                for (const auto& mut : mutations) {
                                    for (const auto& suff : suffixes) {
                                        std::string candidate = mut + suff;
                                        std::string hash = (hash_type == "md5") ? compute_md5(candidate) : compute_sha1(candidate);
                                        if (hash == target_hash) return candidate;
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // Stesso per len=1
                for (const auto& word : wordlist) {
                    if (word.substr(0, len) == prefix) {
                        auto mutations = generate_mutations(word);
                        for (const auto& mut : mutations) {
                            for (const auto& suff : suffixes) {
                                std::string candidate = mut + suff;
                                std::string hash = (hash_type == "md5") ? compute_md5(candidate) : compute_sha1(candidate);
                                if (hash == target_hash) return candidate;
                            }
                        }
                    }
                }
            }
        }
    }

    return "Password non trovata";
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Uso: smartcracker <hash_target> <tipo_hash (md5|sha1)>" << std::endl;
        return 1;
    }

    std::string target_hash = argv[1];
    std::string hash_type = argv[2];

    std::cout << "Crackando password..." << std::endl;
    std::string result = crack_password(target_hash, hash_type);
    std::cout << "Risultato: " << result << std::endl;

    return 0;
}

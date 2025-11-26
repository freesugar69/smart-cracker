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

std::string to_lower(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower;
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

    // Title case (prima lettera maiuscola, resto minuscolo)
    std::string title = word;
    if (!title.empty()) {
        title[0] = ::toupper(title[0]);
        for (size_t i = 1; i < title.size(); ++i) {
            title[i] = ::tolower(title[i]);
        }
    }
    mutations.push_back(title);

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
    // Lista built-in strutturata per prefissi (2-6 chars, poi 4-8 chars), numeriche, alfanumeriche
    return {
        // Prefissi "ab" (2-6 chars)
        "abete", "abito", "ab1t0", "Ab3t3", "abaco", "abate", "abuso", "abito", "abate", "abaco",
        // Prefissi "ac" (2-6 chars)
        "acro", "AC3t0", "Ac3", "Ace", "Acr0", "acido", "acqua", "acero", "acuto", "acqua",
        // Prefissi "ad" (2-6 chars)
        "adito", "Ad1t0", "Ad3", "Ade", "Adr0", "adobe", "adagio", "adore", "adobe", "adagio",
        // Prefissi "ae" (2-6 chars)
        "aereo", "A3r30", "A3r", "Aer", "A3r0", "aereo", "aereo", "aereo", "aereo", "aereo",
        // Prefissi "af" (2-6 chars)
        "afido", "Af1d0", "Af3", "Afe", "Afr0", "afido", "afido", "afido", "afido", "afido",
        // Prefissi "pr" (2-6 chars, per predator)
        "predator", "primo", "prato", "prisma", "primavera", "prompt", "principe", "pratica", "pronto", "principe",
        // Parole 4-8 chars per "ab"
        "abete", "abito", "abaco", "abate", "abuso", "abisso", "aborto", "abbono", "abbono", "abbono",
        // Parole 4-8 chars per "ac"
        "acido", "acqua", "acero", "acuto", "acacia", "accusa", "accusa", "accusa", "accusa", "accusa",
        // Parole 4-8 chars per "ad"
        "adobe", "adagio", "adore", "adesso", "adesso", "adesso", "adesso", "adesso", "adesso",
        // Parole 4-8 chars per "ae"
        "aereo", "aereo", "aereo", "aereo", "aereo", "aereo", "aereo", "aereo", "aereo",
        // Parole 4-8 chars per "af"
        "afido", "afido", "afido", "afido", "afido", "afido", "afido", "afido", "afido",
        // Parole 4-8 chars per "pr"
        "predator", "predatore", "preda", "principe", "pratica", "pronto", "principe", "principe", "principe", "principe",
        // Numeriche 1-3 cifre
        "123", "456", "789", "369", "258", "147", "000", "111", "222", "333",
        // Numeriche 4 cifre (giorno/mese)
        "0112", "0825", "0309", "1225", "0101", "1231", "0606", "0707", "0808", "0909",
        // Numeriche 6 cifre (giorno/mese/anno attuale, es. 030925 per 03/09/2025)
        "030925", "082525", "122525", "010125", "060625", "070725", "080825", "090925", "101025", "111125",
        // Alfanumeriche con simboli 1-4 chars
        "/*-+.", ":;,", "/*-+.:;", "369/*-+.", "123.:;", "abc/*-+.", "xyz.:;", "qwerty/*-+.", "asdf.:;", "zxcv.:;"
    };
}

std::vector<std::string> generate_suffixes() {
    // Suffissi comuni (numeri, simboli)
    return {
        ".123", ".369", "/*-+", ".abc", ".xyz", "123", "369", "/*-+",
        "!@#", "$%^", "&*()", "qwerty", "asdf", "zxcv", ".369/*-+"
    };
}

std::string crack_password(const std::string& target_hash, const std::string& hash_type) {
    auto wordlist = load_wordlist();
    auto suffixes = generate_suffixes();

    // Caratteri per brute-force iniziale
    std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-/*.,:;";

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
                            // Controlla se il prefisso matcha inizio di parole in wordlist (case-insensitive)
                            for (const auto& word : wordlist) {
                                if (to_lower(word).substr(0, len) == to_lower(prefix)) {
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
                            if (to_lower(word).substr(0, len) == to_lower(prefix)) {
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
                    if (to_lower(word).substr(0, len) == to_lower(prefix)) {
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

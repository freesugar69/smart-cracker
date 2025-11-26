# SmartCracker - Intelligent Password Cracking Tool

SmartCracker is a simple and effective password cracking tool based on a hybrid dictionary + brute-force algorithm with mutations. It is designed for ethical hacking on Kali Linux, inspired by tools like Hashcat but with a "guided" approach for semi-predictable passwords.

## Features
- **Intelligent Algorithm**: Starts with brute-force on short prefixes, expands with wordlist, applies mutations (leet speak, case variations) and adds common suffixes.
- **Hash Support**: MD5 and SHA1 (easily extensible to SHA256).
- **Built-in Wordlist**: Common English/Italian words + numeric/symbol patterns.
- **Easy Installation**: Uses CMake for build and installation.
- **Ethical Use**: Only for authorized security testing.

## Installation
### Prerequisites
- Kali Linux (or Debian-based).
- CMake (>= 3.10).
- OpenSSL (already installed on Kali: `sudo apt install libssl-dev` if needed).

### Build and Installation
```bash
# Clone or download the project
cd smart-cracker

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Compile
make

# Install globally (requires sudo)
sudo make install
```

The tool will be available as `smartcracker` in the PATH.

## Usage
```bash
smartcracker <target_hash> <hash_type>
```
- `<target_hash>`: The hash to crack (e.g., "5d41402abc4b2a76b9719d911017c592").
- `<hash_type>`: "md5" or "sha1".

### Examples
```bash
# Crack an MD5 hash
smartcracker "0a2ac58b8bb1939d0618217673a2edc7" md5
# Output: Result: predator.369

# Crack a SHA1 hash
smartcracker "da39a3ee5e6b4b0d3255bfef95601890afd80709" sha1
```

## Algorithm Details
1. **Initial Brute-force**: Tries prefixes of 1-3 characters (a-zA-Z0-9+-/*.,:;).
2. **Wordlist Expansion**: If the prefix matches the start of a word (case-insensitive, e.g., "Pr" -> "predator"), generates mutations. Wordlist is structured by prefixes (e.g., ab, ac, ad, ae, af, pr) with 2-6 chars and 4-8 chars words, numeric lists (1-3, 4, 6 digits), alfanumeric with symbols.
3. **Mutations**: Case variations (upper, lower, title, alternating), leet speak (e->3, o->0, i->1, etc.).
4. **Suffixes**: Adds common patterns (e.g., ".369", "/*-+", ".369/*-+").
5. **Verification**: Computes hash of candidate and compares. Alternates brute-force with wordlist for incremental building.

## Customization
- **Add Words**: Modify `load_wordlist()` in `src/main.cpp`.
- **Extra Suffixes**: Modify `generate_suffixes()`.
- **External Wordlist File**: Extend to read from file (e.g., rockyou.txt).

## License
GPL-3.0 - Open-source for ethical hacking community.

## Contributions
Fork on GitHub, pull requests welcome. Test on real hashes ethically.

## Disclaimer
Use only for authorized penetration testing. Not responsible for illegal uses.

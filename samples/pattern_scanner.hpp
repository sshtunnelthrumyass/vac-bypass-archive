#pragma once
// pattern_scanner.hpp - IDA-style byte pattern scanner
// Research/analysis tool for locating byte sequences in memory dumps.
// Not a cheat component. Used for building detection signatures.

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <span>
#include <sstream>

namespace sig {

struct PatternByte {
    uint8_t value;
    bool wildcard;  // true = match any byte (IDA's '?' notation)
};

// Parse an IDA-style signature string: "48 8B 05 ?? ?? ?? ?? 48 85 C0"
inline std::vector<PatternByte> Parse(const std::string& sig) {
    std::vector<PatternByte> pattern;
    std::istringstream stream(sig);
    std::string token;

    while (stream >> token) {
        if (token == "?" || token == "??") {
            pattern.push_back({0, true});
        } else {
            pattern.push_back({
                static_cast<uint8_t>(std::stoul(token, nullptr, 16)),
                false
            });
        }
    }
    return pattern;
}

// Scan a memory region for the first occurrence of a pattern.
// Returns offset from region start, or nullopt if not found.
inline std::optional<size_t> FindFirst(
    std::span<const uint8_t> region,
    const std::vector<PatternByte>& pattern)
{
    if (pattern.empty() || region.size() < pattern.size()) return std::nullopt;

    const size_t scanEnd = region.size() - pattern.size();

    for (size_t i = 0; i <= scanEnd; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].wildcard && region[i + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return std::nullopt;
}

// Find all occurrences
inline std::vector<size_t> FindAll(
    std::span<const uint8_t> region,
    const std::vector<PatternByte>& pattern)
{
    std::vector<size_t> results;
    if (pattern.empty() || region.size() < pattern.size()) return results;

    const size_t scanEnd = region.size() - pattern.size();

    for (size_t i = 0; i <= scanEnd; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].wildcard && region[i + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match) results.push_back(i);
    }
    return results;
}

// Resolve a RIP-relative address at a pattern match site.
// offset: byte offset within the pattern where the 4-byte RIP displacement starts
// instrLen: total length of the instruction containing the displacement
inline uintptr_t ResolveRip(uintptr_t matchAddr, size_t offset, size_t instrLen,
                             std::span<const uint8_t> region, size_t matchOffset) {
    int32_t displacement;
    std::memcpy(&displacement, &region[matchOffset + offset], sizeof(int32_t));
    return matchAddr + instrLen + displacement;
}

} // namespace sig
```

#pragma once
#include <bls12-381/bls12-381.hpp>

namespace bls12_381_groth16 {
    bool deserializeG1FromVector(bls12_381::g1 *out, const std::vector<const unsigned char> *v, size_t startIndex);
    bool deserializeG2FromVector(bls12_381::g1 *out, const std::vector<const unsigned char> *v, size_t startIndex);
    bool deserializeFpFromVector(bls12_381::fp *out, const std::vector<const unsigned char> *v, size_t startIndex);
    bool deserializeScalarFromVector(const std::array<uint64_t, 4> &out, const std::vector<const unsigned char> *v, size_t startIndex);
}
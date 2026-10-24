#pragma once
#include <cstddef>
#include <cstdint>
#ifdef __CUDACC__
#define BAM_HD __host__ __device__
#else
#define BAM_HD
#endif
namespace bam {
// CQE has no opcode: validate tracked SQ command opcode, then CID/SQID/phase/status.
BAM_HD inline unsigned completion(uint16_t cid, uint16_t observed_cid,
    uint8_t submitted_opcode, uint8_t expected_opcode, uint16_t sqid,
    uint16_t expected_sqid, uint16_t status_with_phase) {
    if (cid != observed_cid || submitted_opcode != expected_opcode || sqid != expected_sqid)
        return 1;
    if ((status_with_phase & 1) == 0 || (status_with_phase >> 1) != 0) return 2;
    return 0;
}
inline bool verify(const unsigned char* expected, size_t n,
    const unsigned char* actual, size_t actual_n, const unsigned char* prefix,
    size_t prefix_n, const unsigned char* suffix, size_t suffix_n) {
    if (n != actual_n || prefix_n != 32 || suffix_n != 32) return false;
    for (size_t i=0;i<32;++i) if(prefix[i]!=0xa5 || suffix[i]!=0xa5) return false;
    for (size_t i=0;i<n;++i) if(expected[i]!=actual[i]) return false;
    return true;
}
}
#undef BAM_HD

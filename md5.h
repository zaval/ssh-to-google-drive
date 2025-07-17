#ifndef MD5_H
#define MD5_H
#include <string>
#include <openssl/types.h>


/**
 * @class MD5
 * @brief This class implements the MD5 hashing algorithm.
 *
 * The MD5 class provides functionality to compute MD5 hash values.
 * MD5 is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value,
 * commonly expressed as a 32-character hexadecimal number.
 *
 * It is commonly used to verify data integrity but is not recommended for cryptographic security purposes
 * due to vulnerabilities.
 */
class MD5 {
public:
    MD5();
    bool update(const char *data, const size_t &size) const;

    [[nodiscard]] std::string hexdigest() const;


private:
    EVP_MD_CTX* md_context;
};



#endif //MD5_H

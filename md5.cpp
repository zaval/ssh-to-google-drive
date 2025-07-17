#include "md5.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <openssl/evp.h>
#include <vector>

#include "spdlog/spdlog.h"

MD5::MD5() {
    md_context = EVP_MD_CTX_new();
    if (md_context == nullptr) {
        spdlog::error("Error: EVP_MD_CTX_new() failed.");
        // std::cerr << "Error: EVP_MD_CTX_new() failed." << std::endl;
        return;
    }
    if (EVP_DigestInit_ex(md_context, EVP_md5(), nullptr) != 1) {
        spdlog::error("Error: EVP_DigestInit_ex() failed.");
        // std::cerr << "Error: EVP_DigestInit_ex() failed." << std::endl;
        EVP_MD_CTX_free(md_context);
        return;
    }
}

bool MD5::update(const char *data, const size_t &size) const {
    if (EVP_DigestUpdate(md_context, data, size) != 1) {
        spdlog::error("Error: EVP_DigestUpdate() failed.");
        // std::cerr << "Error: EVP_DigestUpdate() failed." << std::endl;
        EVP_MD_CTX_free(md_context);
        return false;
    }
    return true;
}

std::string MD5::hexdigest() const {
    std::vector<unsigned char> hash_result(EVP_MD_size(EVP_md5()));
    unsigned int hash_length = 0;
    if (EVP_DigestFinal_ex(md_context, hash_result.data(), &hash_length) != 1) {
        spdlog::error("Error: EVP_DigestFinal_ex() failed.");
        // std::cerr << "Error: EVP_DigestFinal_ex() failed." << std::endl;
        EVP_MD_CTX_free(md_context);
        return "";
    }

    EVP_MD_CTX_free(md_context);
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_length; ++i) {
        ss << std::setw(2) << static_cast<int>(hash_result[i]);
    }

    return ss.str();
}

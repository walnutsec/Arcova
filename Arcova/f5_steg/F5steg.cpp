// F5steg.cpp (VERSI FINAL YANG SUDAH DIPERBAIKI)

#include "F5steg.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <thread>
#include <mutex>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

Logger::Logger(const std::string& filename) {
    log_file_.open(filename, std::ios::app);
    if (!log_file_.is_open()) {
        throw std::runtime_error("Cannot open log file: " + filename);
    }
}

Logger::~Logger() {
    if (log_file_.is_open()) log_file_.close();
}

void Logger::log(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    log_file_ << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
              << " [" << level << "] " << message << std::endl;
}

JpegHandler::JpegHandler() : coeff_arrays_(nullptr), width_(0), height_(0), comps_(0), data_precision_(0) {
    srcinfo_.err = jpeg_std_error(&jerr_);
    dstinfo_.err = jpeg_std_error(&jerr_);
    jpeg_create_decompress(&srcinfo_);
    jpeg_create_compress(&dstinfo_);
}

JpegHandler::~JpegHandler() {
    jpeg_destroy_decompress(&srcinfo_);
    jpeg_destroy_compress(&dstinfo_);
}

void JpegHandler::load(const std::string& filename, Logger& logger) {
    FILE* infile = fopen(filename.c_str(), "rb");
    if (!infile) {
        logger.log("ERROR", "Cannot open input JPEG: " + filename);
        throw std::runtime_error("Cannot open input JPEG: " + filename);
    }
    jpeg_stdio_src(&srcinfo_, infile);
    jpeg_read_header(&srcinfo_, TRUE);
    width_ = srcinfo_.image_width;
    height_ = srcinfo_.image_height;
    comps_ = srcinfo_.num_components;
    data_precision_ = srcinfo_.data_precision;
    coeff_arrays_ = jpeg_read_coefficients(&srcinfo_);
    fclose(infile);
    logger.log("INFO", "Loaded JPEG: " + filename + " (" + std::to_string(width_) + "x" + std::to_string(height_) + ")");
}

void JpegHandler::save(const std::string& filename, int quality, Logger& logger) {
    FILE* outfile = fopen(filename.c_str(), "wb");
    if (!outfile) {
        logger.log("ERROR", "Cannot open output JPEG: " + filename);
        throw std::runtime_error("Cannot open output JPEG: " + filename);
    }
    jpeg_stdio_dest(&dstinfo_, outfile);
    jpeg_copy_critical_parameters(&srcinfo_, &dstinfo_);
    dstinfo_.optimize_coding = TRUE;
    jpeg_set_quality(&dstinfo_, quality, TRUE);
    jpeg_write_coefficients(&dstinfo_, coeff_arrays_);
    jpeg_finish_compress(&dstinfo_);
    fclose(outfile);
    logger.log("INFO", "Saved JPEG: " + filename);
}

jvirt_barray_ptr* JpegHandler::get_coeff_arrays() const { return coeff_arrays_; }
jpeg_decompress_struct& JpegHandler::get_srcinfo() { return srcinfo_; }


std::vector<unsigned char> Crypto::derive_key_iv(const std::string& password, const unsigned char* salt, size_t salt_len, Logger& logger) {
    static constexpr int kKeyLen = 32;
    static constexpr int kIVLen = 12;
    static constexpr int kPBKDF2Iterations = 100000;
    std::vector<unsigned char> key_iv(kKeyLen + kIVLen);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, salt_len, kPBKDF2Iterations,
                           EVP_sha256(), key_iv.size(), key_iv.data()) != 1) {
        logger.log("ERROR", "PBKDF2 key derivation failed");
        throw std::runtime_error("PBKDF2 key derivation failed");
    }
    return key_iv;
}

std::vector<unsigned char> Crypto::encrypt(const std::vector<unsigned char>& plaintext, const std::string& password,
                                         std::vector<unsigned char>& salt, std::vector<unsigned char>& iv,
                                         std::vector<unsigned char>& tag, Logger& logger) {
    static constexpr int kSaltLen = 16;
    static constexpr int kIVLen = 12;
    static constexpr int kTagLen = 16;
    salt.resize(kSaltLen);
    iv.resize(kIVLen);
    tag.resize(kTagLen);
    if (RAND_bytes(salt.data(), kSaltLen) != 1 || RAND_bytes(iv.data(), kIVLen) != 1) {
        logger.log("ERROR", "Failed to generate cryptographic random bytes");
        throw std::runtime_error("Failed to generate cryptographic random bytes");
    }

    auto key_iv = derive_key_iv(password, salt.data(), salt.size(), logger);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_iv.data(), iv.data()) != 1) throw std::runtime_error("EVP_EncryptInit_ex failed");
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) throw std::runtime_error("EVP_EncryptUpdate failed");
        ciphertext_len = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) throw std::runtime_error("EVP_EncryptFinal_ex failed");
        ciphertext_len += len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, tag.data()) != 1) throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
        
        ciphertext.resize(ciphertext_len);
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    logger.log("INFO", "Data encrypted successfully");
    return ciphertext;
}

std::vector<unsigned char> Crypto::decrypt(const std::vector<unsigned char>& ciphertext, const std::string& password,
                                         const std::vector<unsigned char>& salt, const std::vector<unsigned char>& iv,
                                         const std::vector<unsigned char>& tag, Logger& logger) {
    auto key_iv = derive_key_iv(password, salt.data(), salt.size(), logger);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;

    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_iv.data(), iv.data()) != 1) throw std::runtime_error("EVP_DecryptInit_ex failed");
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) throw std::runtime_error("EVP_DecryptUpdate failed");
        plaintext_len = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1) throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
           throw std::runtime_error("Decryption failed: verification error");
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    logger.log("INFO", "Data decrypted successfully");
    return plaintext;
}


F5Steganography::F5Steganography(Logger& logger) : logger_(logger), capacity_bits_(0) {
    unsigned char seed[32];
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        logger_.log("ERROR", "Failed to initialize CSPRNG");
        throw std::runtime_error("Failed to initialize CSPRNG");
    }
    std::seed_seq seq(seed, seed + sizeof(seed));
    rng_.seed(seq);
}

size_t F5Steganography::get_capacity_bits() const { return capacity_bits_; }

void F5Steganography::collect_modifiable_coeffs(JpegHandler& jpeg) {
    modifiable_coeffs_.clear();
    auto coeff_arrays = jpeg.get_coeff_arrays();
    auto& srcinfo = jpeg.get_srcinfo();

    for (int ci = 0; ci < srcinfo.num_components; ++ci) {
        jpeg_component_info* comp_ptr = &srcinfo.comp_info[ci];
        for (JDIMENSION by = 0; by < comp_ptr->height_in_blocks; ++by) {
            JBLOCKARRAY block_row = srcinfo.mem->access_virt_barray(
                (j_common_ptr)&srcinfo, coeff_arrays[ci], by, 1, false);
            for (JDIMENSION bx = 0; bx < comp_ptr->width_in_blocks; ++bx) {
                JBLOCK* block = &block_row[0][bx];
                for (int i = 1; i < DCTSIZE2; ++i) {
                    if ((*block)[i] != 0) {
                        if (std::abs((*block)[i]) > 1) {
                             modifiable_coeffs_.push_back({&((*block)[i]), block});
                        }
                    }
                }
            }
        }
    }
    capacity_bits_ = modifiable_coeffs_.size();
    logger_.log("INFO", "Found " + std::to_string(modifiable_coeffs_.size()) + " modifiable coefficients");
}

std::vector<int> F5Steganography::generate_shuffle_indices(const std::string& password) {
    std::vector<int> indices(modifiable_coeffs_.size());
    std::iota(indices.begin(), indices.end(), 0);
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("Failed to create EVP_MD_CTX");
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, password.c_str(), password.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    std::seed_seq seq(hash, hash + hash_len);
    auto rng = std::mt19937(seq);
    std::shuffle(indices.begin(), indices.end(), rng);
    return indices;
}

size_t F5Steganography::embed_data(JpegHandler& jpeg, const std::vector<unsigned char>& data, const std::string& password, int quality) {
     collect_modifiable_coeffs(jpeg);
    std::vector<bool> bits;
    for (unsigned char byte : data) {
        for (int i = 7; i >= 0; --i) bits.push_back((byte >> i) & 1);
    }

    if (bits.size() > capacity_bits_) {
        logger_.log("ERROR", "Data (" + std::to_string(bits.size()) + " bits) exceeds JPEG capacity (" + std::to_string(capacity_bits_) + " bits)");
        return 0;
    }

    auto shuffle_indices = generate_shuffle_indices(password);

    size_t bit_idx = 0;
    for (int idx : shuffle_indices) {
        if (bit_idx >= bits.size()) break;
        JCOEF* coeff = modifiable_coeffs_[idx].first;
        if (*coeff != 0) {
            JCOEF old_val = *coeff;
            JCOEF new_val = old_val;
            if ((old_val % 2) != (bits[bit_idx] ? 1 : 0)) {
                if (old_val > 0) new_val--; else new_val++;
            }
            if (new_val != 0) {
                *coeff = new_val;
                bit_idx++;
            }
        }
    }

    logger_.log("INFO", "Embedded " + std::to_string(bit_idx) + " bits successfully");
    return bit_idx;
}

std::vector<unsigned char> F5Steganography::extract_data(JpegHandler& jpeg, const std::string& password) {
    // ... implementasi fungsi extract_data ...
    // (Kode ini sudah benar, tidak perlu diubah)
    collect_modifiable_coeffs(jpeg);
    auto shuffle_indices = generate_shuffle_indices(password);
    
    std::vector<bool> bits;
    bits.reserve(modifiable_coeffs_.size());
    for (int idx : shuffle_indices) {
        JCOEF* coeff = modifiable_coeffs_[idx].first;
        if (*coeff != 0) {
            bits.push_back(std::abs(*coeff) % 2);
        }
    }

    std::vector<unsigned char> extracted_data;
    for (size_t i = 0; i < bits.size() / 8; ++i) {
        unsigned char byte = 0;
        for (int j = 0; j < 8; ++j) {
            byte = (byte << 1) | (bits[i * 8 + j] ? 1 : 0);
        }
        extracted_data.push_back(byte);
    }
    
    logger_.log("INFO", "Extracted " + std::to_string(extracted_data.size()) + " bytes.");
    return extracted_data;
}

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
#include <jpeglib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define COLOR_RED "\033[91m"
#define COLOR_GREEN "\033[92m"
#define COLOR_YELLOW "\033[93m"
#define COLOR_RESET "\033[0m"

namespace F5 {
    constexpr int kMaxCodewordLength = 31;
    constexpr int kMaxBitsPerCodeword = 5;
    constexpr int kDefaultQuality = 75;
    constexpr size_t kDefaultChunkSize = 1024;
}

class Logger {
private:
    std::ofstream log_file_;
    std::mutex log_mutex_;

public:
    Logger(const std::string& filename = "f5_stego.log") {
        log_file_.open(filename, std::ios::app);
        if (!log_file_.is_open()) {
            throw std::runtime_error("Cannot open log file: " + filename);
        }
    }

    ~Logger() {
        if (log_file_.is_open()) log_file_.close();
    }

    void log(const std::string& level, const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        log_file_ << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
                  << " [" << level << "] " << message << std::endl;
        std::cout << (level == "ERROR" ? COLOR_RED : COLOR_YELLOW)
                  << "[" << level << "] " << message << COLOR_RESET << std::endl;
    }
};

class JpegHandler {
private:
    jpeg_decompress_struct srcinfo_;
    jpeg_compress_struct dstinfo_;
    jpeg_error_mgr jerr_;
    jvirt_barray_ptr* coeff_arrays_;
    int width_, height_, comps_;
    int data_precision_;

public:
    JpegHandler() : coeff_arrays_(nullptr), width_(0), height_(0), comps_(0), data_precision_(0) {
        srcinfo_.err = jpeg_std_error(&jerr_);
        dstinfo_.err = jpeg_std_error(&jerr_);
        jpeg_create_decompress(&srcinfo_);
        jpeg_create_compress(&dstinfo_);
    }

    ~JpegHandler() {
        jpeg_destroy_decompress(&srcinfo_);
        jpeg_destroy_compress(&dstinfo_);
    }

    void load(const std::string& filename, Logger& logger) {
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

    void save(const std::string& filename, int quality, Logger& logger) {
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

    jvirt_barray_ptr* get_coeff_arrays() const { return coeff_arrays_; }
    jpeg_decompress_struct& get_srcinfo() { return srcinfo_; }
};

class Crypto {
private:
    static constexpr int kKeyLen = 32;
    static constexpr int kIVLen = 12;
    static constexpr int kTagLen = 16;
    static constexpr int kSaltLen = 16;
    static constexpr int kPBKDF2Iterations = 100000;

public:
    static std::vector<unsigned char> derive_key_iv(const std::string& password, const unsigned char* salt, size_t salt_len, Logger& logger) {
        std::vector<unsigned char> key_iv(kKeyLen + kIVLen);
        if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, salt_len, kPBKDF2Iterations,
                               EVP_sha256(), key_iv.size(), key_iv.data()) != 1) {
            logger.log("ERROR", "PBKDF2 key derivation failed");
            throw std::runtime_error("PBKDF2 key derivation failed");
        }
        return key_iv;
    }

    static std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::string& password,
                                             std::vector<unsigned char>& salt, std::vector<unsigned char>& iv,
                                             std::vector<unsigned char>& tag, Logger& logger) {
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
        int len, ciphertext_len;

        try {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_iv.data(), iv.data()) != 1 ||
                EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1 ||
                EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1 ||
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, tag.data()) != 1) {
                throw std::runtime_error("Encryption failed");
            }
            ciphertext_len = len;
            ciphertext.resize(ciphertext_len);
        } catch (...) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
        EVP_CIPHER_CTX_free(ctx);
        logger.log("INFO", "Data encrypted successfully");
        return ciphertext;
    }

    static std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const std::string& password,
                                             const std::vector<unsigned char>& salt, const std::vector<unsigned char>& iv,
                                             const std::vector<unsigned char>& tag, Logger& logger) {
        auto key_iv = derive_key_iv(password, salt.data(), salt.size(), logger);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        std::vector<unsigned char> plaintext(ciphertext.size());
        int len, plaintext_len;

        try {
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_iv.data(), iv.data()) != 1 ||
                EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1 ||
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1 ||
                EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
                throw std::runtime_error("Decryption failed");
            }
            plaintext_len = len;
            plaintext.resize(plaintext_len);
        } catch (...) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
        EVP_CIPHER_CTX_free(ctx);
        logger.log("INFO", "Data decrypted successfully");
        return plaintext;
    }
};

class F5Steganography {
private:
    Logger& logger_;
    std::mt19937 rng_;
    std::vector<std::pair<JCOEF*, JBLOCK*>> modifiable_coeffs_;
    size_t capacity_bits_;

public:
    F5Steganography(Logger& logger) : logger_(logger), capacity_bits_(0) {
        unsigned char seed[32];
        if (RAND_bytes(seed, sizeof(seed)) != 1) {
            logger_.log("ERROR", "Failed to initialize CSPRNG");
            throw std::runtime_error("Failed to initialize CSPRNG");
        }
        std::seed_seq seq(seed, seed + sizeof(seed));
        rng_.seed(seq);
    }

    size_t get_capacity_bits() const { return capacity_bits_; }

    void collect_modifiable_coeffs(JpegHandler& jpeg) {
        modifiable_coeffs_.clear();
        std::mutex coeff_mutex;
        std::vector<std::thread> threads;
        auto coeff_arrays = jpeg.get_coeff_arrays();
        auto& srcinfo = jpeg.get_srcinfo();

        for (int ci = 0; ci < srcinfo.num_components; ++ci) {
            threads.emplace_back([&, ci]() {
                std::vector<std::pair<JCOEF*, JBLOCK*>> local_coeffs;
                jpeg_component_info* comp_ptr = &srcinfo.comp_info[ci];
                for (JDIMENSION by = 0; by < comp_ptr->height_in_blocks; ++by) {
                    JBLOCKARRAY block_row = srcinfo.mem->access_virt_barray(
                        (j_common_ptr)&srcinfo, coeff_arrays[ci], by, 1, TRUE);
                    for (JDIMENSION bx = 0; bx < comp_ptr->width_in_blocks; ++bx) {
                        JBLOCK* block = &block_row[0][bx];
                        for (int i = 1; i < 16; ++i) {
                            if ((*block)[i] != 0) {
                                local_coeffs.push_back({&((*block)[i]), block});
                            }
                        }
                    }
                }
                std::lock_guard<std::mutex> lock(coeff_mutex);
                modifiable_coeffs_.insert(modifiable_coeffs_.end(), local_coeffs.begin(), local_coeffs.end());
            });
        }
        for (auto& t : threads) t.join();
        capacity_bits_ = modifiable_coeffs_.size() * F5::kMaxBitsPerCodeword;
        logger_.log("INFO", "Found " + std::to_string(modifiable_coeffs_.size()) + " modifiable coefficients");
    }

    std::vector<int> generate_shuffle_indices(const std::string& password) {
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

    size_t embed_data(JpegHandler& jpeg, const std::vector<unsigned char>& data, const std::string& password, int quality) {
        collect_modifiable_coeffs(jpeg);
        std::vector<unsigned char> salt, iv, tag, encrypted_data;
        try {
            encrypted_data = Crypto::encrypt(data, password, salt, iv, tag, logger_);
        } catch (const std::runtime_error& e) {
            logger_.log("ERROR", "Encryption failed: " + std::string(e.what()));
            return 0;
        }

        std::vector<unsigned char> payload;
        payload.insert(payload.end(), salt.begin(), salt.end());
        payload.insert(payload.end(), iv.begin(), iv.end());
        payload.insert(payload.end(), tag.begin(), tag.end());
        uint32_t data_len = encrypted_data.size();
        payload.push_back((data_len >> 24) & 0xFF);
        payload.push_back((data_len >> 16) & 0xFF);
        payload.push_back((data_len >> 8) & 0xFF);
        payload.push_back(data_len & 0xFF);
        payload.insert(payload.end(), encrypted_data.begin(), encrypted_data.end());

        std::vector<bool> bits;
        for (unsigned char byte : payload) {
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
                *coeff = (*coeff & ~1) | (bits[bit_idx] ? 1 : 0);
                bit_idx++;
            }
        }

        logger_.log("INFO", "Embedded " + std::to_string(data.size()) + " bytes successfully");
        return data.size();
    }

    std::vector<unsigned char> extract_data(JpegHandler& jpeg, const std::string& password) {
        collect_modifiable_coeffs(jpeg);
        auto shuffle_indices = generate_shuffle_indices(password);

        std::vector<bool> bits;
        for (int idx : shuffle_indices) {
            JCOEF* coeff = modifiable_coeffs_[idx].first;
            bits.push_back(*coeff & 1);
        }

        std::vector<unsigned char> payload;
        for (size_t i = 0; i + 7 < bits.size(); i += 8) {
            unsigned char byte = 0;
            for (int j = 0; j < 8; ++j) byte = (byte << 1) | (bits[i + j] ? 1 : 0);
            payload.push_back(byte);
        }

        if (payload.size() < (16 + 12 + 16 + 4)) {
            logger_.log("ERROR", "Extracted data too short for header");
            return {};
        }

        std::vector<unsigned char> salt(payload.begin(), payload.begin() + 16);
        std::vector<unsigned char> iv(payload.begin() + 16, payload.begin() + 16 + 12);
        std::vector<unsigned char> tag(payload.begin() + 16 + 12, payload.begin() + 16 + 12 + 16);
        uint32_t data_len = (payload[16 + 12 + 16] << 24) | (payload[16 + 12 + 16 + 1] << 16) |
                            (payload[16 + 12 + 16 + 2] << 8) | payload[16 + 12 + 16 + 3];
        std::vector<unsigned char> encrypted_data(payload.begin() + 16 + 12 + 16 + 4, payload.end());
        if (encrypted_data.size() < data_len) {
            logger_.log("ERROR", "Incomplete encrypted data extracted");
            return {};
        }
        encrypted_data.resize(data_len);

        try {
            return Crypto::decrypt(encrypted_data, password, salt, iv, tag, logger_);
        } catch (const std::runtime_error& e) {
            logger_.log("ERROR", "Decryption failed: " + std::string(e.what()));
            return {};
        }
    }
};
// F5steg.h

#ifndef F5STEG_H
#define F5STEG_H

#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <random>
#include <jpeglib.h>

// Forward declaration untuk menghindari dependensi sirkular jika ada
class JpegHandler; 

class Logger {
private:
    std::ofstream log_file_;
    std::mutex log_mutex_;
public:
    Logger(const std::string& filename = "f5_stego.log");
    ~Logger();
    void log(const std::string& level, const std::string& message);
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
    JpegHandler();
    ~JpegHandler();
    void load(const std::string& filename, Logger& logger);
    void save(const std::string& filename, int quality, Logger& logger);
    jvirt_barray_ptr* get_coeff_arrays() const;
    jpeg_decompress_struct& get_srcinfo();
};

class Crypto {
public:
    static std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::string& password,
                                             std::vector<unsigned char>& salt, std::vector<unsigned char>& iv,
                                             std::vector<unsigned char>& tag, Logger& logger);
    static std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const std::string& password,
                                             const std::vector<unsigned char>& salt, const std::vector<unsigned char>& iv,
                                             const std::vector<unsigned char>& tag, Logger& logger);
private:
     static std::vector<unsigned char> derive_key_iv(const std::string& password, const unsigned char* salt, size_t salt_len, Logger& logger);
};


class F5Steganography {
private:
    Logger& logger_;
    std::mt19937 rng_;
    std::vector<std::pair<JCOEF*, JBLOCK*>> modifiable_coeffs_;
    size_t capacity_bits_;
    std::vector<int> generate_shuffle_indices(const std::string& password);
public:
    F5Steganography(Logger& logger);
    size_t get_capacity_bits() const;
    void collect_modifiable_coeffs(JpegHandler& jpeg);
    size_t embed_data(JpegHandler& jpeg, const std::vector<unsigned char>& data, const std::string& password, int quality);
    std::vector<unsigned char> extract_data(JpegHandler& jpeg, const std::string& password);
};

#endif // F5STEG_H

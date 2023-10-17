#pragma once
#include <vector>
#include <string>
#include <string.h>
#include <random>

struct dummy {
    int a;
};

// Number of bits in 1 digit. Must be <= 32
const int bit_base = 32;
// Base of the counting system. Numbers are stored in binary format, so base = 2**bit_base
const unsigned long long base = (unsigned long long)pow(2, bit_base);

class bigint;

class RNG {
    std::mt19937 engine;
public:
    RNG();
    unsigned get_random(unsigned min, unsigned max);
    bigint get_big_random(bigint min, bigint max);
};
unsigned int create_bitmask(unsigned char bits);

class bigint
{
private:
    std::vector<unsigned int> digits;
    bool is_negative;
    void _div(bigint &b, bigint *res, bigint *mod);
    int _bits_count();
    void set_bit(int pos, bool val);
    bool get_bit(int pos);
    void trim();
public:
    bigint();
    bigint(bool negative, const unsigned int* digits_arr, size_t count);
    bigint(const unsigned char* bytes, size_t size);
    bigint(const char* hex_str, dummy dummy); // dummy is not used and only here because of c++
    bigint(long long num);
    bigint(RNG &rng, unsigned int bits);
    bigint(const bigint& b);

    std::string to_string() const;

    bool is_prime();
    unsigned long long log2();
    unsigned long long digits_count();
    unsigned char* as_bytes(size_t *size);

    void operator+=(bigint b);
    void operator-= (bigint b);
    void operator*=(bigint b);
    void operator/= (bigint b);
    void operator%=(bigint b);
    void operator++(int d);
    void operator--(int d);

    bigint operator+ (bigint b);
    bigint operator- (bigint b);
    bigint operator* (bigint b);
    bigint operator/ (bigint b);
    bigint operator% (bigint b);
    bigint operator+ (long num);
    bigint operator- (long num);
    bigint operator* (long num);
    bigint operator/ (long num);
    bigint operator% (long num);

    bool operator == (bigint b);
    bool operator == (long num);
    bool operator != (bigint b);
    bool operator != (long num);
    bool operator < (bigint b);
    bool operator < (long num);
    bool operator > (bigint b);
    bool operator > (long num);
    bool operator <= (bigint b);
    bool operator <= (long num);
    bool operator >= (bigint b);
    bool operator >= (long num);

    bigint operator >> (int bits);
    bigint operator << (int bits);
    void operator <<= (int bits);
    void operator >>= (int bits);

    unsigned int operator[](int index);

    bigint friend operator- (bigint& big);

    ~bigint();
};

bigint operator- (bigint& big);
std::ostream& operator << (std::ostream &os, const bigint &big);
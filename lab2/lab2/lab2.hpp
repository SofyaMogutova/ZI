#pragma once
#include "utils.hpp"
#include <assert.h>

class Shamir {
	RNG rng;
	std::string name;
	int c, d;
public:
	unsigned int p;
	Shamir(const char* name);
	void init_connection(Shamir* receiver);
	void accept_connection(int p);
	void generate_cd();
	void send_encrypted(const unsigned char* message, size_t size, Shamir* receiver);
	void receive_x1(Shamir* sender, unsigned int* x1, size_t size);
	void receive_x2(Shamir* receiver, unsigned int* x2, size_t size);
	void receive_x3(Shamir* sender, unsigned int* x3, size_t size);
};

class RSA {
	RNG rng;
	std::string name;
	int p, q;
	int secret_key;
public:
	int public_key;
	int n;
	RSA(const char* name = "RSA");
	void generate_keys();
	void print_keys();
	void save_keys_to_files(const char* _public, const char* _secret);
	void load_keys_from_files(const char* _public, const char* _secret);
	int* encrypt_data(const unsigned char* data, int public_key, int n, size_t size);
	unsigned char* decrypt_data(const int* encrypted, int secret_key, int n, size_t size);
	void send_encrypted(RSA* receiver, const unsigned char* message, size_t size);
	void receive_encrypted(int* encrypted, size_t size);
	void encrypt_file(const char* file_in, const char* file_out);
	void decrypt_file(const char* file_in, const char* file_out);
};

class RSA_Big {
	RNG rng;
	std::string name;
	bigint p, q, phi;
	bigint secret_key;
public:
	bigint public_key;
	bigint n;
	RSA_Big(const char* name = "RSA");
	void generate_keys();
	void print_keys();
	bool test_keys();
	void save_keys_to_files(const char* _public, const char* _secret);
	void load_keys_from_files(const char* _public, const char* _secret);
	std::vector<bigint> encrypt_data(const unsigned char* data, bigint public_key, bigint n, size_t size);
	unsigned char* decrypt_data(std::vector<bigint> encrypted, bigint secret_key, bigint n, size_t* size);
	void send_encrypted(RSA_Big* receiver, const unsigned char* message, size_t size);
	void receive_encrypted(std::vector<bigint> encrypted);
	void encrypt_file(const char* file_in, const char* file_out);
	void decrypt_file(const char* file_in, const char* file_out);
};

static class Vernam {
public:
	static unsigned char* encrypt_data(const unsigned char* data, const unsigned char* key, size_t size);
	static void encrypt_file(const char* file_in, const char* file_out, const char* file_key);
	static unsigned char* generate_key(size_t size);
	static unsigned char* decrypt_data(const unsigned char* encrypted, const unsigned char* key, size_t size);
	static void decrypt_file(const char* file_in, const char* file_out, const char* file_key);
};
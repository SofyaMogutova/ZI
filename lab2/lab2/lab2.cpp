#include "utils.hpp"
#include "lab2.hpp"

int main()
{
    RNG rng;
    //bigint test = generate_big_prime(256);
    //std::cout << test << " is prime? : " << is_prime(test, 5) << std::endl;
    //char buffer[] = "Hello, Bob!";

    unsigned int buffer[] = { 10, 32 };
    bigint test(false, buffer, sizeof(buffer) / sizeof(buffer[0]));
    std::cout << test << std::endl;
    size_t data_size;
    unsigned char* test_data = test.as_bytes(&data_size);
    std::cout << "Size = " << data_size << std::endl;
    for (int i = 0; i < data_size; i++) {
        std::cout << (int)test_data[i] << " ";
    }
    std::cout << std::endl;
    return 0;

    // pk: 80283cd0ef834946a90d3eaaecd54e74737f331e7790d6d9a8713749f38a16c1
    // n:  a9cf8d311ea04f178ad7780f20e1856a24422212a06955e264021557be2f6f9
    // sk: 555502f233ac386ad38bad28bfa53b867aeec79276ef5d0f719851d75382c41

    /*bigint test(5);
    test *= base;
    test <<= 24;
    std::cout << test << std::endl;
    size_t size;
    unsigned char* data = test.as_bytes(&size);
    for (int i = 0; i < size; i++) {
        std::cout << std::hex << (int)data[i] << std::endl;
    }
    return 0;*/

    //bigint test(buffer, sizeof(buffer));
    //std::cout << test << std::endl;
    
    /*Shamir alice("Alice");
    Shamir bob("Bob");
    alice.init_connection(&bob);
    alice.send_encrypted(buffer, sizeof(buffer), &bob);*/

    /*Abonent alice("Alice");
    Abonent bob("Bob");
    alice.init_connection(bob);
    alice.send_el_gamal_encrypted(bob, buffer, sizeof(buffer));*/

    //RSA_Big alice("Alice");
    ////RSA_Big bob("Bob");
    //alice.print_keys();
    //alice.test_keys();
    //bob.print_keys();
    //alice.send_encrypted(&bob, buffer, sizeof(buffer));
    //bigint test(buffer, sizeof(buffer));
    /*for (int i = 0; i < sizeof(buffer); i++) {
        std::cout << std::hex << (int)buffer[i];
    }
    std::cout << std::endl;*/
    /*char* test_buf = test.as_bytes();
    std::cout << test_buf << std::endl;
    delete[] test_buf;*/
    //alice.send_encrypted(&bob, buffer, sizeof(buffer));
    size_t pic_size;
    unsigned char* data = load_from_file("test.txt", &pic_size);
    for (int i = 0; i < 20; i++) {
        std::cout /* << std::hex*/ << (int)data[pic_size - i - 1] << " ";
    }
    std::cout << std::endl;
    RSA_Big rsa;
   /* rsa.encrypt_file("Screen.png", "rsa_enc.txt");
    rsa.decrypt_file("rsa_enc.txt", "rsa_dec_pic.png");*/
    rsa.encrypt_file("test.txt", "rsa_enc.txt");
    rsa.decrypt_file("rsa_enc.txt", "rsa_dec.txt");

    size_t dec_size;
    unsigned char* dec_data = load_from_file("rsa_dec.txt", &dec_size);
    for (int i = 0; i < 20; i++) {
        std::cout /* << std::hex*/ << (int)dec_data[dec_size - i - 1] << " ";
    }
    std::cout << std::endl;

    //size_t pic_size;
    //unsigned char* data = load_from_file("Screen.png", &pic_size);
    //for (int i = 0; i < 20; i++) {
    //    std::cout /* << std::hex*/ << (int)data[i] << std::endl;
    //}
    //save_to_file(data, pic_size, "test_save.png");
    
    /*Vernam::encrypt_file("test.txt", "vernam_enc.txt", "vernam_key.txt");
    Vernam::decrypt_file("vernam_enc.txt", "vernam_dec.txt", "vernam_key.txt");*/
}
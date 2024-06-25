#ifndef DECRYPT_H
#define DECRYPT_H

// #define MAIN_DECRYPT

#define CLIENT_RANDOM_LENGTH 32
#define SERVER_RANDOM_LENGTH 32
#define PRE_MASTER_SECRET_LENGTH 48
#define HASH_SECRET_LENGTH 48
#define HASH_SEED_LENGTH 77
#define HASH_OUT_LENGTH 104
#define PRF_OUT_LENGTH 104
#define KEY_EXPANSION_LENGTH 104
#define CLIENT_KEY_LENGTH 16
#define SERVER_KEY_LENGTH 16
#define CLIENT_IV_LENGTH 4
#define SERVER_IV_LENGTH 4

#define SEQ_LENGTH 8
#define NONCE_LENGTH 12
#define ADD_LENGTH 13
#define AUTH_TAG_LENGTH 16

#define PLAINTEXT_LENGTH 4096

#define KEY_EXPANSION_HEX "\x6b\x65\x79\x20\x65\x78\x70\x61\x6e\x73\x69\x6f\x6e"

typedef unsigned char u_char;

int decrypt_aes_128_gcm(const unsigned char *ciphertext, int ciphertext_len, 
                    const unsigned char *key,
                    const unsigned char *nonce,                     
                    unsigned char *plaintext);


typedef struct tls_session_info
{
    int has_client_random;
    int has_server_random;
    int has_pre_master_key;

    unsigned char client_random[CLIENT_RANDOM_LENGTH];
    unsigned char server_random[SERVER_RANDOM_LENGTH];

    unsigned char pre_master_secret[PRE_MASTER_SECRET_LENGTH];

    unsigned char hash_secret[HASH_SECRET_LENGTH];
    unsigned char hash_seed[HASH_SEED_LENGTH];

    unsigned char hash_out[HASH_OUT_LENGTH];
    unsigned char prf_out[PRF_OUT_LENGTH];
    unsigned char key_expansion[KEY_EXPANSION_LENGTH];

    unsigned char client_key[CLIENT_KEY_LENGTH];
    unsigned char server_key[SERVER_KEY_LENGTH];

    unsigned char client_iv[CLIENT_IV_LENGTH];
    unsigned char server_iv[SERVER_IV_LENGTH];

    // unsigned short int http_version; // 判断以解压 http 数据
}tls_session_info;

typedef struct tls_record_info{
    unsigned int ciphertext_length;
    unsigned char *ciphertext;

    unsigned char seq[SEQ_LENGTH];
    unsigned char nonce[NONCE_LENGTH];
    unsigned char aad[ADD_LENGTH];
    unsigned char auth_tag[AUTH_TAG_LENGTH];

    unsigned int plaintext_length;
    unsigned char *plaintext;
}tls_record_info;

int generate(tls_session_info *session, tls_record_info *record);



#endif /* DECRYPT_H */

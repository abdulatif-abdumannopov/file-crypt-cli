#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

unsigned char* read_file(const char *filename, size_t *len) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buffer = malloc(*len);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    fread(buffer, 1, *len, f);
    fclose(f);
    return buffer;
}

void hash_sha256(const unsigned char *data, size_t len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

void derive_key_iv(const char *password, unsigned char *key, unsigned char *iv) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);

    memcpy(key, hash, 32);
    memcpy(iv, hash, 12);
}


int encrypt_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext, unsigned char *tag) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_aes_gcm(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    const unsigned char *tag,
                    unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main(int argc, char *argv[]) {
    int opt;
    char *input = NULL;
    char *output = NULL;
    char *password = NULL;
    int mode = 0;

    while ((opt = getopt(argc, argv, "edf:o:p:h")) != -1) {
        switch (opt) {
            case 'e': mode = 1; break;
            case 'd': mode = 2; break;
            case 'h': mode = 3; break;
            case 'f': input = optarg; break;
            case 'o': output = optarg; break;
            case 'p': password = optarg; break;
            default:
                fprintf(stderr, "use: %s [-e][-d][-h] -f file_path -o output filename", argv[0]);
                return 1;
        }
    }

    if (mode == 0 || !input || (mode != 3 && !output) || (mode != 3 && !password)) {
        fprintf(stderr, "Not right arguments\n");
        return 1;
    }

    size_t len;
    unsigned char *data = read_file(input, &len);
    if (!data) {
        fprintf(stderr, "couldn't open the file %s\n", input);
        return 1;
    }

    if (mode == 1) {
        unsigned char key[32], iv[12], tag[16];
        derive_key_iv(password, key, iv);

        unsigned char *ciphertext = malloc(len + 16);
        int ct_len = encrypt_aes_gcm(data, len, key, iv, ciphertext, tag);

        FILE *fout = fopen(output, "wb");
        fwrite(ciphertext, 1, ct_len, fout);
        fwrite(tag, 1, 16, fout);
        fclose(fout);

        printf("File encrypted: %s\n", output);
        free(ciphertext);

    } else if (mode == 2) {
        if (len < 16) {
            fprintf(stderr, "File's too short\n");
            free(data);
            return 1;
        }

        unsigned char key[32], iv[12];
        derive_key_iv(password, key, iv);

        int ciphertext_len = len - 16;
        unsigned char *ciphertext = data;
        unsigned char *tag = data + ciphertext_len;

        unsigned char *plaintext = malloc(ciphertext_len);
        int pt_len = decrypt_aes_gcm(ciphertext, ciphertext_len, key, iv, tag, plaintext);

        if (pt_len < 0) {
            fprintf(stderr, "Decryption error (wrong password or broken file)\n");
            free(data);
            free(plaintext);
            return 1;
        }

        FILE *fout = fopen(output, "wb");
        fwrite(plaintext, 1, pt_len, fout);
        fclose(fout);

        printf("Encrypted file: %s\n", output);
        free(plaintext);

    } else if (mode == 3) {
        hash_sha256(data, len);
    }

    free(data);
    return 0;
}

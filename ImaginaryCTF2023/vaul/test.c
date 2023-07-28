#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "aes.h"
struct AES_ctx ctx;
/* Initialize context calling one of: */
void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);
void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);

/* ... or reset IV at random point: */
void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);

/* Then start encrypting and decrypting with the functions below: */
void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);
void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);

/* Same function for encrypting as for decrypting in CTR mode */
void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);

int main(int argc, char *argv[])
{
    struct AES_ctx ctx;

    uint8_t key[] = "aaaaaaaaaaaaaaaa";
    uint8_t iv[] = "bbbbbbbbbbbbbbbb";
    uint8_t str[] = "This a sample text, Length eq 32";

    printf("\n raw buffer \n");
    for (int i = 0; i < 32; ++i)
    {
        printf("%.2x", str[i]);
    }

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, str, 32);

    printf("\n Encrypted buffer\n");

    for (int i = 0; i < 32; ++i)
    {
        printf("%.2x", str[i]);
    }

    printf("\n Decrypted buffer\n");

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, str, 32);

    for (int i = 0; i < 32; ++i)
    {
        printf("%.2x", str[i]);
    }

    printf("\n");
    return 0;
}



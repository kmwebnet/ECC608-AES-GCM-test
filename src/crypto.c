#include "crypto.h"
#include "basic/atca_basic_aes_gcm.h"
#include <stdio.h>

ATCA_STATUS check_config_aes_enable(void)
{
    uint8_t aes_enable;

    // Byte 13 of the config zone contains the AES enable bit
    ATCA_STATUS status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 13, &aes_enable, 1);
    if (status != 0)
    {
        return status;   
    }

    if ((aes_enable & AES_CONFIG_ENABLE_BIT_MASK) ！= 1)
    {
        return ATCA_BAD_PARAM;
    }

    //confirm keyconfig mode
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 96 + key_id * 2, &aes_enable, 1);
    if (status != 0)
    {
        return status;   
    }

    if ((aes_enable & 0x1c ) >> 2 != AES_KEYTYPE)
    {
        return ATCA_BAD_PARAM;
    }



return ATCA_SUCCESS;
}


ATCA_STATUS encryptwrite(uint8_t *data, size_t length) 
{
    if (length > datalength)
    {
        return ATCA_BAD_PARAM;
    }

    uint8_t iv[ivlength];
    uint8_t tag[AES_DATA_SIZE];
    atca_aes_gcm_ctx_t aes_gcm_ctx;
    uint8_t writebuffer[datalength];
    uint8_t ciphertext[datalength];

    uint8_t iv_v[ivlength];
    uint8_t tag_v[AES_DATA_SIZE];
    uint8_t ciphertext_v[datalength];

    ATCAIfaceCfg cfg;
    get_atecc608cfg(&cfg);
    ATCA_STATUS status = atcab_init(&cfg);

    status = check_config_aes_enable();
    if (status != ATCA_SUCCESS)
    {
        printf("bad device config:%d\n", status);
        return ATCA_BAD_PARAM;
    }

    // Load AES keys into Device Slot
    uint8_t aeskeys[32];
    status = atcab_random(aeskeys);
    status = atcab_write_zone(2, key_id, 0, 0, aeskeys, 32);
    printf("atcab_write_zone_5_finish: %02x\n", status);

    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init_rand(&aes_gcm_ctx, key_id, aes_key_block, sizeof(iv), NULL, 0, iv);
    printf("atcab_aes_gcm_init_finish: %02x\n", status);

    status = atcab_write_bytes_zone(2, 8, ivoffset, iv, ivlength);
    printf("atcab_write_iv_finish: %02x\n", status);    

    memcpy(writebuffer, data, length);

    for (int i=0; i < 15; i++ )
    {
    status = atcab_aes_gcm_encrypt_update(&aes_gcm_ctx, &writebuffer[i * 16], 16, &ciphertext[i * 16]);
    printf("atcab_aes_gcm_encrypt_update%d_finish: %02x\n", i,  status);
    }

    status = atcab_write_bytes_zone(2, 8, dataoffset, ciphertext, datalength);
    printf("atcab_write_data_finish: %02x\n", status);   

    //Calculate authentication tag
    status = atcab_aes_gcm_encrypt_finish(&aes_gcm_ctx, tag, taglength);
    printf("atcab_aes_gcm_encrypt_finish: %02x\n", status);

    status = atcab_write_bytes_zone(2, 8, tagoffset, tag, taglength);
    printf("atcab_write_tag_finish: %02x\n", status);   

    //verify
    status = atcab_read_bytes_zone(2, 8, ivoffset, iv_v, ivlength);
    status = memcmp(iv, iv_v, ivlength);
    if (status != 0)
    {
        return ATCA_EXECUTION_ERROR;   
    }

    status = atcab_read_bytes_zone(2, 8, dataoffset, ciphertext_v, datalength);
    status = memcmp(ciphertext, ciphertext_v, datalength);
    if (status != 0)
    {
        return ATCA_EXECUTION_ERROR;   
    }

    status = atcab_read_bytes_zone(2, 8, tagoffset, tag_v, taglength);
    status = memcmp(tag, tag_v, taglength);
    if (status != 0)
    {
        return ATCA_EXECUTION_ERROR;   
    }

return ATCA_SUCCESS;
};

ATCA_STATUS decryptread(uint8_t *data, size_t length) 
{
    if (length > datalength)
    {
        return ATCA_BAD_PARAM;
    }

    uint8_t iv[ivlength];
    uint8_t tag[AES_DATA_SIZE];
    bool is_verified;
    atca_aes_gcm_ctx_t aes_gcm_ctx;
    uint8_t ciphertext[datalength];
    uint8_t readbuffer[datalength];

    ATCAIfaceCfg cfg;
    get_atecc608cfg(&cfg);
    ATCA_STATUS status = atcab_init(&cfg);

    check_config_aes_enable();

    status = atcab_read_bytes_zone(2, 8, ivoffset, iv, ivlength);

    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&aes_gcm_ctx, key_id, aes_key_block, iv, ivlength);
    printf("atcab_aes_gcm_init_finish: %02x\n", status); 

    status = atcab_read_bytes_zone(2, 8, dataoffset, ciphertext, datalength);
    printf("atcab_read_data_finish: %02x\n", status);   

    for (int i=0; i < 15; i++ )
    {
    status = atcab_aes_gcm_decrypt_update(&aes_gcm_ctx, &ciphertext[i * 16], 16, &readbuffer[i * 16]);
    printf("atcab_aes_gcm_decrypt_update%d_finish: %02x\n", i,  status);
    }

    status = atcab_read_bytes_zone(2, 8, tagoffset, tag, taglength);
    printf("atcab_read_tag_finish: %02x\n", status);   

    //Calculate authentication tag
    status = atcab_aes_gcm_decrypt_finish(&aes_gcm_ctx, tag, taglength, &is_verified);
    printf("atcab_aes_gcm_decrypt_finish: %02x\n", status);

    if (is_verified == false)
    {
        return status;   
    }

    memcpy(data, readbuffer, length);

return ATCA_SUCCESS;
};

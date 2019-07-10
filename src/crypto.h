#ifndef _CRYPTO_H
#define _CRYPTO_H

#include "cryptoauthlib.h"
#include "basic/atca_basic_aes_gcm.h"

#define AES_CONFIG_ENABLE_BIT_MASK   (uint8_t)0x01
#define AES_KEYTYPE                  (uint8_t)0x06

#define key_id 5
#define aes_key_block 0
#define dataoffset 104
#define datalength 240
#define ivoffset 76
#define ivlength 12
#define tagoffset 88
#define taglength 16

void get_atecc608cfg(ATCAIfaceCfg *cfg);
ATCA_STATUS check_config_aes_enable(void);
ATCA_STATUS encryptwrite(uint8_t *data, size_t length);
ATCA_STATUS decryptread(uint8_t *data, size_t length);

#endif
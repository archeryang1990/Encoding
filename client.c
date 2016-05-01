/* ECDSA-256/SHA256, secp256r1
 *
 * This sample is for verify a signature, it's "Client Side".
 * Generate a signature
 * 1. Openssl command to generate key pair:
 *    -Private Key: openssl ecparam -genkey -name secp256k1 -noout -out myprivatekey.pem
 *    -Public Key: openssl ec -in myprivatekey.pem -pubout -out mypubkey.pem
 * 2. Read data_info and fill in structure
 * 3. Generate a digest from soruce data(only message part) with SHA256(digest = 32 bytes)
 * 4. Transfer signature(DER format, 70~72 bytes) to ECDSA_SIG format for OpenSSL stander API usage
 * 5. Decode signature with ECDSA-256(secp256r1) with public key
 * 6. Verify(or means compare) the Step3. digest and Step5.
 *
 * Note. Openssl commands:
 *    -PEM convert to DER: openssl ec -inform DER -in xxx.der -outform PEM xxx.pem
 *    -DER convert to PEM: openssl ec -inform PEM -in xxx.pem -outform DER xxx.der
 *    -Parse private key to hex: openssl asn1parse -i -in xxx.pem
 *    -Build command: gcc -o client -lssl -lcrypto -std=c99 client.c
 *    -Exe command: ./client appeded_sig_token.bin
 *
 *Version History:
 **-------------------------------------------------------------------------------------------------------------------
 **| Update Data | Who   | Version | Symptom
 **-------------------------------------------------------------------------------------------------------------------
 **| Apr.02 2016 | Syuan | 1.0     | Implement Decode tool with ECDSA algo.
 **-------------------------------------------------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#define TEST 1
#define WRONG_PUBKEY_TEST 0
#define LEN_DATA_INFO_MEG 125
#define LEN_DATA_INFO_SIG 70
typedef struct data_info
{
        char magic[8];
        int request_version;
        int message_length;
        int signature_offset;
        int signature_length;
        char nonce[32];
        char sn[32];
        char pn[32];
        int request_type;
        unsigned char reboot_count;
        //...
        char signature[LEN_DATA_INFO_SIG];
}DATA_INFO;

DATA_INFO g_data_request;

#if WRONG_PUBKEY_TEST
//FAILED PUB KEY for test
unsigned char* pem_pubkey = "-----BEGIN PUBLIC KEY-----\n"
                            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEe75CfPzne6uBgz/nuuNO3QZ1lTHWYjke\n"
                            "NANhS67rH4Eb9ExQ4HdNuKnO0RslcXPQNzuQ4m1zldbVspvogKIlMw==\n"
                            "-----END PUBLIC KEY-----\n";
#else
unsigned char* pem_pubkey = "-----BEGIN PUBLIC KEY-----\n"
			    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEOJmY+4XzBab/9y/3zZqZNCthLWDJZNlO\n"
			    "cq/d/UziKG/4+potphoqzrH26OS3ssydAcmzZLhyRw8/5xl7ATbC7A==\n"
			    "-----END PUBLIC KEY-----\n";
#endif

void fill_data_info(char* data)
{
        memset(&g_data_request, 0, sizeof(struct data_info));

        memcpy(&g_data_request.magic, data, 8);
        memcpy(&g_data_request.request_version, data+8, 4);
        memcpy(&g_data_request.message_length, data+12, 4);
        memcpy(&g_data_request.signature_offset, data+16, 4);
        memcpy(&g_data_request.signature_length, data+20, 4);
        memcpy(&g_data_request.nonce, data+24, 32);
        memcpy(&g_data_request.sn, data+56, 32);
        memcpy(&g_data_request.pn, data+88, 32);
        memcpy(&g_data_request.request_type, data+120, 4);
        memcpy(&g_data_request.reboot_count, data+124, 1);
	//signature
	memcpy(&g_data_request.signature, data+125, LEN_DATA_INFO_SIG);
}

int calculate_sha(unsigned char* src, int len, unsigned char* digest)
{
        if (src == NULL || len <= 0 || digest == NULL)
        {
                printf("[SHA256] Caculate SHA failed.\n");
                return -1;
        }

        SHA256(src, len, digest);
#if TEST
        printf("[SHA256] DATA INFO DIGEST:\n");
        for (int xx=1; xx<=32; xx++)
        {
                printf("%.2x ", *(digest+xx-1));
                if (xx%16 == 0)
                {
                        printf("\n");
                }
        }
        printf("\n\n");
#endif
	return 0;
}

static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey)
{
        EC_KEY *dtmp;
        if(!key) return NULL;
        dtmp = EVP_PKEY_get1_EC_KEY(key);
        EVP_PKEY_free(key);
        if(!dtmp) return NULL;
        if(eckey)
        {
                EC_KEY_free(*eckey);
                *eckey = dtmp;
        }
        return dtmp;
}

EVP_PKEY *ARRAY_read_PubKey(unsigned char* pemkey, EVP_PKEY **x, pem_password_cb *cb,
                                                                void *u)
{
        BIO *b;
        EVP_PKEY *ret;
        if ((b=BIO_new_mem_buf(pemkey, -1)) == NULL)
        {
                printf("%s(%d): Failed.\n", __func__, __LINE__);
                return 0;
        }
        ret=PEM_read_bio_PUBKEY(b,x,cb,u);
        BIO_free(b);
        return ret;
}

EC_KEY *ARRAY_read_ECPublicKey(unsigned char* pemkey, EC_KEY **eckey, pem_password_cb *cb,
                                                               void *u)
{
        EVP_PKEY *pktmp;
        pktmp = ARRAY_read_PubKey(pemkey, NULL, cb, u);
        return pkey_get_eckey(pktmp, eckey);    /* will free pktmp */
}

int main(int argc, char *argv[])
{
	char info_digest[32] = {0};
	EC_KEY* ec_pubkey = EC_KEY_new();
	ECDSA_SIG *sig = NULL;
	int ret = 0;

        if (argc < 1)
        {
                printf("***Please append the data token image***\n");
                return 0;
        }

	// read token and fill in data info structure
        FILE* src_fp = fopen(argv[1], "rb");
        if (src_fp == NULL)
        {
                printf("***Failed to open token binary file***\n");
                fclose(src_fp);
                return 0;
        }

        char* tmp_buf = (char*)malloc(LEN_DATA_INFO_MEG + LEN_DATA_INFO_SIG);
        ret = fread(tmp_buf, 1, LEN_DATA_INFO_MEG + LEN_DATA_INFO_SIG, src_fp);
        if (ret != LEN_DATA_INFO_MEG + LEN_DATA_INFO_SIG)
        {
                printf("***Read failed token size(%d)***\n", ret);
                fclose(src_fp);
                free(tmp_buf);
                return 0;
        }

	fill_data_info(tmp_buf);
	free(tmp_buf);
	fclose(src_fp);
#if TEST
        printf("[Read] Token Info:\n");
        for (int xx=1; xx<=LEN_DATA_INFO_MEG + LEN_DATA_INFO_SIG; xx++)
        {
                printf("%.2x ", *((unsigned char*)&g_data_request+xx-1));
                if (xx%16 == 0)
                {
                        printf("\n");
                }
        }
        printf("\n");
#endif

	//calculate SHA256 for compare
	if (calculate_sha((unsigned char*)&g_data_request, LEN_DATA_INFO_MEG, (unsigned char*)&info_digest))
	{
		//fail
	}

	//catch signature and transder to ECDSA_SIG format
	unsigned char* der_sig = NULL;
	der_sig = (unsigned char*)malloc(LEN_DATA_INFO_SIG);
	memcpy(der_sig, &g_data_request.signature, LEN_DATA_INFO_SIG);

	sig = (ECDSA_SIG *)d2i_ECDSA_SIG(&sig, (const unsigned char**)&der_sig, LEN_DATA_INFO_SIG);
        printf("Transfer SIG to DER format:(trans %s!!)\n", sig == NULL? "FAIL":"PASS");

	//read public key
	printf("Read public key form hard code.\n");
	ec_pubkey = ARRAY_read_ECPublicKey(pem_pubkey, &ec_pubkey, NULL, NULL);
	printf("Transfer public key to EC_KEY format.\n");

	//do verify
	ret = ECDSA_do_verify((const unsigned char *)&info_digest, sizeof(info_digest), sig, ec_pubkey);
	if (ret == 1)
		printf("Finish to verify, Valid Sig!!!\n");
	else if (ret == 0)
		printf("Finish to verify, Invalid Sig!!!\n");
	else
		printf("Failed to verify!!!\n");

return 0;
}

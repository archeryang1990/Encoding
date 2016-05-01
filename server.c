/* ECDSA-256/SHA256, secp256r1
 * 
 * This sample is for generate a signature, it's "Server Side".
 *
 * Generate a signature
 * 1. Openssl command to generate key pair:
 *    -Private Key: openssl ecparam -genkey -name secp256k1 -noout -out myprivatekey.pem
 *    -Public Key: openssl ec -in myprivatekey.pem -pubout -out mypubkey.pem
 * 2. Read data_info and fill in structure
 * 3. Generate a digest from soruce data with SHA256(digest = 32 bytes)
 * 4. Encode digest with ECDSA-256(secp256r1) with private key to ECDSA_SIG format signature
      and try to transfer signature raw BN big number, r and s, to readable format(string and hex), it's 64 bytes each one
 * 5. Transfer signature format to DER(DER sig = 70~72 bytes)
 * 6. Create a binary to store data_info and append signature(DER format) on tail
 *
 * Note. Openssl commands:
 *    -PEM convert to DER: openssl ec -inform DER -in xxx.der -outform PEM xxx.pem
 *    -DER convert to PEM: openssl ec -inform PEM -in xxx.pem -outform DER xxx.der
 *    -Parse private key to hex: openssl asn1parse -i -in xxx.pem
 *    -Build command: gcc -o server -lssl -lcrypto -std=c99 server.c
 *    -Exe command: ./server test_token.bin
 *
 *Version History:
 **-------------------------------------------------------------------------------------------------------------------
 **| Update Data | Who   | Version | Symptom
 **-------------------------------------------------------------------------------------------------------------------
 **| Apr.02 2016 | Syuan | 1.0     | Implement Encode tool with ECDSA algo.
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

#define LEN_DATA_INFO_MEG 125
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
	char signature[72];
}DATA_INFO;

DATA_INFO g_data_request;

unsigned char* pem_prikey = "-----BEGIN EC PRIVATE KEY-----\n"
                            "MHQCAQEEIC4hIfr/sFZPkqfytHtzLDx6H2A8iJNmEfgLVQ3qzOj+oAcGBSuBBAAK\n"
                            "oUQDQgAEOJmY+4XzBab/9y/3zZqZNCthLWDJZNlOcq/d/UziKG/4+potphoqzrH2\n"
                            "6OS3ssydAcmzZLhyRw8/5xl7ATbC7A==\n"
                            "-----END EC PRIVATE KEY-----\n";

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
}

static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey)
{
        EC_KEY *dtmp = NULL;
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

EVP_PKEY *ARRAY_read_PrivateKey(unsigned char* pemkey, EVP_PKEY **x, pem_password_cb *cb,
                                                                void *u)
{
        BIO *b = NULL;
        EVP_PKEY *ret = NULL;

        if ((b=BIO_new_mem_buf(pemkey, -1)) == NULL)
        {
                printf("%s(%d): Failed.\n", __func__, __LINE__);
                return 0;
        }

        ret=PEM_read_bio_PrivateKey(b,x,cb,u);
        BIO_free(b);
return ret;
}

EC_KEY *ARRAY_read_ECPrivateKey(unsigned char* pemkey, EC_KEY **eckey, pem_password_cb *cb,
                                                                void *u)
{
        EVP_PKEY *pktmp = NULL;
        pktmp = ARRAY_read_PrivateKey(pemkey, NULL, cb, u);
        return pkey_get_eckey(pktmp, eckey);    /* will free pktmp */
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

int main(int argc, char *argv[])
{
	EC_KEY* ec_prikey = EC_KEY_new();
	ECDSA_SIG *sig = NULL;
	char* sig_r = NULL;
	char* sig_s = NULL;
	char info_digest[32] = {0};
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

	char* tmp_buf = (char*)malloc(LEN_DATA_INFO_MEG);
	ret = fread(tmp_buf, 1, LEN_DATA_INFO_MEG, src_fp);
	if (ret != LEN_DATA_INFO_MEG)
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
	printf("[Read] Unlock Info:\n");
	for (int xx=1; xx<=LEN_DATA_INFO_MEG; xx++)
	{
		printf("%.2x ", *((char*)&g_data_request+xx-1));
		if (xx%16 == 0)
		{
			printf("\n");
		}
	}
	printf("\n");
#endif

	//calculate 64 byte hex as sha256
	if (calculate_sha((unsigned char*)&g_data_request, LEN_DATA_INFO_MEG, (unsigned char*)&info_digest))
	{
		goto __END;
	}

	// read private key
        printf("Read private key form hard code.\n");
        ec_prikey = ARRAY_read_ECPrivateKey(pem_prikey, &ec_prikey, NULL, NULL);
        printf("Transfer private key to EC_KEY format.\n");

        //do sign
        sig = ECDSA_do_sign((unsigned char*)&info_digest, sizeof(info_digest), ec_prikey);
        if (sig == NULL)
        {
                printf("Failed to sign\n");
		goto __END;
        }
        printf("Finish to sign!!!\n\n");

        // transfer SIG BN to readable string and hex format
        sig_r = BN_bn2hex(sig->r);
        if (sig_r == NULL)
        {
                printf("Transfer BN to HEX failed: ECDSA_SIG->r\n");
		goto __END;
        }
        else
        {
                printf("Transfer BN to HEX passed: ECDSA_SIG->r\n");
                printf("ECDSA_SIG->r(string): %s\n", sig_r);
                printf("ECDSA_SIG->r(hex):\n");
                for (int ii=1;ii<=64;ii++)
                {
                        printf("%.2x ", *(sig_r+ii-1));
                        if (ii%16 == 0)
                        {
                                printf("\n");
                        }
                }
                printf("\n");
        }
        sig_s = BN_bn2hex(sig->s);
        if (sig_s == NULL)
        {
                printf("Transfer BN to HEX failed: ECDSA_SIG->s\n");
		goto __END;
        }
        else
        {
                printf("Transfer BN to HEX passed: ECDSA_SIG->s\n");
                printf("ECDSA_SIG->s(string): %s\n", sig_s);
                printf("ECDSA_SIG->s(hex):\n");
                for (int ii=1;ii<=64;ii++)
                {
                        printf("%.2x ", *(sig_s+ii-1));
                        if (ii%16 == 0)
                        {
                                printf("\n");
                        }
                }
                printf("\n");
        }

	// transfer SIG to DER format
        int der_sig_len = i2d_ECDSA_SIG(sig, NULL);
	unsigned char* der_sig = NULL;

        i2d_ECDSA_SIG(sig, &der_sig);

        printf("Transfer SIG to DER format:(len %d bytes)\n", der_sig_len);
#if TEST
        for (int ii=1;ii<=der_sig_len;ii++)
        {
                printf("%.2x ", *(der_sig+ii-1));
                if (ii%16 == 0)
                {
                        printf("\n");
                }
        }
        printf("\n");
#endif

	//create a data_token and append hash to tail of data
	FILE* token_fp = fopen("appeded_sig_token.bin", "wb");
	ret = fwrite(&g_data_request, 1, LEN_DATA_INFO_MEG, token_fp);
	if (ret != LEN_DATA_INFO_MEG)
	{
		printf("***Write failed token(msg part) size(%d)***\n", ret);
		fclose(token_fp);
		return 0;	
	}

	fseek(token_fp, 0, SEEK_END);
	ret = fwrite(der_sig, 1, der_sig_len, token_fp);
	if (ret != der_sig_len)
	{
		printf("***Write failed token(sig part) size(%d)***\n", ret);
		fclose(token_fp);
		return 0;
	}
	fclose(token_fp);
	printf("\nFinished to create a data_token(appeded_sig_token.bin) and append signature on the tail.\n", ret);
__END:
	EC_KEY_free(ec_prikey);
	ECDSA_SIG_free(sig);
	free(sig_r);
	free(sig_s);
return 0;
}

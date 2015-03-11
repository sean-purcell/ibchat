#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/bignum.h>

#include "keyfile.h"

#define ERR(str) fprintf(stderr, str);

int cmp_pub_key(RSA_PUBLIC_KEY *pkey1, RSA_PUBLIC_KEY *pkey2) {
	int ret = 0;
	ret |= pkey1->bits - pkey2->bits;
	ret |= pkey1->e - pkey2->e;
	ret |= bno_cmp(&pkey1->n, &pkey2->n);

	return ret;
}

int cmp_pri_key(RSA_KEY *pkey1, RSA_KEY *pkey2) {
	int ret = 0;
	ret |= pkey1->bits - pkey2->bits;
	ret |= pkey1->e - pkey2->e;
	ret |= bno_cmp(&pkey1->n, &pkey2->n);
	ret |= bno_cmp(&pkey1->d, &pkey2->d);
	ret |= bno_cmp(&pkey1->p, &pkey2->p);
	ret |= bno_cmp(&pkey1->q, &pkey2->q);

	return ret;
}

void keyfile_err(int ret) {
	switch(ret) {
	case MEM_FAIL:
		ERR("failed to allocate memory\n");
		break;
	case CRYPTOGRAPHY_FAIL:
		ERR("a cryptography error occurred\n");
		break;
	case OPEN_FAIL:
		ERR("failed to open file\n");
		break;
	case WRITE_FAIL:
		ERR("failed to write to file\n");
		break;
	case READ_FAIL:
		ERR("failed to read from file\n");
		break;
	case INVALID_FILE:
		ERR("keyfile invalid\n");
		break;
	case INVALID_MAC:
		ERR("invalid password or keyfile\n");
		break;
	}
}

int main(int argc, char **argv) {
	RSA_KEY key;
	RSA_PUBLIC_KEY pkey;

	RSA_KEY key_file;
	RSA_PUBLIC_KEY pkey_file;

	char *password = "passwordPASSWORDpassword";

	char filename[] = "/tmp/ibchat-keyfiletestXXXXXX";

	int ret;

	/* create a file name */
	if((ret = mkstemp(filename)) == -1) {	
		ERR("failed to make temporary filename\n");
		goto err1;
	}

	close(ret);

	if(rsa_gen_key(&key, 2048, 65537) != 0) {
		ERR("failed to generate RSA key\n");
		goto err2;
	}
	if(rsa_pub_key(&key, &pkey) != 0) {
		goto err3;
	}

	/* test the public key first */
	if((ret = write_pub_key(&pkey, filename)) != 0) {
		keyfile_err(ret);
		goto err4;
	}

	if((ret = read_pub_key(filename, &pkey_file)) != 0) {
		keyfile_err(ret);
		goto err5;
	}

	if(cmp_pub_key(&pkey, &pkey_file) != 0) {
		ERR("public keys don't match\n");
		goto err6;
	}

	if(rsa_free_pubkey(&pkey_file) != 0) {
		ERR("failed to free file public key\n");
		goto err7;
	}

	if((ret = write_pri_key(&key, filename, NULL)) != 0) {
		keyfile_err(ret);
		goto err8;
	}

	if((ret = read_pri_key(filename, &key_file, NULL)) != 0) {
		keyfile_err(ret);
		goto err9;
	}

	if(cmp_pri_key(&key, &key_file) != 0) {
		ERR("password-less private keys don't match\n");
		goto err10;
	}

	if(rsa_free_prikey(&key_file) != 0) {
		ERR("failed to free file private key\n");
		goto err11;
	}

	if((ret = write_pri_key(&key, filename, password)) != 0) {
		keyfile_err(ret);
		goto err12;
	}

	if((ret = read_pri_key(filename, &key_file, password)) != 0) {
		keyfile_err(ret);
		goto err13;
	}

	if(cmp_pri_key(&key, &key_file) != 0) {
		ERR("password protected private keys don't match\n");
		goto err14;
	}

	if(rsa_free_prikey(&key_file) != 0) {
		ERR("failed to free file private key\n");
		goto err15;
	}

	if(rsa_free_pubkey(&pkey) != 0) {
		ERR("failed to free public key\n");
		goto err16;
	}

	if(rsa_free_prikey(&key) != 0) {
		ERR("failed to free private key\n");
		goto err17;
	}

	if(remove(filename) != 0) {
		ERR("failed to delete temporary file\n");
		goto err18;
	}

	printf("tests successfully completed\n");

	return 0;

err18:
err17:
err16:
err15:
	goto err13;
err14:
	rsa_free_prikey(&key_file);
err13:
err12:
err11:
	goto err9;
err10:
	rsa_free_prikey(&key_file);
err9:
err8:
err7:
err6:
err5:
err4:
	remove(filename);
	rsa_free_pubkey(&pkey);
err3:
	rsa_free_prikey(&key);
err2:
err1:
	return 1;
}


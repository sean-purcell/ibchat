#include <ibcrypt/rand.h>

#include "login.h"

int gen_login_data(struct login_data *data) {
	if(cs_rand(data->symm_seed, 32) != 0) {
		return 1;
	}
	if(cs_rand(data->hmac_seed, 32) != 0) {
		return 1;
	}
	if(rsa_gen_key(&data->id, 2048, 65537) != 0) {
		return 1;
	}

	return 0;
}


/*
 * pam_multipass
 *
 * Author: Alex Osborne 2012
 * License: 2-clause BSD.  See LICENSE.txt for details.
 *
 * -*- mode: C; c-basic-offset: 4; -*- 
 */
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <assert.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "crypt_blowfish.h"
#include "pam_multipass.h"

#define BCRYPT_HASHSIZE	64

#define UNUSED __attribute__((unused))

json_object *pam_multipass_read_hashes(const char *user)
{
    static const char *hashes_filename = "/.multipass/hashes.json";
    json_object *hashes = NULL;

    int home_len = 0;
    struct passwd *pw = getpwnam(user);
    if (pw != NULL && pw->pw_dir != NULL) {
	home_len = strlen(pw->pw_dir);
    }

    if (home_len == 0) {
	/* fprintf(stderr, "pam_multipass: user has no home directory:
	   %s\n", user); */
	return NULL;
    }

    char *hashes_file = malloc(home_len + strlen(hashes_filename) + 1);
    if (hashes_file == NULL) return NULL;

    memcpy(hashes_file, pw->pw_dir, home_len);
    memcpy(hashes_file + home_len, hashes_filename, strlen(hashes_filename) + 1);

    hashes = json_object_from_file((char *)hashes_file);

    if (hashes == NULL) {
	fprintf(stderr, "pam_multipass: error parsing %s\n", hashes_file);
	goto out;
    }

    if (hashes == error_ptr(-1)) { /* unable to read */
	hashes = NULL;
	goto out;
    }

    if (!json_object_is_type(hashes, json_type_object)) {
	fprintf(stderr, "pam_multipass: %s must be a JSON object like \"{}\"\n", hashes_file);
	hashes = NULL;
	goto out;
    }

 out:
    free(hashes_file);
    return hashes;
}

static int check_password(const char *password, const char *hash)
{
    char hash2[BCRYPT_HASHSIZE];
    if (hash == NULL || strlen(hash) < 4) {
	return PAM_AUTH_ERR; /* invalid hash */
    }
    _crypt_blowfish_rn(password, hash, hash2, BCRYPT_HASHSIZE);
    if (strcmp(hash, hash2) == 0) {
	return PAM_SUCCESS;
    } else {
	return PAM_AUTH_ERR;
    }
}

int pam_multipass_authenticate(json_object *hashes, const char *password)
{
    int ret = PAM_AUTH_ERR;
    json_object_object_foreach(hashes, name, obj) {
	const char *hash = json_object_get_string(json_object_object_get(obj, "hash"));
	if (hash == NULL) {
	    fprintf(stderr, "pam_multipass: no hash defined for %s\n", name);
	}
	ret = check_password(password, hash);
	if (ret == 0) break;
    }
    return ret;
}

static int prompt_password(pam_handle_t *pamh, const char **password)
{
    int ret;
    const struct pam_conv *conv;
    ret = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
    if (ret != PAM_SUCCESS) return ret;

    const struct pam_message *pmsg[1];
    struct pam_message msg[1];
    msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
    msg[0].msg = "Multipass: ";
    pmsg[0] = &msg[0];

    struct pam_response *resp = NULL;
    ret = conv->conv(1, pmsg, &resp, conv->appdata_ptr);
    if (ret != PAM_SUCCESS) return ret;
    *password = resp->resp;
    free(resp);
    return PAM_SUCCESS;
}

static int count_hashes_for_service(json_object *hashes, const char *service) {
    int count = 0;
    json_object_object_foreach(hashes, name, obj) {
	json_object *svc_array = json_object_object_get(obj, "services");
	if (svc_array == NULL) {
	    fprintf(stderr, "pam_multipass: warning: services array missing for %s\n", name);	    
	}
	int len = json_object_array_length(svc_array);
	for (int i = 0; i < len; i++) {
	    json_object *svc_obj = json_object_array_get_idx(svc_array, i);
	    const char *svc = json_object_get_string(svc_obj);
	    if (service != NULL && (strcmp(svc, service) == 0 ||
				    strcmp(svc, "all") == 0)) {
		count++;
		break;
	    }	    
	}
    }
    return count;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, UNUSED int flags, UNUSED int argc, UNUSED const char **argv) {
    const char *user, *password, *service;
    int ret;

    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS) return ret;

    /*
     * First, we do nothing unless user has a valid hashes.json.
     */
    json_object *hashes = pam_multipass_read_hashes(user);
    if (hashes == NULL) {
	return PAM_USER_UNKNOWN;
    }

    /*
     * Second, make sure they've defined at least one hash for this
     * service.
     */
    ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
    if (ret != PAM_SUCCESS) return ret;
    if (count_hashes_for_service(hashes, service) == 0) {
	ret = PAM_USER_UNKNOWN;
	goto out;
    }

    /*
     * Alrighty, let's get us a password.
     */
    ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &password);
    if (ret != PAM_SUCCESS) return ret;
    if (password == NULL) {
	ret = prompt_password(pamh, &password);
	if (ret != PAM_SUCCESS) return ret;
	pam_set_item (pamh, PAM_AUTHTOK, password);
    }

    /*
     * Validate the password.
     */
    ret = pam_multipass_authenticate(hashes, password);

 out:
    json_object_put(hashes); /* free ref */
    return ret;
}

PAM_EXTERN
int pam_sm_setcred(UNUSED pam_handle_t *pamh, UNUSED int flags,
		   UNUSED int argc, UNUSED const char **argv)
{
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_rootok_modstruct = {
    "pam_multipass",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};

#endif

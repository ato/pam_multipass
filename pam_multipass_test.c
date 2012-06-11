/* -*- mode: C; c-basic-offset: 4; -*- */
#include <stdlib.h>
#include <stdio.h>
#include "pam_multipass.h"

int main(void)
{
    const char *user = getenv("LOGNAME");
    json_object *hashes = pam_multipass_read_hashes(user);
    json_object_object_foreach(hashes, name, obj) {
	const char *hash = json_object_get_string(json_object_object_get(obj, "hash"));
	printf("%s: %s\n", name, hash);
    }
    pam_multipass_authenticate(hashes, "a");
    json_object_put(hashes); /* free ref */
}

#include <json.h>

json_object *pam_multipass_read_hashes(const char *user);
int pam_multipass_authenticate(json_object *hashes, const char *password);

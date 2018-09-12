/*
 * TODO licence
 */

#include "kadmin_locl.h"
#include "kadmin-commands.h"

int
prune(void *opt, int argc, char **argv)
{
    krb5_error_code ret = 0;
    char *princ_name = NULL;
    krb5_principal princ_ent = NULL;
    int prunekvno = -1;

    princ_name = argv[0];
    prunekvno = atoi(argv[1]);

    ret = krb5_parse_name(context, princ_name, &princ_ent);
    if (ret) {
        krb5_warn(context, ret, "krb5_parse_name %s", princ_name);
        goto out2;
    }

    ret = kadm5_prune_principal(kadm_handle, princ_ent, prunekvno);
    if (ret)
        krb5_warn(context, ret, "kadm5_prune_principal");

out2:
    return ret != 0;
}

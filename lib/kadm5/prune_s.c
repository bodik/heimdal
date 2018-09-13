/*
 * TODO licence
 */

#include "kadm5_locl.h"

RCSID("$Id$");

static kadm5_ret_t
prune_principal(void *server_handle,
                krb5_principal princ,
                int prunekvno)
{
    kadm5_server_context *context = server_handle;
    hdb_entry_ex ent;
    kadm5_ret_t ret;

    memset(&ent, 0, sizeof(ent));
    if (!context->keep_open) {
        ret = context->db->hdb_open(context->context, context->db, O_RDWR, 0);
        if(ret)
            return ret;
    }

    ret = kadm5_log_init(context);
    if (ret)
        goto out;

    ret = context->db->hdb_fetch_kvno(context->context, context->db, princ,
                                      HDB_F_GET_ANY|HDB_F_ADMIN_DATA, 0, &ent);
    if (ret)
        goto out2;

    ret = hdb_prune_keys_kvno(context->context, &ent.entry, prunekvno);
    if (ret)
        goto out3;

    ret = hdb_seal_keys(context->context, context->db, &ent.entry);
    if (ret)
        goto out3;

    ret = kadm5_log_modify(context, &ent.entry, KADM5_KEY_DATA);

out3:
    hdb_free_entry(context->context, &ent);
out2:
    (void) kadm5_log_end(context);
out:
    if (!context->keep_open) {
        kadm5_ret_t ret2;
        ret2 = context->db->hdb_close(context->context, context->db);
        if (ret == 0 && ret2 != 0)
            ret = ret2;
    }
    return _kadm5_error_code(ret);
}


kadm5_ret_t
kadm5_s_prune_principal(void *server_handle,
                        krb5_principal princ,
                        int prunekvno)
{
    return prune_principal(server_handle, princ, prunekvno);
}

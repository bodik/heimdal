/*
 * TODO licence
 */

#include "kadm5_locl.h"

RCSID("$Id$");

kadm5_ret_t
kadm5_c_prune_principal(void *server_handle, krb5_principal princ, int prunekvno)
{
    kadm5_client_context *context = server_handle;
    kadm5_ret_t ret;
    krb5_storage *sp;
    unsigned char buf[1024];
    int32_t tmp;
    krb5_data reply;

    ret = _kadm5_connect(server_handle);
    if(ret)
        return ret;

    sp = krb5_storage_from_mem(buf, sizeof(buf));
    if (sp == NULL) {
        krb5_clear_error_message(context->context);
        return ENOMEM;
    }
    krb5_store_int32(sp, kadm_prune);
    krb5_store_principal(sp, princ);
    krb5_store_int32(sp, prunekvno);
    ret = _kadm5_client_send(context, sp);
    krb5_storage_free(sp);
    if (ret)
        return ret;
    ret = _kadm5_client_recv(context, &reply);
    if (ret)
        return ret;
    sp = krb5_storage_from_data(&reply);
    if(sp == NULL) {
        krb5_clear_error_message(context->context);
        krb5_data_free(&reply);
        return ENOMEM;
    }
    krb5_ret_int32(sp, &tmp);
    krb5_clear_error_message(context->context);
    krb5_storage_free(sp);
    krb5_data_free (&reply);
    return tmp;
}


#include "ftp_locl.h"

#include <des.h>
#include <krb.h>

KTEXT_ST krb4_adat;

static des_cblock key;
static des_key_schedule schedule;

static char *data_buffer;

enum { prot_clear, prot_safe, prot_confidential, prot_private };

extern struct sockaddr_in hisctladdr, myctladdr;

int auth_complete;

static int command_prot;

static int auth_pbsz;
static int data_prot;


static struct {
    int level;
    char *name;
} level_names[] = {
    { prot_clear, "clear" },
    { prot_safe, "safe" },
    { prot_confidential, "confidential" },
    { prot_private, "private" }
};

static char *level_to_name(int level)
{
    int i;
    for(i = 0; i < sizeof(level_names) / sizeof(level_names[0]); i++)
	if(level_names[i].level == level)
	    return level_names[i].name;
    return "unknown";
}

static int name_to_level(char *name)
{
    int i;
    for(i = 0; i < sizeof(level_names) / sizeof(level_names[0]); i++)
	if(!strncasecmp(level_names[i].name, name, strlen(name)))
	    return level_names[i].level;
    return -1;
}

void sec_status(void)
{
    if(auth_complete){
	printf("Using KERBEROS_V4 for authentication.\n");

	command_prot = prot_private; /* this variable is not used */

	printf("Using %s command channel.\n", 
	       level_to_name(command_prot));

	printf("Using %s data channel.\n", 
	       level_to_name(data_prot));
	if(auth_pbsz > 0)
	    printf("Protection buffer size: %d.\n", auth_pbsz);
    }else{
	printf("Not using any security mechanism.\n");
    }
}

void sec_prot(int argc, char **argv)
{
    int s;
    int ret;
    char *p;
    int level = -1;
    if(argc != 2){
	fprintf(stderr,
		"usage: %s (clear | safe | confidential | private)\n",
		argv[0]);
	code = -1;
	return;
    }
    if(!auth_complete){
	fprintf(stderr, "ehu?\n");
	code = -1;
	return;
    }
    level = name_to_level(argv[1]);
    
    if(level == prot_confidential){
	printf("Confidential protection is not defined for Kerberos.\n");
	code = -1;
	return;
    }

    if(level == -1){
	fprintf(stderr,
		"usage: %s (clear | safe | confidential | private)\n",
		argv[0]);
	code = -1;
	return;
    }
    if(level){
	s = 65536;
	ret = command("PBSZ %d", s);
	if(ret != COMPLETE){
	    fprintf(stderr, "Ehu?\n");
	    code = -1;
	    return;
	}
	auth_pbsz = s;
	p = strstr(reply_string, "PBSZ=");
	if(p)
	    sscanf(p, "PBSZ=%d", &s);
	if(s < auth_pbsz)
	    auth_pbsz = s;
	if(data_buffer)
	    free(data_buffer);
	data_buffer = malloc(auth_pbsz);
    }
    
    ret = command("PROT %c", level["CSEP"]); /* XXX :-) */
    if(ret != COMPLETE){
	fprintf(stderr, "Ehu ?\n");
	code = -1;
	return;
    }
    data_prot = level;
    code = 0;
}


int sec_getc(FILE *F)
{
    if(auth_complete && data_prot)
	return krb4_getc(F);
    else
	return getc(F);
}

int sec_read(int fd, void *data, int length)
{
    if(auth_complete && data_prot)
	return krb4_read(fd, data, length);
    else
	return read(fd, data, length);
}

static int
krb4_recv(int fd)
{
    int len;
    MSG_DAT m;
    int kerror;
    
    krb_net_read(fd, &len, sizeof(len));
    len = ntohl(len);
    krb_net_read(fd, data_buffer, len);
    if(data_prot == prot_safe)
	kerror = krb_rd_safe(data_buffer, len, &key, 
			     &hisctladdr, &myctladdr, &m);
    else
	kerror = krb_rd_priv(data_buffer, len, schedule, &key, 
			     &hisctladdr, &myctladdr, &m);
    if(kerror){
	return -1;
    }
    memmove(data_buffer, m.app_data, m.app_length);
    return m.app_length;
}


int krb4_getc(FILE *F)
{
    static int bytes;
    static int index;
    if(bytes == 0){
	bytes = krb4_recv(fileno(F));
	index = 0;
    }
    if(bytes){
	bytes--;
	return data_buffer[index++];
    }
    return EOF;
}

int krb4_read(int fd, char *data, int length)
{
    static int left;
    static int index;
    static int eof;
    int len = left;
    int rx = 0;

    if(eof){
	eof = 0;
	return 0;
    }
    
    if(left){
	if(length < len)
	    len = length;
	memmove(data, data_buffer + index, len);
	length -= len;
	index += len;
	rx += len;
	left -= len;
    }
    
    while(length){
	len = krb4_recv(fd);
	if(len == 0){
	    if(rx)
		eof = 1;
	    return rx;
	}
	if(len > length){
	    left = len - length;
	    len = index = length;
	}
	memmove(data, data_buffer, len);
	length -= len;
	data += len;
	rx += len;
    }
    return rx;
}


static int
krb4_encode(char *from, char *to, int length)
{
    if(data_prot == prot_safe)
	return krb_mk_safe(from, to, length, &key, 
			   &myctladdr, &hisctladdr);
    else
	return krb_mk_priv(from, to, length, schedule, &key, 
			   &myctladdr, &hisctladdr);
}

static int
krb4_overhead(int len)
{
    if(data_prot == prot_safe)
	return 31;
    else
	return 26;
}

static char p_buf[1024];
static int p_index;

int
sec_putc(int c, FILE *F)
{
    if(data_prot){
	if((c == '\n' && p_index) || p_index == sizeof(p_buf)){
	    sec_write(fileno(F), p_buf, p_index);
	    p_index = 0;
	}
	p_buf[p_index++] = c;
	return c;
    }
    return putc(c, F);
}

static int
sec_send(int fd, char *from, int length)
{
    int bytes;
    bytes = krb4_encode(from, data_buffer, length);
    bytes = htonl(bytes);
    krb_net_write(fd, &bytes, sizeof(bytes));
    krb_net_write(fd, data_buffer, ntohl(bytes));
    return length;
}

int
sec_fflush(FILE *F)
{
    if(data_prot){
	if(p_index){
	    sec_write(fileno(F), p_buf, p_index);
	    p_index = 0;
	}
	sec_send(fileno(F), NULL, 0);
    }
    fflush(F);
    return 0;
}

int
sec_write(int fd, char *data, int length)
{
    int len = auth_pbsz;
    int tx = 0;
    int bytes;
      
    if(data_prot == prot_clear)
	return write(fd, data, length);

    len -= krb4_overhead(len);
    while(length){
	if(length < len)
	    len = length;
	sec_send(fd, data, len);
	length -= len;
	data += len;
	tx += len;
    }
    return tx;
}

static int
do_auth(char *service, char *host, int checksum)
{
    int ret;
    CREDENTIALS cred;
    char sname[SNAME_SZ], inst[INST_SZ], realm[REALM_SZ];
    strcpy(sname, service);
    strcpy(inst, krb_get_phost(host));
    strcpy(realm, krb_realmofhost(host));
    ret = krb_mk_req(&krb4_adat, sname, inst, realm, checksum);
    if(ret)
	return ret;
    strcpy(sname, service);
    strcpy(inst, krb_get_phost(host));
    strcpy(realm, krb_realmofhost(host));
    ret = krb_get_cred(sname, inst, realm, &cred);
    memmove(&key, &cred.session, sizeof(des_cblock));
    des_key_sched(&key, schedule);
    memset(&cred, 0, sizeof(cred));
    return ret;
}


int
do_klogin(char *host)
{
    int ret;
    char *phost;
    char *p, *q;
    int len;
    char adat[1024];
    MSG_DAT msg_data;
    int checksum;
    int tmp;

    int old_verbose = verbose;

    verbose = 0;
    printf("Trying KERBEROS_V4...\n");
    ret = command("AUTH KERBEROS_V4");
    if(ret != CONTINUE){
	if(code == 504){
	    fprintf(stderr, "Kerberos is not supported by the server.\n");
	}else if(code == 534){
	    fprintf(stderr, "KERBEROS_V4 rejected as security mechanism.\n");
	}else if(ret == ERROR)
	    fprintf(stderr, "The server doesn't understand the FTP "
		    "security extentions.\n");
	verbose = old_verbose;
	return -1;
    }

    checksum = getpid();
    ret = do_auth("ftp", host, checksum);
    if(ret == KDC_PR_UNKNOWN)
	ret = do_auth("rcmd", host, checksum);
    if(ret){
	fprintf(stderr, "%s\n", krb_get_err_text(ret));
	verbose = old_verbose;
	return ret;
    }

    base64_encode(krb4_adat.dat, krb4_adat.length, &p);
    ret = command("ADAT %s", p);
    free(p);

    if(ret != COMPLETE){
	fprintf(stderr, "Server didn't accept auth data.");
	verbose = old_verbose;
	return -1;
    }

    p = strstr(reply_string, "ADAT=");
    if(!p){
	fprintf(stderr, "Remote host didn't send adat reply.");
	verbose = old_verbose;
	return -1;
    }
    p+=5;
    len = base64_decode(p, adat);
    if(len < 0){
	fprintf(stderr, "Failed to decode base64 from server.");
	verbose = old_verbose;
	return -1;
    }
    ret = krb_rd_safe(adat, len, &key, 
		      &hisctladdr, &myctladdr, &msg_data);
    if(ret){
	fprintf(stderr, "Error reading reply from server: %s.", 
	      krb_get_err_text(ret));
	verbose = old_verbose;
	return -1;
    }
    memmove(&tmp, msg_data.app_data, 4);
    tmp = ntohl(tmp);
    if(tmp - checksum != 1){
	fprintf(stderr, "Bad checksum returned from server.");
	verbose = old_verbose;
	return -1;
    }
    auth_complete = 1;
    verbose = old_verbose;
    return 0;
}

int krb4_write_enc(FILE *F, char *fmt, va_list ap)
{
    int len;
    char *p;
    char buf[1024];
    char enc[1024];
    vsprintf(buf, fmt, ap);
    len = krb_mk_priv(buf, enc, strlen(buf), schedule, &key, 
		      &myctladdr, &hisctladdr);
    base64_encode(enc, len, &p);

    fprintf(F, "ENC %s", p);
    return 0;
}


int krb4_read_msg(char *s, int priv)
{
    int len;
    int ret;
    char buf[1024];
    MSG_DAT m;
    int code;
    
    len = base64_decode(s + 4, buf);
    if(priv)
	ret = krb_rd_priv(buf, len, schedule, &key, 
			  &hisctladdr, &myctladdr, &m);
    else
	ret = krb_rd_safe(buf, len, &key, &myctladdr, &hisctladdr, &m);
    if(ret){
      fprintf(stderr, "%s\n", krb_get_err_text(ret));
      return -1;
    }
	
    m.app_data[m.app_length] = 0;
    if(m.app_data[3] == '-')
      code = 0;
    else
      sscanf((char*)m.app_data, "%d", &code);
    strncpy(s, (char*)m.app_data, strlen((char*)m.app_data));
    
    s[m.app_length] = 0;
    len = strlen(s);
    if(s[len-1] == '\n')
	s[len-1] = 0;
    
    return code;
}

int
krb4_read_mic(char *s)
{
    return krb4_read_msg(s, 0);
}

int
krb4_read_enc(char *s)
{
    return krb4_read_msg(s, 1);
}


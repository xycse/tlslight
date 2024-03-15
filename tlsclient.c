#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <regex.h>
#include <libgen.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/x509v3.h>
#include <assert.h>

static void print_ssl_error(char *errctx)
{
	unsigned long error;
	while ((error = ERR_get_error()))
		printf("%s: %s\n", errctx, ERR_error_string(error, NULL));
}

char *getcertsubject(X509* cert)
{
	X509_NAME *name = X509_get_subject_name(cert);
	if (!name)
	{
		printf("error getting cert subject name\n");
		return NULL;
	}
	BIO *bio = NULL;
	char *buf = NULL;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
	{
		printf("error getting bio\n");
		return NULL;
	}
	X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
	buf = malloc(BIO_number_written(bio) + 1);
	if (buf)
	{
		BIO_read(bio, buf, BIO_number_written(bio));
		buf[BIO_number_written(bio)] = '\0';
	}
	BIO_free(bio);
	return buf;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
	char *buf = NULL;
	X509 *err_cert = NULL;
	int err, depth;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);
	if (!ok && err_cert)
	{
		printf("verify cb: failed\n");
	}
	ok = 1;
	/* verify cert depth .. not doing right now 
	 *
	 *
	 if (depth > MAX_CERT_DEPTH) {
        ok = 0;
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err);
    }

	 *
	 *
	 *
	 * */
	
	/* returning 1 without doing error handling */
	return ok;
}

static int cookie_generate_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	return 1;
}

static int cookie_verify_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	return 1;
}

static int tls_ca_update(SSL_CTX *ctx)
{
	STACK_OF(X509_NAME) *calist;
	X509_STORE *x509_s;
	unsigned long error;
	char *cafile = "/home/ubuntu/openssl_remote/public_ip/ca.crt";
	SSL_CTX_set_cert_store(ctx, X509_STORE_new());
	if (!SSL_CTX_load_verify_locations(ctx, cafile, "/etc/ssl/certs"))
	{
		while ((error = ERR_get_error()))
			printf("ssl ca error: %s\n", ERR_error_string(error, NULL));
		printf("Error updating tls context\n");
		return 1;
	}
	calist = SSL_load_client_CA_file(cafile);
	if (!calist)
	{
		print_ssl_error("error getting calist");	
		return 1;
	}
	ERR_clear_error();
	SSL_CTX_set_client_CA_list(ctx, calist);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
	SSL_CTX_set_verify_depth(ctx, 6);
	//SSL_CTX_set_cookie_generate_cb(ctx, cookie_generate_cb);
	//SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify_cb);
	/* leave out cookie callback related code */
	return 0;
}

int main(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	OPENSSL_init_ssl(0, NULL);
	/* create tls context */
	STACK_OF(X509_NAME) *calist;
	X509_STORE *s509_s;
	unsigned long error;

	SSL_CTX *ctx = NULL;
	ctx = SSL_CTX_new(SSLv23_method());
	//SSL_CTX_set_min_proto_version(ctx, 0x10100000);
	//SSL_CTX_set_max_proto_version(ctx, 0x10100000);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	if (!ctx)
	{
		printf("Error creating tls context\n");
		return 1;
	}
	if (!SSL_CTX_use_certificate_chain_file(ctx, "/home/ubuntu/openssl_remote/public_ip/server.crt") ||
	   	!SSL_CTX_use_PrivateKey_file(ctx, "/home/ubuntu/openssl_remote/public_ip/server.key", SSL_FILETYPE_PEM) ||
		!SSL_CTX_check_private_key(ctx))
	{
		while ((error = ERR_get_error()))
			printf("err: ssl: %s\n", ERR_error_string(error, NULL));
		printf("Error initializing ssl context\n");
		SSL_CTX_free(ctx);
	}
	/* update tls context with ca cert path and cert store details */
	tls_ca_update(ctx);
	SSL *ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating ssl instance\n");
		return 1;
	}
	char *servername = "127.0.0.1";
	SSL_set_tlsext_host_name(ssl, servername);
	/* tcp connect before ssl connect */
	struct sockaddr_in tlsserver = {0};
	tlsserver.sin_family = AF_INET;
	tlsserver.sin_port = htons(1888);
	tlsserver.sin_addr.s_addr = inet_addr(servername);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
	{
		perror("socket");
		return 1;
	}
	int optind = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, &optind, sizeof(struct sockaddr_in)) < 0)
	{
		perror("setsockopt");
		return 1;
	}
	socklen_t slen = sizeof(struct sockaddr_in);
	if (connect(fd, (struct sockaddr *)&tlsserver, slen) < 0)
	{
		perror("connect");
		return 1;
	}
	printf("Connected\n");
	SSL_set_fd(ssl, fd);
	int r = SSL_connect(ssl);
	if (r <= 0)
	{
		printf("ssl connect failed\n");
		return 1;
	}
	printf("ssl connection success\n");
	/* at this point ssl connection is successfully done on the server side */
	/* from here on we verify the ssl certs sent by the server */
	/* verify tls cert */
	X509 *cert;
	error = 0;
	if (SSL_get_verify_result(ssl) != X509_V_OK)
	{
		printf("server cert verification failed\n");
		while ((error = ERR_get_error()))
				printf("error: %s", ERR_error_string(error, NULL));
		return 1;
	}
	cert = SSL_get_peer_certificate(ssl);
	if (!cert)
	{
		printf("failed to get peer certificate\n");
		return 1;
	}
	printf("cert validation success for %s\n", servername);
	/* verify tls cert ends */
	/* verify certificate for host, verify conf cert */
	char *certsubject = getcertsubject(cert);
	printf("certsubject: %s\n", certsubject);
	if (certsubject)
	{
		printf("tlsconnect: tls connection up for ssl version: %s, cipher: %s\n", 
						SSL_get_version(ssl), SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
	}
	free(certsubject);
	free(cert);
	printf("tls connection up\n");
	return 0;
}


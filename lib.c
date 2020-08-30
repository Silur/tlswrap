/* compile with
 * gcc -o libtlswrap.so tlswrap.c -ldl -lcrypto -lssl
 * Usage: LD_PRELOAD=./libtlswrap.so yourexec
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int (*accept_orig)(int socket, struct sockaddr *address, 
	socklen_t *address_len);
int (*connect_orig)(int socket, const struct sockaddr *address,
	socklen_t address_len);
ssize_t (*send_orig)(int socket, const void *buffer, size_t length, int flags);
ssize_t (*write_orig)(int fd, const void *buffer, size_t length);
ssize_t (*read_orig)(int fd, const void *buffer, size_t length);
ssize_t (*recv_orig)(int socket, const void *buffer, size_t length, int flags);
int (*close_orig)(int flides);

SSL **sessions = 0;
size_t sessions_len = 0;
size_t sessions_count = 16;
SSL_CTX *server_ctx = 0;
SSL_CTX *client_ctx = 0;
int init_done = 0;
static int read_lock = 0;
static int write_lock = 0;

static void
cleanup_openssl()
{
    EVP_cleanup();
	size_t i;
	for(i=0; i<sessions_len; i++)
		SSL_free(sessions[i]);
	if(server_ctx)
		SSL_CTX_free(server_ctx);
	if(client_ctx)
		SSL_CTX_free(client_ctx);
}

static SSL_CTX*
create_server_ctx()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
	{
        ERR_print_errors_fp(stderr);
		exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) 
	{
        ERR_print_errors_fp(stderr);
		exit(1);
    }
    return ctx;
}
static SSL_CTX*
create_client_ctx()
{
	return 0;
}
static int
get_ssl_id(int tfd)
{
	size_t i;
	for(i=0; i<sessions_count; i++)
	{
		int cfd = SSL_get_fd(sessions[i]);
		if(cfd == tfd) return i;
	}
	return -1;
}

static void
init()
{ 
    SSL_load_error_strings();
	ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();
	server_ctx = create_server_ctx();
	client_ctx = create_server_ctx();
	accept_orig = dlsym(RTLD_NEXT,"accept");
	send_orig = dlsym(RTLD_NEXT,"send");
	recv_orig = dlsym(RTLD_NEXT,"recv");
	close_orig = dlsym(RTLD_NEXT,"close");
	read_orig = dlsym(RTLD_NEXT,"read");
	write_orig = dlsym(RTLD_NEXT,"write");
	sessions_len = 16;
	sessions_count = 0;
	sessions = malloc(sessions_len*sizeof(SSL*));
}
int accept(int sock, struct sockaddr *addr, 
	socklen_t *len)
{
	if(!init_done) init();
	if(!server_ctx)
		server_ctx = create_server_ctx();
	SSL *ssl;
	int client = accept_orig(sock, (struct sockaddr*)addr, len);
	if (client < 0) 
	{
		perror("Unable to accept");
		exit(1);
	}

	ssl = SSL_new(server_ctx);
	SSL_set_fd(ssl, client);
	
	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
	}
	if(sessions_count+1 > sessions_len)
	{
		sessions = realloc(sessions, (sessions_len+16)*sizeof(SSL*));
		sessions_len+=16;
	}
	sessions[sessions_count++] = ssl;
	printf("ACCEPT client %d\n", client);
	fflush(stdout);
	return client;
}

ssize_t
send(int socket, const void *buffer, size_t length, int flags)
{
	int id = get_ssl_id(socket);
	if(id == -1)
	{
		fprintf(stderr, "SSL socket closed unexpectedly!\n");
		exit(1);
	}
	write_lock = 1;
	return SSL_write(sessions[id], buffer, length);
}

ssize_t 
write(int fd, const void *buffer, size_t length)
{
	if(write_lock)
	{
		return write_orig(fd, buffer, length);
	}
	int id = get_ssl_id(fd);
	if(id == -1) 
	{
		return write_orig(fd, buffer, length);
	}
	SSL *ssl = sessions[id];
	int ret;
	write_lock = 1;
write_again:
	ret = SSL_write(ssl, buffer, length);
	switch(SSL_get_error(ssl, ret))
	{
		case SSL_ERROR_NONE:
			read_lock = 0;
			return ret;
		case SSL_ERROR_WANT_WRITE:
			goto write_again;
	}
}


ssize_t 
recv(int socket, void *buffer, size_t length, int flags)
{
	int id = get_ssl_id(socket);
	if(id == -1)
	{
		fprintf(stderr, "SSL socket closed unexpectedly!\n");
		exit(1);
	}
	read_lock=1;
	return SSL_read(sessions[id], buffer, length);
}

ssize_t 
read(int fd, void *buffer, size_t length)
{
	if(read_lock)
	{
		return read_orig(fd, buffer, length);
	}
	int id = get_ssl_id(fd);
	if(id == -1) 
	{
		printf("calling original read\n"); fflush(stdout);
		return read_orig(fd, buffer, length);
	}
	SSL *ssl = sessions[id];
	int ret;
	read_lock = 1;
read_again:
	ret = SSL_read(ssl, buffer, length);
	switch(SSL_get_error(ssl, ret))
	{
		case SSL_ERROR_NONE:
			read_lock = 0;
			return ret;
		case SSL_ERROR_WANT_READ:
			goto read_again;
	}
}

int close(int fd)
{
	int id = get_ssl_id(fd);
	if(id == -1) return close_orig(fd);
	SSL *ssl = sessions[id];
	if(ssl) 
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	size_t i;
	for(i=id; i<sessions_count-1; i++)
	{
		sessions[i] = sessions[i+1];
	}
	sessions[id] = 0;
	sessions_count--;
	return close_orig(fd);
}

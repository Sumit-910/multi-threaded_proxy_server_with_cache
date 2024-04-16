#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>

#ifndef PROXY_PARSE
#define PROXY_PARSE
#define DEBUG 1

struct parsed_header{
    char *key;
    size_t key_len;
    char *value;
    size_t value_len;
};

struct parsed_request{
    char *method;
    char *protocol;
    char *host;
    char *port;
    char *path;
    char *version;
    char *buf;
    size_t buflen;
    struct parsed_header *headers;
    size_t headers_used;
    size_t headers_len;
};

struct parsed_request* parsed_request_create();
int parsed_request_parse(struct parsed_request *parse, const char *buf, int buflen);
void parsed_request_destroy(struct parsed_request *pr);
int parsed_request_unparse(struct parsed_request *pr, char *buf, size_t buflen);
int parsed_request_unparse_headers(struct parsed_request *pr, char *buf, size_t buflen);
size_t parsed_request_total_len(struct parsed_request *pr);
size_t parsed_header_headers_len(struct parsed_request *pr);
int parsed_header_set(struct parsed_request *pr, const char *key, const char *value);
struct parsed_header* parsed_header_get(struct parsed_request *pr, const char *key);
int parsed_header_remove(struct parsed_request *pr, const char *key);
void debug(const char *format, ...);

#endif
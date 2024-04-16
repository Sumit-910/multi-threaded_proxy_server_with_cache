#include "proxy_parse.h"

#define DEFAULT_NHDRS 8
#define MAX_REQ_LEN 65535
#define MIN_REQ_LEN 4

static const char *root_abs_path = "/";

int parsed_request_print_request_line(struct parsed_request *pr, char *buf, size_t buflen, size_t *tmp);

size_t parsed_request_line_len(struct parsed_request *pr);

void debug(const char *format, ...){
    va_list args;
    if(DEBUG){
        va_start(args,format);
        vfprintf(stderr, format, args);
        va_end(args);
    }
}

int parsed_header_set(struct parsed_request *pr, const char *key, const char *value){
    struct parsed_header *ph;
    parsed_header_remove(pr,key);

    if(pr->headers_len <= pr->headers_used+1){
        pr->headers_len = pr->headers_len*2;
        pr->headers = (struct parsed_header *)realloc(pr->headers,pr->headers_len*sizeof(struct parsed_header));

        if(!pr->headers){
            return -1;
        }
    }

    ph = pr->headers + pr->headers_used;
    pr->headers_used += 1;

    ph->key = (char *)malloc(strlen(key)+1);
    memcpy(ph->key, key, strlen(key));
    ph->key[strlen(key)] = '\0';

    ph->value = (char *)malloc(strlen(value)+1);
    memcpy(ph->value,value,strlen(value));
    ph->value[strlen(value)] = '\0';

    ph->key_len = strlen(key) + 1;
    ph->value_len = strlen(value) + 1;
    return 0;
}

struct parsed_header* parsed_header_get(struct parsed_request *pr, const char *key){
    size_t i = 0;
    struct parsed_header *tmp;

    while(pr->headers_used > 1){
        tmp = pr->headers + i;
        if(tmp->key && key && strcmp(tmp->key,key)==0){
            return tmp;
        }
        i++;
    }
    return NULL;
}

int parsed_header_remove(struct parsed_request *pr, const char *key){
    struct parsed_header *tmp;
    tmp = parsed_header_get(pr,key);
    if(tmp==NULL){
        return -1;
    }

    free(tmp->key);
    free(tmp->value);
    tmp->key = NULL;

    return 0;
}

void parsed_header_create(struct parsed_request *pr){
    pr->headers = (struct parsed_header *)malloc(sizeof(struct parsed_header)*DEFAULT_NHDRS);
    pr->headers_len = DEFAULT_NHDRS;
    pr->headers_used = 0;
}

size_t parsed_header_line_len(struct parsed_header *ph){
    if(ph->key != NULL){
        return strlen(ph->key) + strlen(ph->value) + 4;
    }
    return 0;
}

size_t parsed_header_headers_len(struct parsed_request *pr){
    if(!pr || !pr->buf){
        return 0;
    }

    size_t i = 0;
    int len = 0;
    while(i < pr->headers_used){
        len += parsed_header_line_len(pr->headers + i);
        i++;
    }
    len += 2;
    return len;
}

int parsed_header_print_headers(struct parsed_request *pr, char *buf, size_t len){
    char *current = buf;
    struct parsed_header *ph;
    size_t i = 0;

    if(len < parsed_header_headers_len(pr)){
        debug("Buffer for printing headers too small\n");
        return -1;
    }

    while(i < pr->headers_used){
        ph = pr->headers + i;
        if(ph->key){
            memcpy(current, ph->key, strlen(ph->key));
            memcpy(current+strlen(ph->key),": ",2);
            memcpy(current+strlen(ph->key)+2,ph->value,strlen(ph->value));
            memcpy(current+strlen(ph->key)+2+strlen(ph->value),"\r\n",2);
            current += strlen(ph->key)+strlen(ph->value)+4;
        }
        i++;
    }
    memcpy(current,"\r\n",2);
    return 0;
}

void parsed_header_destroy_one(struct parsed_header *ph){
    if(ph->key!=NULL){
        free(ph->key);
        ph->key = NULL;
        free(ph->value);
        ph->value = NULL;
        ph->key_len = 0;
        ph->value_len = 0;
    }
}

void parsed_header_destroy(struct parsed_request *pr){
    size_t i = 0;
    while (i < pr->headers_used)
    {
        parsed_header_destroy_one(pr->headers + i);
        i++;
    }
    pr->headers_used = 0;

    free(pr->headers);
    pr->headers_len = 0;
}

int parsed_header_parse(struct parsed_request *pr, char *line){
    char *key;
    char *value;
    char *index1;
    char *index2;

    index1 = index(line, ':');
    if(index1 == NULL){
        debug("No colon found\n");
        return -1;
    }

    key = (char *)malloc((index1-line+1)*sizeof(char));
    memcpy(key,line,index1-line);
    size_t key_len = index1 - line;
    key[key_len] = '\0';


    index1 += 2;
    index2 = strstr(index1, "\r\n");
    value = (char *)malloc((index2-index1+1)*sizeof(char));
    memcpy(value,index1,(index2-index1));
    value[strlen(index2-index1)] = '\0';

    parsed_header_set(pr, key, value);
    free(key);
    free(value);
    return 0;
}

void parsed_request_destroy(struct parsed_request *pr){
    if(pr->buf != NULL){
        free(pr->buf);
    }
    if(pr->path != NULL){
        free(pr->path);
    }
    if(pr->headers_len > 0){
        parsed_header_destroy(pr);
    }
    free(pr);
}

struct parsed_request* parsed_request_create(){
    struct parsed_request *pr;
    pr = (struct parsed_request *)malloc(sizeof(struct parsed_request));
    if(pr!=NULL){
        parsed_header_create(pr);
        pr->buf = NULL;
        pr->method = NULL;
        pr->protocol = NULL;
        pr->host = NULL;
        pr->path = NULL;
        pr->version = NULL;
        pr->buflen = 0;
    }
    return pr;
}

int parsed_request_unparse(struct parsed_request *pr, char *buf, size_t buflen){
    if(!pr || !pr->buf){return -1;}

    size_t tmp;
    if(parsed_request_print_request_line(pr,buf,buflen,&tmp)<0){return -1;}
    if(parsed_header_print_headers(pr,buf+tmp,buflen-tmp)<0){return -1;}
    return 0;
}

int parsed_request_unparse_headers(struct parsed_request *pr, char *buf, size_t buflen){
    if(!pr || !pr->buf){return -1;}

    if(parsed_header_print_headers(pr,buf,buflen)<0){return -1;}
    return 0;
}

size_t parsed_request_total_len(struct parsed_request *pr){
    if(!pr || !pr->buf){return 0;}
    return parsed_request_line_len(pr) + parsed_header_headers_len(pr);
}

int parsed_request_parse(struct parsed_request *parse, const char *buf, int buflen){
    char *full_addr;
    char *saveptr;
    char *index;
    char *current_header;

    if(parse->buf != NULL){
        debug("Parse object already assigned to a request\n");
        return -1;
    }

    if(buflen < MIN_REQ_LEN || buflen > MAX_REQ_LEN){
        debug("Invalid buffer size %d", buflen);
        return -1;
    }

    char *tmp_buf = (char *)malloc(buflen + 1);
    memcpy(tmp_buf,buf,buflen);
    tmp_buf[buflen] = '\0';

    index = strstr(tmp_buf, "\r\n\r\n");
    if(parse->buf == NULL){
        parse->buf = (char *)malloc((index - tmp_buf) + 1);
        parse->buflen = index - tmp_buf + 1;
    }
    memcpy(parse->buf,tmp_buf,index - tmp_buf);
    parse->buf[index - tmp_buf] = '\0';

    parse->method = strtok_r(parse->buf, " ", &saveptr);
    if(parse->method == NULL){
        debug("Invalid request line, no whitespace\n");
        free(tmp_buf);
        free(parse->buf);
        parse->buf = NULL;
        return -1;
    }

    if(strcmp(parse->method, "GET")){
        debug("Invalid request line, method not 'GET': %s\n",parse->method);
        free(tmp_buf);
        free(parse->buf);
        parse->buf = NULL;
        return -1;
    }

    full_addr = strtok_r(NULL," ",&saveptr);

    if(full_addr == NULL){
        debug("Invalid request line, no full address\n");
        free(tmp_buf);
        free(parse->buf);
        parse->buf = NULL;
        return -1;
    }

    parse->version = full_addr + strlen(full_addr) + 1;

    if(parse->version == NULL){
        debug("Invalid request line, missing version\n");
        free(tmp_buf);
        free(parse->buf);
        parse->buf = NULL;
        return -1;
    }

    if(strncmp(parse->version, "HTTP/", 5)){
        debug("Invalid request line, unsupported version %s\n", parse->version);
        free(tmp_buf);
        free(parse->buf);
        parse->buf = NULL;
        return -1;
    }

    parse->protocol = strtok_r(full_addr, "://", &saveptr);
    if(parse->protocol == NULL){
        debug("Invalid request line, missing host\n");
        free(tmp_buf);
        free(parse->buf);
        parse->buf = NULL;
        return -1;
    }

    const char *rem = full_addr + strlen(parse->protocol) + strlen(";//");
    size_t abs_uri_len = strlen(rem);

    parse->host = strtok_r(NULL,"/",&saveptr);
    if(parse->host == NULL){
        debug("Invalid request line, missing host\n");
        free(tmp_buf);
        free(parse->buf);
        parse->buf = NULL;
        return -1;
    }

    if(strlen(parse->host) == abs_uri_len){
        debug("Invalid request line, missing absolute path\n");
        free(tmp_buf);
        free(parse->buf);
        parse->buf = NULL;
        return -1;
    }

    parse->path = strtok_r(NULL," ",&saveptr);
    if(parse->path == NULL){
        int rlen = strlen(root_abs_path);
        parse->path = (char *)malloc(rlen + 1);
        strncpy(parse->path, root_abs_path, rlen + 1);
    }
    else if(strncmp(parse->path,root_abs_path,strlen(root_abs_path)) == 0){
        debug("Invalid request line, path cannot begin with two slash characters\n");
        free(tmp_buf);
        free(parse->buf);
        free(parse->path);
        parse->buf = NULL;
        parse->path = NULL;
        return -1;
    }
    else{
        char *tmp_path = parse->path;
        int rlen = strlen(root_abs_path);
        int plen = strlen(parse->path);
        parse->path = (char *)malloc(rlen + plen + 1);
        strncpy(parse->path, root_abs_path, rlen);
        strncpy(parse->path + rlen, tmp_path, plen + 1);
    }

    parse->host = strtok_r(parse->host,":",&saveptr);
    parse->port = strtok_r(NULL,"/",&saveptr);

    if(parse->host == NULL){
        debug("Invalid request line, missing host\n");
        free(tmp_buf);
        free(parse->buf);
        free(parse->path);
        parse->buf = NULL;
        parse->path = NULL;
        return -1;
    }

    if(parse->port != NULL){
        int port = strtol(parse->port, (char **)NULL, 10);
        if(port == 0 && errno == EINVAL){
            debug("Invalid request line, bad port: %s\n", parse->port);
            free(tmp_buf);
	        free(parse->buf);
	        free(parse->path);
	        parse->buf = NULL;
	        parse->path = NULL;
	        return -1;
        }
    }

    int ret = 0;
    current_header = strstr(tmp_buf,"\r\n") + 2;
    while(current_header[0] != '\0' && !(current_header[0] == '\r' && current_header[1] == '\n')){
        if(parsed_header_parse(parse, current_header)){
            ret = -1;
            break;
        }

        current_header = strstr(current_header, "\r\n");
        if(current_header == NULL || strlen(current_header) < 2){break;}
        current_header += 2;
    }
    free(tmp_buf);
    return ret;
}

size_t parsed_request_line_len(struct parsed_request *pr){
    if(!pr || !pr->buf){return 0;}

    size_t len = strlen(pr->method) + 1 + strlen(pr->protocol) + 3 + strlen(pr->host) + 1 + strlen(pr->version) + 2;
    if(pr->port != NULL){len += strlen(pr->port) + 1;}
    len += strlen(pr->path);
    return len;
}

int parsed_request_print_request_line(struct parsed_request *pr, char *buf, size_t buflen, size_t *tmp){
    char *current = buf;

    if(buflen < parsed_request_line_len(pr)){
        debug("Not enough memory for first line\n");
        return -1;
    }
    memcpy(current, pr->method,strlen(pr->method));
    current += strlen(pr->method);
    current[0] = ' ';
    current += 1;

    memcpy(current, pr->protocol, strlen(pr->protocol));
    current += strlen(pr->protocol);
    memcpy(current,"://",3);
    current += 3;
    memcpy(current, pr->host, strlen(pr->host));
    current += strlen(pr->host);
    if(pr->port != NULL){
        current[0] = ':';
        current += 1;
        memcpy(current, pr->port, strlen(pr->port));
        current += strlen(pr->port);
    }
    memcpy(current, pr->path, strlen(pr->path));
    current += strlen(pr->path);

    current[0] = ' ';
    current += 1;

    memcpy(current, pr->version, strlen(pr->version));
    current += strlen(pr->version);
    memcpy(current, "\r\n", 2);
    current += 2;
    *tmp = current - buf;
    return 0;
}
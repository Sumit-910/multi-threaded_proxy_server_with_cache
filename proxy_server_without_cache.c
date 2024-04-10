#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>

#define MAX_BYTES 4096
#define MAX_CLIENTS 400

pthread_mutex_t lock;

int port = 8080;
int proxy_socket_id;

pthread_t tid[MAX_CLIENTS];
sem_t semaphore;

int send_error_message(int socket, int status_code)
{
    char str[1024];
    char current_time[50];
    time_t now = time(0);

    struct tm data = *gmtime(&now);

    strftime(current_time, sizeof(current_time), "%a, %d %b %Y %H:%M:%S %Z", &data);

    switch (status_code)
    {
    case 400:
        snprintf(str, sizeof(str),
                 "HTTP/1.1 400 Bad Request\r\n"
                 "Content-Length: 95\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Type: text/html\r\n"
                 "Date: %s\r\n"
                 "Server: sumit/1.0\r\n\r\n"
                 "<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n<BODY><H1>400 Bad Rqeuest</H1>\n</BODY></HTML>",
                 current_time);

        printf("400 BAd Request\n");
        send(socket, str, strlen(str), 0);
        break;

    case 403:
        snprintf(str, sizeof(str),
                 "HTTP/1.1 403 Forbidden\r\n"
                 "Content-Length: 112\r\n"
                 "Content-Type: text/html\r\n"
                 "Connection: keep-alive\r\n"
                 "Date: %s\r\n"
                 "Server: sumit/1.0\r\n\r\n"
                 "<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n<BODY><H1>403 Forbidden</H1><br>Permission Denied\n</BODY></HTML>",
                 current_time);

        printf("403 Forbidden");
        send(socket, str, strlen(str), 0);
        break;

    case 404:
        snprintf(str, sizeof(str),
                 "HTTP/1.1 404 Not Found\r\n"
                 "Content-Length: 91\r\n"
                 "Content-Type: text/html\r\n"
                 "Connection: keep-alive\r\n"
                 "Date: %s\r\n"
                 "Server: sumit/1.0\r\n\r\n"
                 "<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n<BODY><H1>404 Not Found</H1>\n</BODY></HTML>",
                 current_time);

        printf("404 Not Found\n");
        send(socket, str, strlen(str), 0);
        break;

    case 500:
        snprintf(str, sizeof(str),
                 "HTTP/1.1 500 Internal Server Error\r\n"
                 "Content-Length: 115\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Type: text/html\r\n"
                 "Date: %s\r\n"
                 "Server: sumit/1.0\r\n\r\n"
                 "<HTML><HEAD><TITLE>500 Internal Server Error</TITLE></HEAD>\n<BODY><H1>500 Internal Server Error</H1>\n</BODY></HTML>",
                 current_time);

        printf("500 Internal Server Error\n");
        send(socket, str, strlen(str), 0);
        break;

    case 501:
        snprintf(str, sizeof(str),
                 "HTTP/1.1 501 Not Implemented\r\n"
                 "Content-Length: 103\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Type: text/html\r\n"
                 "Date: %s\r\n"
                 "Server: sumit/1.0\r\n\r\n"
                 "<HTML><HEAD><TITLE>404 Not Implemented</TITLE></HEAD>\n<BODY><H1>501 Not Implemented</H1>\n</BODY></HTML>",
                 current_time);

        printf("501 Not Implemented\n");
        send(socket, str, strlen(str), 0);
        break;

    case 505:
        snprintf(str, sizeof(str),
                 "HTTP/1.1 505 HTTP Version Not Supported\r\n"
                 "Content-Length: 125\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Type: text/html\r\n"
                 "Date: %s\r\n"
                 "Server: sumit/1.0\r\n\r\n"
                 "<HTML><HEAD><TITLE>505 HTTP Version Not Supported</TITLE></HEAD>\n<BODY><H1>505 HTTP Version Not Supported</H1>\n</BODY></HTML>",
                 current_time);

        printf("505 HTTP Version Not Supported\n");
        send(socket, str, strlen(str), 0);
        break;

    default:
        return -1;
    }

    return 1;
}

int connect_remote_server(char *host_addr, int port_num)
{
    int remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket < 0)
    {
        fprintf(stderr, "Error in creating socket.\n");
        return -1;
    }

    struct hostent *host = gethostbyname(host_addr);
    if (host == NULL)
    {
        fprintf(stderr, "No such host exists.\n");
        return -1;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_num);

    memcpy(&server_addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);

    if (connect(remote_socket, (struct sockaddr *)&server_addr, (socklen_t)sizeof(server_addr)) < 0)
    {
        fprintf(stderr, "Error in connecting!\n");
        return -1;
    }
    return remote_socket;
}

int handle_request(int client_socket, struct parsed_request *request, char *buf, char *temp_req)
{
    strcpy(buf, "GET ");
    strcat(buf, request->path);
    strcat(buf, " ");
    strcat(buf, request->version);
    strcat(buf, "\r\n");

    size_t len = strlen(buf);

    if (parsed_header_set(request, "Connection", "close") < 0)
    {
        printf("set header key not work\n");
    }

    if (parsed_header_get(request, "Host") == NULL)
    {
        if (parsed_header_set(request, "Host", request->host) < 0)
        {
            printf("Set \"Host\" header key not working\n");
        }
    }

    if (parsed_request_unparse_headers(request, buf + len, (size_t)MAX_BYTES - len) < 0)
    {
        printf("unparse failed\n");
    }

    int server_port = 80;

    if (request->port != NULL)
    {
        server_port = atoi(request->port);
    }

    int remote_socket_id = connect_remote_server(request->host, server_port);
    if (remote_socket_id < 0)
    {
        return -1;
    }

    int bytes_send = send(remote_socket_id, buf, strlen(buf), 0);
    memset(buf, 0, MAX_BYTES);

    bytes_send = recv(remote_socket_id, buf, MAX_BYTES - 1, 0);

    char *temp_buffer = (char *)malloc(sizeof(char) * MAX_BYTES);
    int temp_buffer_size = MAX_BYTES;
    int temp_buffer_index = 0;

    while (bytes_send > 0)
    {
        bytes_send = send(client_socket, buf, bytes_send, 0);

        for (int i = 0; i < bytes_send / sizeof(char); i++)
        {
            temp_buffer[temp_buffer_index] = buf[i];
            temp_buffer_index++;
        }

        temp_buffer_size += MAX_BYTES;

        temp_buffer = (char *)realloc(temp_buffer, temp_buffer_size);

        if (bytes_send < 0)
        {
            perror("Error in sending data to client socket.\n");
            break;
        }

        memset(buf, 0, MAX_BYTES);

        bytes_send = recv(remote_socket_id, buf, MAX_BYTES - 1, 0);
    }

    temp_buffer[temp_buffer_index] = '\0';
    free(temp_buffer);
    free(temp_req);
    printf("Done\n");

    return 0;
}

int check_HTTP_version(char *msg)
{
    int version = -1;

    if (strncmp(msg, "HTTP/1.1", 8) == 0)
    {
        version = 1;
    }
    else if (strncmp(msg, "HTTP/1.0", 8) == 0)
    {
        version = 1;
    }

    return version;
}

void *thread_fn(void *socket_new)
{
    sem_wait(&semaphore);
    int p;
    sem_getvalue(&semaphore, &p);
    printf("Semaphore value: %d\n", p);
    int *t = (int *)(socket_new);
    int socket = *t;

    int bytes_send_client, len;
    char *buffer = (char *)calloc(MAX_BYTES, sizeof(char));
    memset(buffer, 0, MAX_BYTES);
    bytes_send_client = recv(socket, buffer, MAX_BYTES, 0);

    while (bytes_send_client > 0)
    {
        len = strlen(buffer);

        if (strtsr(buffer, "\r\n\r\n") == NULL)
        {
            bytes_send_client = recv(socket, buffer + len, MAX_BYTES - len, 0);
        }
        else
        {
            break;
        }
    }

    char *temp_req = (char *)malloc(strlen(buffer) * sizeof(char) + 10);

    for (int i = 0; i < strlen(buffer); i++)
    {
        temp_req[i] = buffer[i];
    }

    if (bytes_send_client > 0)
    {
        len = strlen(buffer);
        struct parsed_request *request = parsed_request_create();

        if (parsed_request_parsed(request, buffer, len) < 0)
        {
            fprintf(stderr, "Parsing failed\n");
        }
        else
        {
            memset(buffer, 0, MAX_BYTES);
            if (!strcmp(request->method, "GET"))
            {
                if (request->host && request->path && (check_HTTP_version(request->version) == 1))
                {
                    bytes_send_client = handle_request(socket, request, buffer, temp_req);

                    if (bytes_send_client == -1)
                    {
                        send_error_message(socket, 500);
                    }
                }
                else
                {
                    send_error_message(socket, 500);
                }
            }
            else
            {
                printf("This code doesn't support any method other than GET\n");
            }
        }
        parsed_request_destroy(request);
    }
    else if (bytes_send_client < 0)
    {
        perror("Error in recieving from client.\n");
    }
    else if (bytes_send_client == 0)
    {
        printf("Client disconnected!\n");
    }
    shutdown(socket, SHUT_RDWR);
    close(socket);
    free(buffer);
    sem_post(&semaphore);
    sem_getvalue(&semaphore, &p);
    printf("Semaphore post value: %d\n", p);

    return NULL;
}

int main(int argc, char const *argv[])
{
    int client_socket_id, client_len;
    struct sockaddr_in server_addr, client_addr;
    sem_init(&semaphore, 0, MAX_CLIENTS);
    pthread_mutex_init(&lock, NULL);

    if (argc == 2)
    {
        port = atoi(argv[1]);
    }
    else
    {
        printf("Too few agruments\n");
        exit(1);
    }
    printf("Setting Proxy Server Port : %d\n", port);

    proxy_socket_id = socket(AF_INET, SOCK_STREAM, 0);

    if (proxy_socket_id < 0)
    {
        perror("Failed to create socket.\n");
        exit(1);
    }

    int reuse = 1;

    if (setsockopt(proxy_socket_id, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed\n");
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(proxy_socket_id, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Port is not free\n");
        exit(1);
    }

    printf("Binding on port: %d\n", port);

    int listen_status = listen(proxy_socket_id, MAX_CLIENTS);

    if (listen_status < 0)
    {
        perror("Error while listening!\n");
        exit(1);
    }

    int i = 0;
    int connected_socket_id[MAX_CLIENTS];

    while (1)
    {
        memset(&client_addr, 0, sizeof(client_addr));
        client_len = sizeof(client_addr);

        client_socket_id = accept(proxy_socket_id, (struct sockaddr *)&client_addr, (socklen_t *)&client_len);

        if (client_socket_id < 0)
        {
            fprintf(stderr, "Error in accepting connection!\n");
            exit(1);
        }
        else
        {
            connected_socket_id[i] = client_socket_id;
        }

        struct sockaddr_in *client_pt = (struct sockaddr_in *)&client_addr;
        struct in_addr ip_addr = client_pt->sin_addr;
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN);

        pthread_create(&tid[1], NULL, thread_fn, (void *)&connected_socket_id[i]);
        i++;
    }
    close(proxy_socket_id);

    return 0;
}

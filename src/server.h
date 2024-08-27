#pragma once

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zconf.h>
#include <zlib.h>

#define BUFFER_LEN 4096
#define METHOD_LEN 16
#define RESPONSE_LEN 8192
#define PATH_LEN 256
#define ENDPOINT_LEN 128
#define ARGUMENT_LEN 128
#define CONTENT_TYPE_LEN 256
#define NODE_POOL_SIZE 100
#define BODY_MAX_LEN 512000
#define CHUNK 16384
#define ENV_POOL_SIZE 100
#define SINGLE_NODE_POOL_SIZE 100

typedef struct s_env
{
	char files_path[PATH_LEN];
	char request[BUFFER_LEN];
	char method[METHOD_LEN];
	char path[PATH_LEN];
	char endpoint[ENDPOINT_LEN];
	char argument[ARGUMENT_LEN];
	char response_body[BODY_MAX_LEN];
	char body[BODY_MAX_LEN];
	char content_length_str[16];
	size_t content_length;
	char content_type[CONTENT_TYPE_LEN];
	char encoding[256];
	bool gzip_encoding;
	int client_fd;
} t_env;

// Nodes for queue
typedef struct s_Node
{
	t_env *env;
} t_Node;

typedef struct s_nodes_queue_node
{
	t_Node *value;
	struct s_nodes_queue_node *next;
	struct s_nodes_queue_node *prev;
} t_NQueue_node;

typedef struct t_nodes_queue
{
	t_NQueue_node *head;
	t_NQueue_node *tail;
	int len;
} t_NQueue;

// Queue Node pool
typedef struct s_node_pool
{
	t_Node nodes[SINGLE_NODE_POOL_SIZE];
	int used[SINGLE_NODE_POOL_SIZE];
	int next_free;
	pthread_mutex_t lock;
} t_node_pool;

// env pool
typedef struct s_env_pool
{
	t_env envs[ENV_POOL_SIZE];
	int used[ENV_POOL_SIZE];
	int next_free;
	pthread_mutex_t lock;
} t_env_pool;

// Threads: pool and worker
typedef struct s_thread_pool
{
	pthread_t *threads;
	t_NQueue *queue; // queue of tasks to be executed (t_env->client_fd)
	int num_threads;
	int active; // the pool will be active by default
	pthread_mutex_t lock;
	pthread_cond_t signal; // signal threads about available tasks
} t_thread_pool;

typedef struct s_thread_worker
{
	void *(*routine)(void *arg);
	void *arg;
} t_thread_worker;

// globals:

/* action_handlers.c */
int read_request(char request[BUFFER_LEN], int client_fd);
void handle_root_request(int client_fd);
void handle_not_found_request(int client_fd, t_env *env);
void handle_text_response(int client_fd, char *argument);
void handle_file_request(int client_fd, char *filename, char *files_path,
						 char *http_code, char *content_type, t_env *env);
void handle_root_endpoint(int client_fd, t_env *env);
void handle_user_agent_endpoint(int client_fd, char *request);
void handle_files_endpoint(int client_fd, char *argument, char *files_path,
						   char *content_type, t_env *env);
void handle_echo_endpoint(t_env *env);
void handle_files_post(int client_fd, char *filename, char *path,
					   char *request);
void handle_response(t_env *env, char *response_type);
void handle_get_request(t_env *env, int client_fd, char *endpoint,
						char *argument, char *files_path, char *request);
void handle_post_request(int client_fd, char *endpoint, char *argument,
						 char *files_path, char *request, t_env *env);
void handle_request(int client_fd, t_env *env);
void *handle_client(void *arg);

/* compressor.c */
int gzip_compress(const char *src, int src_len, char **dst, int *dst_len);

/* get_info */
char *get_header_value(char *object, char *request);
char *get_content_type(const char *extension);

/* memory_pools */
t_NQueue_node *allocate_node();
void free_node(t_NQueue_node *node);
t_node_pool *create_node_pool();
t_Node *get_node();
void release_node(t_Node *node);
void destroy_node_pool();
t_env_pool *create_env_pool();
t_env *get_env();
void release_env(t_env *env);
void destroy_env_pool();

/* parsers */
void parse_method_path(char *request, char *method, char *path);
void split_url(const char *url, char *endpoint, char *argument);
int parse_request(char *request, char *target, char *content);

/* queue */
t_NQueue *new_nqueue();
int nenqueue(t_NQueue *queue, t_Node *value);
int ndequeue(t_NQueue *queue);
void free_nq(t_NQueue *queue, pthread_mutex_t *lock);

/* threads */
t_thread_pool *new_thread_pool(int num_threads);
void free_thread_pool(t_thread_pool *pool);
void *worker_thread(void *arg);

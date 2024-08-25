#include <ctype.h>
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

#define BUFFER_LEN 1024
#define METHOD_LEN 16
#define RESPONSE_LEN 1024
#define PATH_LEN 256
#define ENDPOINT_LEN 128
#define ARGUMENT_LEN 128
#define NODE_POOL_SIZE 100

void handle_file_request(int client_fd, char *filename, char *files_path,
						 char *http_code, char *content_type);

char *get_content_type(const char *extension);

typedef struct s_env
{
	char path[PATH_LEN];
	int client_fd;
} t_env;

void *worker_thread(void *arg);
void *handle_client(void *arg);

/* TODO: QUEUE: MOVE TO A DIFFERENT FILE */
// Nodes Queue
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

t_NQueue_node node_pool[NODE_POOL_SIZE];
int node_pool_index = 0;
t_NQueue_node *free_list = NULL;

t_NQueue_node *allocate_node()
{
	if (free_list)
	{
		t_NQueue_node *node = free_list;
		free_list = node->next;
		return node;
	}
	else if (node_pool_index < NODE_POOL_SIZE)
	{
		return &node_pool[node_pool_index++];
	}
	else
	{
		return NULL;
	}
}

void free_node(t_NQueue_node *node)
{
	node->next = free_list;
	free_list = node;
}

#define ENV_POOL_SIZE 100

typedef struct s_env_pool
{
	t_env envs[ENV_POOL_SIZE];
	int used[ENV_POOL_SIZE];
	int next_free;
	pthread_mutex_t lock;
} t_env_pool;

t_env_pool *global_env_pool = NULL;

t_env_pool *create_env_pool()
{
	t_env_pool *pool = malloc(sizeof(t_env_pool));
	if (!pool)
		return NULL;

	for (int i = 0; i < ENV_POOL_SIZE; i++)
	{
		pool->used[i] = 0;
	}
	pool->next_free = 0;
	pthread_mutex_init(&pool->lock, NULL);
	return pool;
}

t_env *get_env()
{
	if (!global_env_pool)
	{
		global_env_pool = create_env_pool();
		if (!global_env_pool)
			return NULL;
	}

	pthread_mutex_lock(&global_env_pool->lock);

	if (global_env_pool->next_free >= ENV_POOL_SIZE)
	{
		pthread_mutex_unlock(&global_env_pool->lock);
		return NULL;
	}

	int index = global_env_pool->next_free;
	global_env_pool->used[index] = 1;

	// Find next free slot
	while (global_env_pool->next_free < ENV_POOL_SIZE &&
		   global_env_pool->used[global_env_pool->next_free])
	{
		global_env_pool->next_free++;
	}

	pthread_mutex_unlock(&global_env_pool->lock);
	return &global_env_pool->envs[index];
}

void release_env(t_env *env)
{
	if (!env || !global_env_pool)
		return;

	pthread_mutex_lock(&global_env_pool->lock);

	int index = (int)(env - global_env_pool->envs);
	if (index >= 0 && index < ENV_POOL_SIZE)
	{
		global_env_pool->used[index] = 0;
		if (index < global_env_pool->next_free)
		{
			global_env_pool->next_free = index;
		}
		// Reset the env struct here if necessary. No need for now
	}

	pthread_mutex_unlock(&global_env_pool->lock);
}

void destroy_env_pool()
{
	if (global_env_pool)
	{
		pthread_mutex_lock(&global_env_pool->lock);
		// Any cleanup needed for individual envs can be done here
		pthread_mutex_unlock(&global_env_pool->lock);
		pthread_mutex_destroy(&global_env_pool->lock);
		free(global_env_pool);
		global_env_pool = NULL;
	}
}

#define SINGLE_NODE_POOL_SIZE 100

typedef struct s_node_pool
{
	t_Node nodes[SINGLE_NODE_POOL_SIZE];
	int used[SINGLE_NODE_POOL_SIZE];
	int next_free;
	pthread_mutex_t lock;
} t_node_pool;

t_node_pool *global_node_pool = NULL;

t_node_pool *create_node_pool()
{
	t_node_pool *pool = malloc(sizeof(t_node_pool));
	if (!pool)
		return NULL;

	for (int i = 0; i < NODE_POOL_SIZE; i++)
	{
		pool->used[i] = 0;
		pool->nodes[i].env = NULL;
	}
	pool->next_free = 0;
	pthread_mutex_init(&pool->lock, NULL);
	return pool;
}

t_Node *get_node()
{
	if (!global_node_pool)
	{
		global_node_pool = create_node_pool();
		if (!global_node_pool)
			return NULL;
	}

	pthread_mutex_lock(&global_node_pool->lock);

	if (global_node_pool->next_free >= NODE_POOL_SIZE)
	{
		pthread_mutex_unlock(&global_node_pool->lock);
		return NULL; // Pool is full
	}

	int index = global_node_pool->next_free;
	global_node_pool->used[index] = 1;

	// Find next free slot
	while (global_node_pool->next_free < NODE_POOL_SIZE &&
		   global_node_pool->used[global_node_pool->next_free])
	{
		global_node_pool->next_free++;
	}

	pthread_mutex_unlock(&global_node_pool->lock);
	return &global_node_pool->nodes[index];
}

void release_node(t_Node *node)
{
	if (!node || !global_node_pool)
		return;

	pthread_mutex_lock(&global_node_pool->lock);

	int index = (int)(node - global_node_pool->nodes);
	if (index >= 0 && index < NODE_POOL_SIZE)
	{
		global_node_pool->used[index] = 0;
		if (index < global_node_pool->next_free)
		{
			global_node_pool->next_free = index;
		}
		// Free the env if it exists
		if (node->env)
		{
			release_env(node->env);
			node->env = NULL;
		}
	}

	pthread_mutex_unlock(&global_node_pool->lock);
}

void destroy_node_pool()
{
	if (global_node_pool)
	{
		pthread_mutex_lock(&global_node_pool->lock);
		// Free any remaining env structs
		for (int i = 0; i < NODE_POOL_SIZE; i++)
		{
			if (global_node_pool->used[i] && global_node_pool->nodes[i].env)
			{
				release_env(global_node_pool->nodes[i].env);
			}
		}
		pthread_mutex_unlock(&global_node_pool->lock);
		pthread_mutex_destroy(&global_node_pool->lock);
		free(global_node_pool);
		global_node_pool = NULL;
	}
}
// End of pools

t_NQueue *new_nqueue()
{
	t_NQueue *Q = malloc(sizeof(t_NQueue));
	if (!Q)
		return NULL;

	Q->len = 0;
	Q->head = NULL;
	Q->tail = NULL;

	return Q;
}

int nenqueue(t_NQueue *queue, t_Node *value)
{
	if (!queue)
		return -1;
	t_NQueue_node *node = allocate_node();
	if (!node)
		return -1;
	node->value = value;
	node->next = NULL;
	node->prev = queue->tail;
	if (!queue->head)
	{
		queue->head = node;
	}
	else
	{
		queue->tail->next = node;
	}
	queue->tail = node;
	queue->len++;
	return 0;
}

int ndequeue(t_NQueue *queue)
{
	if (!queue || queue->len < 1)
		return -1;

	t_NQueue_node *tmp = queue->head;
	queue->head = tmp->next;
	if (queue->head)
	{
		queue->head->prev = NULL;
	}
	else
	{
		queue->tail = NULL;
	}
	free_node(tmp);
	queue->len--;
	return 0;
}

void free_nq(t_NQueue *queue)
{
	if (!queue)
		return;
	t_NQueue_node *node = queue->head;
	while (node)
	{
		t_NQueue_node *next = node->next;
		release_env(node->value->env);
		release_node(node->value);
		free_node(node);
		node = next;
	}
	free(queue);
}

/* END OF QUEUE */

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

t_thread_pool *new_thread_pool(int num_threads)
{
	t_thread_pool *pool = malloc(sizeof(t_thread_pool));
	if (!pool)
		return NULL;
	pool->threads = malloc(sizeof(pthread_t) * num_threads);
	if (!pool->threads)
	{
		free(pool);
		return NULL;
	}
	pool->queue = new_nqueue();
	if (!pool->queue)
	{
		free(pool->threads);
		free(pool);
		return NULL;
	}
	pool->num_threads = num_threads;
	pool->active = 1;
	pthread_mutex_init(&pool->lock, NULL);
	pthread_cond_init(&pool->signal, NULL);
	for (int i = 0; i < num_threads; i++)
	{
		pthread_create(&pool->threads[i], NULL, worker_thread, pool);
	}
	return pool;
}

void free_thread_pool(t_thread_pool *pool)
{
	if (!pool)
		return;

	// Signal all worker threads to exit
	pthread_mutex_lock(&pool->lock);
	pool->active = 0;
	pthread_cond_broadcast(&pool->signal);
	pthread_mutex_unlock(&pool->lock);

	// Wait for all worker threads to exit
	for (int i = 0; i < pool->num_threads; i++)
	{
		pthread_join(pool->threads[i], NULL);
	}
	free(pool->threads);
	pthread_mutex_destroy(&pool->lock);
	pthread_cond_destroy(&pool->signal);
	free(pool);
}

/* Function executed by each thread */
void *worker_thread(void *arg)
{
	t_thread_pool *pool = (t_thread_pool *)arg;

	while (1)
	{
		pthread_mutex_lock(&pool->lock);

		// Wait for a task to be available in the queue
		while (pool->active && pool->queue->len == 0)
		{
			pthread_cond_wait(&pool->signal, &pool->lock);
		}

		// If the pool is no longer active, exit the thread
		if (!pool->active)
		{
			pthread_mutex_unlock(&pool->lock);
			pthread_exit(NULL);
		}

		t_Node *task;
		// Dequeue a task and process it
		if (pool->queue->len > 0)
		{
			task = pool->queue->head->value;
			if (task)
				ndequeue(pool->queue);
		}

		pthread_mutex_unlock(&pool->lock);
		if (task)
		{
			handle_client(task->env);
			// free(task);
			release_node(task);
		}
	}

	return NULL;
}

int read_request(char request[BUFFER_LEN], int client_fd)
{
	ssize_t bytes_read = 0;
	ssize_t total_bytes = 0;

	while ((bytes_read = recv(client_fd, request + total_bytes,
							  BUFFER_LEN - total_bytes, 0)) > 0)
	{
		total_bytes += bytes_read;
		if (total_bytes > BUFFER_LEN - 1)
		{
			puts("Error: the request is too long");
			request[BUFFER_LEN - 1] = '\0';
			return -1;
		}
		request[total_bytes] = '\0';
		if (total_bytes > BUFFER_LEN - 1)
		{
			puts("Error: the request is too long");
			return -1;
		}
		if (strstr(request, "\r\n\r\n") != NULL)
		{
			// Entire request received
			break;
		}
	}
	return bytes_read;
}

void parse_request(char *request, char *method, char *path)
{
	sscanf(request, "%15s %254s", method, path);
}

void split_url(const char *url, char *endpoint, char *argument)
{
	char *url_copy = strdup(url);
	char *token = NULL;
	char *rest = url_copy;

	// Skip over any leading slashes
	while (*rest == '/')
		rest++;
	token = strsep(&rest, "/");
	if (token != NULL)
	{
		strncpy(endpoint, token, ENDPOINT_LEN - 1);
		endpoint[ENDPOINT_LEN - 1] = '\0';
	}

	token = strsep(&rest, "/");
	if (token != NULL)
	{
		strncpy(argument, token, ARGUMENT_LEN - 1);
		argument[ARGUMENT_LEN - 1] = '\0';
	}

	free(url_copy);
}

void handle_root_request(int client_fd)
{
	char const *ok_status = "HTTP/1.1 200 OK\r\n\r\n";
	send(client_fd, ok_status, strlen(ok_status), 0);
}

void handle_not_found_request(int client_fd)
{
	handle_file_request(client_fd, "404.jpeg", "./error_images/",
						"404 Not Found", ".jpeg");
	// char const *not_found_status = "HTTP/1.1 404 Not Found\r\n\r\n";
	// send(client_fd, not_found_status, strlen(not_found_status), 0);
}

char *get_header_value(char *object, char *request)
{
	char *value = strstr(request, object);

	if (value == NULL)
		return value;
	value += strlen(object);
	char *endof_value = strchr(value, '\r');
	if (endof_value != NULL)
		*endof_value = '\0';

	return value;
}

void handle_text_response(int client_fd, char *argument)
{
	char response[RESPONSE_LEN];
	bzero(response, sizeof(response));

	snprintf(response, RESPONSE_LEN - 1,
			 "HTTP/1.1 200 OK\r\nContent-Type: "
			 "text/plain\r\nContent-Length: %zu\r\n\r\n%s",
			 strlen(argument), argument);
	send(client_fd, response, strlen(response), 0);
}

void move_buffer_to_response(char **response, char *buffer, int bytes_read,
							 int *response_len)
{
	*response = realloc(*response, *response_len + bytes_read + 1);
	if (*response == NULL)
	{
		fprintf(stderr, "Memory reallocation failed\n");
		return;
	}
	memcpy(*response + *response_len, buffer, bytes_read);
	*response_len += bytes_read;
	(*response)[*response_len] = '\0';
}

char *get_content_type(const char *extension)
{
	if (!extension)
		return "application/octet-stream";
	char *ext = strchr(extension, '.');
	if (strncmp(ext, ".html", strlen(ext)) == 0)
		return "text/html";
	if (strncmp(ext, ".css", strlen(ext)) == 0)
		return "text/css";
	if (strncmp(ext, ".js", strlen(ext)) == 0)
		return "application/javascript";
	if (strncmp(ext, ".jpeg", strlen(ext)) == 0 ||
		strncmp(ext, ".jpg", strlen(ext)) == 0)
		return "image/jpeg";
	if (strncmp(ext, ".png", strlen(ext)) == 0)
		return "image/png";
	if (strncmp(ext, ".gif", strlen(ext)) == 0)
		return "image/gif";
	return "application/octet-stream";
}

void handle_file_request(int client_fd, char *filename, char *files_path,
						 char *http_code, char *content_type)
{

	char *response = NULL;
	char buffer[BUFFER_LEN];
	int bytes_read = 0;
	int response_len = 0;
	int file_path_len = strlen(files_path) + strlen(filename) + 1;
	char *file_path = malloc(file_path_len);

	snprintf(file_path, file_path_len, "%s%s", files_path, filename);
	if (access(file_path, F_OK) != 0)
	{
		fprintf(stderr, "%s doesn't exist\n", file_path);
		handle_not_found_request(client_fd);
		free(file_path);
		return;
	}

	printf("serving %s\n", file_path);
	FILE *file = fopen(file_path, "rb"); // Open in binary mode
	if (file == NULL)
	{
		fprintf(stderr, "%s failed to open\n", file_path);
		handle_not_found_request(client_fd);
		free(file_path);
		return;
	}

	while ((bytes_read = fread(buffer, 1, BUFFER_LEN, file)) > 0)
	{
		move_buffer_to_response(&response, buffer, bytes_read, &response_len);
	}
	fclose(file);
	printf("Response length: %d bytes\n", response_len);

	char header[256];
	snprintf(header, sizeof(header),
			 "HTTP/1.1 %s\r\nContent-Type: %s\r\n"
			 "Content-Length: %d\r\n\r\n",
			 http_code, content_type, response_len);

	send(client_fd, header, strlen(header), 0);
	send(client_fd, response, response_len, 0);

	free(file_path);
	free(response);
}

void handle_root_endpoint(int client_fd) { handle_root_request(client_fd); }

void handle_user_agent_endpoint(int client_fd, char *request)
{
	handle_text_response(client_fd, get_header_value("User-Agent: ", request));
}

void handle_files_endpoint(int client_fd, char *argument, char *files_path,
						   char *content_type)
{
	handle_file_request(client_fd, argument, files_path, "200 OK",
						content_type);
}

void handle_echo_endpoint(int client_fd, char *argument)
{
	handle_text_response(client_fd, argument);
}

void handle_files_post(int client_fd, char *filename, char *path, char *request)
{
	char const ok_status[] = "HTTP/1.1 201 Created\r\n\r\n";
	char const err_status[] = "HTTP/1.1 422 Unprocessable Content\r\n\r\n";
	char *request_body = NULL;
	int file_path_len;
	char *file_path;

	file_path_len = (path ? strlen(path) : strlen("")) + strlen(filename) + 1;
	file_path = malloc(file_path_len);
	snprintf(file_path, file_path_len, "%s%s", path ? path : "", filename);

	FILE *file;
	if (access(file_path, F_OK) != 0)
		file = fopen(file_path, "w");
	else
		file = fopen(file_path, "a");

	if (file == NULL)
	{
		fprintf(stderr, "<%s> failed to open\n", file_path);
		send(client_fd, err_status, sizeof(err_status), 0);
		free(file_path);
		return;
	}

	request_body = strstr(request, "\r\n\r\n");
	if (request_body && strlen(request_body) >= 4)
		request_body += 4;

	fprintf(file, "%s", request_body);
	printf("Content written to <%s>\n", file_path);
	send(client_fd, ok_status, sizeof(ok_status), 0);

	free(file_path);
	fclose(file);
}

void handle_get_request(int client_fd, char *endpoint, char *argument,
						char *files_path, char *request)
{
	if (!strcmp(endpoint, ""))
	{
		handle_root_endpoint(client_fd);
	}
	else if (!strcmp(endpoint, "user-agent"))
	{
		handle_user_agent_endpoint(client_fd, request);
	}
	else if (!strcmp(endpoint, "files"))
	{
		handle_files_endpoint(client_fd, argument, files_path,
							  get_content_type(NULL));
	}
	else if (!strcmp(endpoint, "echo"))
	{
		handle_echo_endpoint(client_fd, argument);
	}
	else if (!strcmp(endpoint, "home"))
	{
		handle_files_endpoint(client_fd, "home.html", "./static_html/",
							  get_content_type(".html"));
	}
	else
	{
		handle_not_found_request(client_fd);
	}
}

void handle_post_request(int client_fd, char *endpoint, char *argument,
						 char *files_path, char *request)
{
	if (!strcmp(endpoint, "files"))
	{
		handle_files_post(client_fd, argument, files_path, request);
	}
	else
	{
		handle_not_found_request(client_fd);
	}
}

void handle_request(int client_fd, char *files_path)
{
	char request[BUFFER_LEN];
	char method[METHOD_LEN];
	char path[PATH_LEN];
	char endpoint[ENDPOINT_LEN];
	char argument[ARGUMENT_LEN];
	bzero(request, sizeof(request));
	bzero(method, sizeof(method));
	bzero(path, sizeof(path));
	bzero(endpoint, sizeof(endpoint));
	bzero(argument, sizeof(argument));

	if (read_request(request, client_fd) == -1)
	{
		perror("Something went wrong: recv()");
		return;
	}

	parse_request(request, method, path);
	split_url(path, endpoint, argument);

	printf("\n%s\n", request);
	printf("Method is %s\n", method);
	printf("Route is %s\n", path);
	if (endpoint[0] && argument[0])
	{
		printf("Endpoint is %s\n", endpoint);
		printf("Argument is %s\n", argument);
	}

	if (!strncmp(method, "GET", strlen(method)))
	{
		handle_get_request(client_fd, endpoint, argument, files_path, request);
	}
	else if (!strncmp(method, "POST", strlen(method)))
	{
		handle_post_request(client_fd, endpoint, argument, files_path, request);
		return;
	}
	else
	{
		// handle other request
	}
}

void *handle_client(void *arg)
{
	t_env *env = (t_env *)arg;
	handle_request(env->client_fd, env->path);
	close(env->client_fd);
	return NULL;
}

volatile sig_atomic_t run_server = true;

void handle_signals(int signal)
{
	if (signal == SIGINT)
		run_server = false;
}

/* The basic logic of a connection is:
 * - set addr_in info for the server
 * - open a file descriptor socket()
 * - associate the fd with the local address and port using bind()
 * - listen for incoming connections with listen()
 * - accept an incoming connection with accept()
 *
 * After being accepted, the newly created socket for the client is ready
 * for send() and recv().
 */

int main(int argc, char **argv)
{
	signal(SIGINT, handle_signals);

	char files_path[PATH_LEN];
	if (argc == 3 && !strncmp(argv[1], "--directory", strlen(argv[1])))
	{
		if (strlen(argv[2]) > PATH_LEN - 1)
		{
			fprintf(stderr, "Path is too long\n");
			return 1;
		}
		strcpy(files_path, argv[2]);
	}
	else
		strcpy(files_path, "/");
	/* Disables output requestering, causing the output to be written
	 * directly to stdout or stderr without delay. */
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	int server_fd;
	uint32_t client_addr_len;
	struct sockaddr_in client_addr; // Address structure for IPv4.
									// Note: This can be cast to a generic
									// sockaddr structure when needed.

	/* Get the file descriptor
	 * Domain - What kind of socket you want: AF_INET = IPv4
	 * Type - SOCK_STREAM = Two-way connection-based byte streams (TCP)
	 * Protocol - 0 = let the socket choose the protocol it can use given
	 * type and domain
	 */
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
	{
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}

	// Since the tester restarts your program quite often, setting
	// SO_REUSEADDR ensures that we don't run into 'Address already in use'
	// errors.
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
		0)
	{
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}

	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET, // Address family - AF_INET = family of IPv4
		.sin_port = htons(4221),
		.sin_addr = {htonl(INADDR_ANY)},
		/* INADDR_ANY -  this lets the program run without knowing the IP
		   address of the network interface machine it is running on.

		   htonl - converts a 32-bit integer (e.g., IP address) from host
		   byte order to network byte order (big-endian).

		   htons - converts a 16-bit integer (e.g., port number) from host
		   byte order to network byte order (big-endian).
		*/
	};

	/* Bind the File Descriptor (server_fd) with the Address+Port
	 * (serv_addr) */
	if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
	{
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

	/* Wait for incoming connections. Listening for the port of serv_addr
	 * (no need to write it as it is bound to the socket server_fd)
	 *
	 * fd: The server file descriptor already bound to its address and port.
	 * n: number of connections allowed on the incoming queue.
	 * If an error occurs, listen() returns -1.
	 */
	int connection_backlog = 80;
	if (listen(server_fd, connection_backlog) != 0)
	{
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}

	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);

	t_thread_pool *pool = new_thread_pool(80);

	while (run_server)
	{
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		fd_set readfds;
		FD_ZERO(&readfds);			 // initialise to zero a set of fds
		FD_SET(server_fd, &readfds); // add the server to the readfds

		/* Wait until a connection is ready or the timeout of one second
		 * nfds is the max number of readfds to check. I only need to check
		 * server_fd.
		 */
		int activity = select(server_fd + 1, &readfds, NULL, NULL, &tv);

		/* activity: a connection is ready
		 * FD_ISSET: check if server_fd is part of readfds */
		if (activity > 0 && FD_ISSET(server_fd, &readfds))
		{
			t_env *env = get_env();
			if (!env)
			{
				perror("Failed to allocate memory for env");
				continue;
			}
			strcpy(env->path, files_path);
			env->client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
									&client_addr_len);
			if (env->client_fd == -1)
			{
				perror("could not accept the connection");
				release_env(env);
				continue;
			}

			t_Node *node = get_node();
			if (!node)
			{
				perror("Failed to allocate memory for task node");
				close(env->client_fd);
				release_env(env);
				continue;
			}
			node->env = env;

			/* Lock the mutex, enqueue the task, signal the condition variable,
			 * and unlock the mutex */
			pthread_mutex_lock(&pool->lock);
			if (nenqueue(pool->queue, node) != 0)
			{
				perror("Failed to enqueue task");
				close(node->env->client_fd);
				release_node(node);
				pthread_mutex_unlock(&pool->lock);
				continue;
			}
			pthread_cond_signal(&pool->signal);
			pthread_mutex_unlock(&pool->lock);
		}
	}
	free_nq(pool->queue);
	free_thread_pool(pool);
	close(server_fd);
	destroy_env_pool();
	destroy_node_pool();

	return 0;
}

#include "server.h"

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

void handle_root_request(int client_fd)
{
	char const *ok_status = "HTTP/1.1 200 OK\r\n\r\n";
	send(client_fd, ok_status, strlen(ok_status), 0);
}

void handle_not_found_request(int client_fd, t_env *env)
{
	handle_file_request(client_fd, "not_found.html", "./src/static_html/",
						"404 Not Found", get_content_type(".html"), env);
}

void return_404(int client_fd)
{
	char const *not_found_status = "HTTP/1.1 404 Not Found\r\n\r\n";
	send(client_fd, not_found_status, strlen(not_found_status), 0);
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

void handle_file_request(int client_fd, char *filename, char *files_path,
						 char *http_code, char *content_type, t_env *env)
{
	(void)http_code;
	(void)content_type;
	char buffer[BUFFER_LEN];
	int bytes_read = 0;
	int file_path_len = strlen(files_path) + strlen(filename) + 1;
	char *file_path = malloc(file_path_len);

	snprintf(file_path, file_path_len, "%s%s", files_path, filename);
	if (access(file_path, F_OK) != 0)
	{
		fprintf(stderr, "%s doesn't exist\n", file_path);
		handle_not_found_request(client_fd, env);
		free(file_path);
		return;
	}

	printf("serving %s\n", file_path);
	FILE *file = fopen(file_path, "rb"); // Open in binary mode
	if (file == NULL)
	{
		fprintf(stderr, "%s failed to open\n", file_path);
		handle_not_found_request(client_fd, env);
		free(file_path);
		return;
	}

	// Determine the correct MIME type
	const char *mime_type = get_content_type(filename);

	// Send headers
	char header[BUFFER_LEN];
	int header_len = snprintf(header, BUFFER_LEN,
							  "HTTP/1.1 200 OK\r\n"
							  "Content-Type: %s\r\n"
							  "\r\n",
							  mime_type);
	send(client_fd, header, header_len, 0);

	// Send file content
	while ((bytes_read = fread(buffer, 1, BUFFER_LEN, file)) > 0)
	{
		send(client_fd, buffer, bytes_read, 0);
	}

	fclose(file);
	free(file_path);
}

void handle_root_endpoint(int client_fd, t_env *env)
{

	handle_file_request(client_fd, "home.html", "./src/static_html/", "200 OK",
						get_content_type(".html"), env);
}

void handle_user_agent_endpoint(int client_fd, char *request)
{
	handle_text_response(client_fd, get_header_value("User-Agent: ", request));
}

void handle_files_endpoint(int client_fd, char *argument, char *files_path,
						   char *content_type, t_env *env)
{
	// files expect octect response
	handle_file_request(client_fd, argument, files_path, "200 OK", content_type,
						env);
}

void handle_echo_endpoint(t_env *env)
{
	// echo expects text response
	strncpy(env->response_body, env->argument, strlen(env->argument));
	handle_response(env, get_content_type(NULL));
	// handle_text_response(client_fd, argument);
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

void handle_response(t_env *env, char *response_type)
{
	char header[RESPONSE_LEN];
	bzero(header, sizeof(header));
	int header_len = snprintf(header, RESPONSE_LEN - 1, "HTTP/1.1 200 OK\r\n");

	if (response_type != NULL)
	{
		header_len +=
			snprintf(header + header_len, RESPONSE_LEN - header_len - 1,
					 "Content-Type: %s\r\n", response_type);
	}

	if (env->gzip_encoding && env->response_body[0] != '\0')
	{
		char *compressed = NULL;
		int compressed_len = 0;

		if (gzip_compress(env->response_body, strlen(env->response_body),
						  &compressed, &compressed_len) == 0)
		{
			header_len +=
				snprintf(header + header_len, RESPONSE_LEN - header_len - 1,
						 "Content-Encoding: gzip\r\n"
						 "Content-Length: %d\r\n\r\n",
						 compressed_len);

			// Send header
			send(env->client_fd, header, header_len, 0);
			// Send compressed body
			send(env->client_fd, compressed, compressed_len, 0);
			free(compressed);
			return;
		}
		// If compression fails, fall through to uncompressed response
	}
	if (env->response_body[0] != '\0')
	{
		header_len +=
			snprintf(header + header_len, RESPONSE_LEN - header_len - 1,
					 "Content-Length: %zu\r\n", strlen(env->response_body));
	}
	header_len +=
		snprintf(header + header_len, RESPONSE_LEN - header_len - 1, "\r\n");

	send(env->client_fd, header, header_len, 0);
	if (env->response_body[0] != '\0')
	{
		send(env->client_fd, env->response_body, strlen(env->response_body), 0);
	}
}
// Modify the handle_get_request function to handle static files
void handle_get_request(t_env *env, int client_fd, char *endpoint,
						char *argument, char *files_path, char *request)
{
	if (!strcmp(endpoint, ""))
	{
		handle_root_endpoint(client_fd, env);
	}
	else if (!strcmp(endpoint, "user-agent"))
	{
		handle_user_agent_endpoint(client_fd, request);
	}
	else if (!strcmp(endpoint, "files"))
	{
		handle_files_endpoint(client_fd, argument, files_path,
							  get_content_type("octet-stream"), env);
	}
	else if (!strcmp(endpoint, "echo"))
	{
		handle_echo_endpoint(env);
	}
	else
	{
		// Try to serve the file from the static directory
		char *static_path = "./src/static/";
		handle_file_request(client_fd, env->path, static_path, "200 OK", NULL,
							env);
	}
}

void handle_post_request(int client_fd, char *endpoint, char *argument,
						 char *files_path, char *request, t_env *env)
{
	if (!strcmp(endpoint, "files"))
	{
		handle_files_post(client_fd, argument, files_path, request);
	}
	else
	{
		handle_not_found_request(client_fd, env);
	}
}

void handle_request(int client_fd, t_env *env)
{
	if (read_request(env->request, client_fd) == -1)
	{
		perror("Something went wrong: recv()");
		return;
	}

	parse_method_path(env->request, env->method, env->path);
	split_url(env->path, env->endpoint, env->argument);

	parse_request(env->request, "Content-Type: ", env->content_type);
	if (parse_request(env->request, "Accept-Encoding: ", env->encoding) == 0)
		env->gzip_encoding = strstr(env->encoding, "gzip") != NULL;
	if (parse_request(env->request,
					  "Content-Length: ", env->content_length_str) == 0)
		env->content_length = atoi(env->content_length_str);

	printf("\n%s\n", env->request);
	// printf("Files path: %s\n", env->files_path);
	// printf("\tMethod: %s\n", env->method);
	// printf("\tFull Path: %s\n", env->path);
	// printf("Endpoint: %s\n", env->endpoint);
	// printf("Argument: %s\n", env->argument);
	// printf("\tContent-Length: %zu\n", env->content_length);
	// printf("\tContent-Type: %s\n", env->content_type);
	// printf("Gzip Encoding: %s\n", env->gzip_encoding ? "Yes" : "No");

	if (!strncmp(env->method, "GET", strlen(env->method)))
	{
		handle_get_request(env, client_fd, env->endpoint, env->argument,
						   env->files_path, env->request);
	}
	else if (!strncmp(env->method, "POST", strlen(env->method)))
	{
		handle_post_request(client_fd, env->endpoint, env->argument,
							env->files_path, env->request, env);
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
	handle_request(env->client_fd, env);
	close(env->client_fd);
	return NULL;
}

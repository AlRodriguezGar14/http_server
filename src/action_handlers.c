#include "server.h"

#define OK_STATUS "HTTP/1.1 200 OK\r\n\r\n"
#define NOT_FOUND_STATUS "HTTP/1.1 404 Not Found\r\n\r\n"
#define CREATED_STATUS "HTTP/1.1 201 Created\r\n\r\n"
#define UNPROCESSABLE_STATUS "HTTP/1.1 422 Unprocessable Content\r\n\r\n"

int read_request(char request[BUFFER_LEN], int client_fd)
{
	ssize_t bytes_read = 0;
	ssize_t total_bytes = 0;

	while ((bytes_read = recv(client_fd, request + total_bytes,
							  BUFFER_LEN - total_bytes, 0)) > 0)
	{
		total_bytes += bytes_read;

		if (total_bytes >= BUFFER_LEN)
		{
			puts("Error: the request is too long");
			request[BUFFER_LEN - 1] = '\0';
			return -1;
		}

		request[total_bytes] = '\0';

		if (strstr(request, "\r\n\r\n") != NULL)
		{
			// Entire request received
			break;
		}
	}
	return bytes_read;
}

void send_status_response(int client_fd, const char *status)
{
	send(client_fd, status, strlen(status), 0);
}

void handle_root_request(int client_fd)
{
	send_status_response(client_fd, OK_STATUS);
}

void handle_not_found_request(int client_fd, t_env *env)
{
	handle_file_request(client_fd, "not_found.html", "./src/static_html/", env);
}

void handle_text_response(int client_fd, const char *text)
{
	char response[RESPONSE_LEN];
	snprintf(response, sizeof(response),
			 "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
			 "%zu\r\n\r\n%s",
			 strlen(text), text);
	send(client_fd, response, strlen(response), 0);
}

FILE *open_file(const char *file_path, const char *mode)
{
	if (access(file_path, F_OK) != 0)
	{
		fprintf(stderr, "%s doesn't exist\n", file_path);
		return NULL;
	}

	FILE *file = fopen(file_path, mode);
	if (file == NULL)
	{
		fprintf(stderr, "%s failed to open\n", file_path);
	}

	return file;
}

void handle_file_request(int client_fd, const char *filename,
						 const char *files_path, t_env *env)
{
	char file_path[BUFFER_LEN];
	snprintf(file_path, sizeof(file_path), "%s%s", files_path, filename);

	FILE *file = open_file(file_path, "rb");
	if (!file)
	{
		handle_not_found_request(client_fd, env);
		return;
	}

	const char *mime_type = get_content_type(filename);

	char header[BUFFER_LEN];
	int header_len =
		snprintf(header, BUFFER_LEN,
				 "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n", mime_type);
	send(client_fd, header, header_len, 0);

	char buffer[BUFFER_LEN];
	size_t bytes_read;
	while ((bytes_read = fread(buffer, 1, BUFFER_LEN, file)) > 0)
	{
		send(client_fd, buffer, bytes_read, 0);
	}

	fclose(file);
}

void handle_root_endpoint(int client_fd, t_env *env)
{
	handle_file_request(client_fd, "home.html", "./src/static_html/", env);
}

void handle_user_agent_endpoint(int client_fd, const char *request)
{
	handle_text_response(client_fd, get_header_value("User-Agent: ", request));
}

void handle_files_endpoint(int client_fd, const char *argument,
						   const char *files_path, t_env *env)
{
	handle_file_request(client_fd, argument, files_path, env);
}

void handle_echo_endpoint(t_env *env)
{
	strncpy(env->response_body, env->argument, strlen(env->argument));
	handle_response(env, get_content_type(NULL));
}

void handle_files_post(int client_fd, const char *filename, const char *path,
					   const char *request)
{
	char file_path[BUFFER_LEN];
	snprintf(file_path, sizeof(file_path), "%s%s", path ? path : "", filename);

	FILE *file = open_file(file_path, "a");
	if (!file)
	{
		send_status_response(client_fd, UNPROCESSABLE_STATUS);
		return;
	}

	const char *request_body = strstr(request, "\r\n\r\n");
	if (request_body && strlen(request_body) >= 4)
		request_body += 4;

	fprintf(file, "%s", request_body);
	printf("Content written to <%s>\n", file_path);
	send_status_response(client_fd, CREATED_STATUS);

	fclose(file);
}

void handle_response(t_env *env, const char *response_type)
{
	char header[RESPONSE_LEN];
	int header_len = snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\n");

	if (response_type != NULL)
	{
		header_len += snprintf(header + header_len, sizeof(header) - header_len,
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
				snprintf(header + header_len, sizeof(header) - header_len,
						 "Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n",
						 compressed_len);

			send(env->client_fd, header, header_len, 0);
			send(env->client_fd, compressed, compressed_len, 0);
			free(compressed);
			return;
		}
	}

	if (env->response_body[0] != '\0')
	{
		header_len +=
			snprintf(header + header_len, sizeof(header) - header_len,
					 "Content-Length: %zu\r\n", strlen(env->response_body));
	}

	header_len +=
		snprintf(header + header_len, sizeof(header) - header_len, "\r\n");

	send(env->client_fd, header, header_len, 0);
	if (env->response_body[0] != '\0')
	{
		send(env->client_fd, env->response_body, strlen(env->response_body), 0);
	}
}

void handle_get_request(t_env *env, int client_fd)
{
	if (!strcmp(env->endpoint, ""))
	{
		handle_root_endpoint(client_fd, env);
	}
	else if (!strcmp(env->endpoint, "user-agent"))
	{
		handle_user_agent_endpoint(client_fd, env->request);
	}
	else if (!strcmp(env->endpoint, "files"))
	{
		handle_files_endpoint(client_fd, env->argument, env->files_path, env);
	}
	else if (!strcmp(env->endpoint, "echo"))
	{
		handle_echo_endpoint(env);
	}
	else
	{
		handle_file_request(client_fd, env->path, "./src/static/", env);
	}
}

void handle_post_request(int client_fd, const char *endpoint,
						 const char *argument, const char *files_path,
						 const char *request, t_env *env)
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

	if (!strncmp(env->method, "GET", strlen(env->method)))
	{
		handle_get_request(env, client_fd);
	}
	else if (!strncmp(env->method, "POST", strlen(env->method)))
	{
		handle_post_request(client_fd, env->endpoint, env->argument,
							env->files_path, env->request, env);
	}
	else
	{
		// Handle other request methods
	}
}

void *handle_client(void *arg)
{
	t_env *env = (t_env *)arg;
	handle_request(env->client_fd, env);
	close(env->client_fd);
	return NULL;
}

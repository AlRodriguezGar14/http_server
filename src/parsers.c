#include "server.h"

void parse_method_path(char *request, char *method, char *path) {
	// printf("Request: %s\n", request);
	sscanf(request, "%15s %254s", method, path);
}

void split_url(const char *url, char *endpoint, char *argument) {
	char *url_copy = strdup(url);
	char *token = NULL;
	char *rest = url_copy;

	// Skip over any leading slashes
	while (*rest == '/')
		rest++;
	token = strsep(&rest, "/");
	if (token != NULL) {
		strncpy(endpoint, token, ENDPOINT_LEN - 1);
		endpoint[ENDPOINT_LEN - 1] = '\0';
	}

	token = strsep(&rest, "/");
	if (token != NULL) {
		strncpy(argument, token, ARGUMENT_LEN - 1);
		argument[ARGUMENT_LEN - 1] = '\0';
	}

	free(url_copy);
}

int parse_request(char *request, char *target, char *content) {
	char *search_result = strstr(request, target);
	if (search_result == NULL) {
		content = NULL;
		return -1;
	}
	char *end = strstr(search_result, "\r\n");
	strncpy(content, search_result + strlen(target),
			end - search_result - strlen(target));
	return 0;
}

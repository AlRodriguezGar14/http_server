#include "server.h"

char *get_header_value(char *object, char *request) {
	char *value = strstr(request, object);

	if (value == NULL)
		return value;
	value += strlen(object);
	char *endof_value = strchr(value, '\r');
	if (endof_value != NULL)
		*endof_value = '\0';

	return value;
}

char *get_content_type(const char *extension) {
	if (!extension)
		return "text/plain";
	char *ext = strchr(extension, '.');
	if (!ext)
		return "application/octet-stream";
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

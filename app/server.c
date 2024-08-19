#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_LEN 1024

int read_request(char request[BUFFER_LEN], int client_fd) {
	ssize_t bytes_read = 0;
	ssize_t total_bytes = 0;

	while ((bytes_read = recv(client_fd, request + total_bytes,
							  BUFFER_LEN - total_bytes, 0)) > 0) {
		total_bytes += bytes_read;
		// TODO: Deal with the potential overflow
		request[total_bytes] = '\0';
		if (total_bytes > BUFFER_LEN - 1) {
			puts("Error: the request is too long");
			return -1;
		}
		if (strstr(request, "\r\n\r\n") != NULL) {
			// Entire request received
			break;
		}
	}
	return bytes_read;
}

void handle_request(int client_fd) {

	// TODO: Once the server is working and done, improve the efficiency and
	// memory use of this code
	char const *ok_status = "HTTP/1.1 200 OK\r\n\r\n";
	char const *not_found_status = "HTTP/1.1 404 Not Found\r\n\r\n";
	char request[BUFFER_LEN];
	char method[16];
	char path[256];
	bzero(request, sizeof(request));
	if (read_request(request, client_fd) == -1) {
		perror("Something went wrong: recv()");
		exit(1);
	}
	sscanf(request, "%15s %254s", method, path);
	// printf("Request type: %s, from: %s\n", method, path);
	if (!strncmp(path, "/", strlen(path)))
		send(client_fd, ok_status, strlen(ok_status), 0);
	else
		send(client_fd, not_found_status, strlen(not_found_status), 0);
}

/* The basic logic of a connection is:
 * - set addr_in info for the server
 * - open a file descriptor socket()
 * - associate the fd with the local address and port using bind()
 * - listen for incoming connections with listen()
 * - accept an incoming connection with accept()
 *
 * After being accepted, the newly created socket for the client is ready for
 * send() and recv().
 */

int main() {
	// Disable output requestering
	/* Disables output requestering, causing the output to be written directly
	 * to stdout or stderr without delay. This might reduce performance but
	 * ensures immediate output, which can be useful for debugging or working
	 * with certain consoles.
	 */
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	/* Print statements for debugging */
	printf("Logs from your program will appear here!\n");

	// Uncomment this block to pass the first stage

	int server_fd;
	uint32_t client_addr_len;
	struct sockaddr_in client_addr; // Address structure for IPv4.
									// Note: This can be cast to a generic
									// sockaddr structure when needed.

	/* Get the file descriptor
	 * Domain - What kind of socket you want: AF_INET = IPv4
	 * Type - SOCK_STREAM = Two-way connection-based byte streams (TCP)
	 * Protocol - 0 = let the socket choose the protocol it can use given type
	 * and domain
	 */
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}

	// Since the tester restarts your program quite often, setting SO_REUSEADDR
	// ensures that we don't run into 'Address already in use' errors.
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
		0) {
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}

	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET, // Address family - AF_INET = family of IPv4
		.sin_port = htons(4221),
		.sin_addr = {htonl(INADDR_ANY)},
		/* INADDR_ANY -  this lets the program run without knowing the IP
		   address of the network interface machine it is running on.

		   htonl - converts a 32-bit integer (e.g., IP address) from host byte
		   order to network byte order (big-endian).

		   htons - converts a 16-bit integer (e.g., port number) from host byte
		   order to network byte order (big-endian).
		*/
	};

	/* Bind the File Descriptor (server_fd) with the Address+Port (serv_addr) */
	if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) !=
		0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

	/* Wait for incoming connections. Listening for the port of serv_addr (no
	 * need to write it as it is bound to the socket server_fd)
	 *
	 * fd: The server file descriptor already bound to its address and port.
	 * n: number of connections allowed on the incoming queue.
	 * If an error occurs, listen() returns -1.
	 */
	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}

	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);

	/* Once a client connection is accepted from the queue, a new socket fd is
	 * created for communication with the client.
	 *
	 * fd: the listening socket
	 * addr: a pointer to a sockaddr structure to store the client's address.
	 * addr_len: the size of the address structure, updated on return to reflect
	 * the actual size of the client's address.
	 *
	 * On error, accept() returns -1 and sets errno accordingly.
	 */
	int client_fd =
		accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
	printf("Client connected\n");
	handle_request(client_fd);
	/* Ends the connection after the first connection */
	close(server_fd);

	return 0;
}

#include "server.h"

volatile sig_atomic_t run_server = true;
void handle_signals(int signal) {
  if (signal == SIGINT)
    run_server = false;
}

int main(int argc, char **argv) {
  signal(SIGINT, handle_signals);

  char files_path[PATH_LEN];
  if (argc == 3 && !strncmp(argv[1], "--directory", strlen(argv[1]))) {
    if (strlen(argv[2]) > PATH_LEN - 1) {
      fprintf(stderr, "Path is too long\n");
      return 1;
    }
    strcpy(files_path, argv[2]);
  } else
    strcpy(files_path, "/");
  /* Disables output requestering, causing the output to be written
   * directly to stdout or stderr without delay. */
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  int server_fd;
  uint32_t client_addr_len;
  struct sockaddr_in client_addr;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // SO_REUSEADDR ensures that we don't run into 'Address already in use'
  // errors.
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEADDR failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(4221),
      .sin_addr = {htonl(INADDR_ANY)},
      /* INADDR_ANY -  this lets the program run without knowing the IP
         address of the network interface machine it is running on.
      */
  };

  if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    return 1;
  }

  int connection_backlog = 80;
  if (listen(server_fd, connection_backlog) != 0) {
    printf("Listen failed: %s \n", strerror(errno));
    return 1;
  }

  printf("Waiting for a client to connect...\n");
  client_addr_len = sizeof(client_addr);

  t_thread_pool *pool = new_thread_pool(80);
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 10000;
  while (run_server) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);

    int activity = select(server_fd + 1, &readfds, NULL, NULL, &tv);

    if (activity > 0 && FD_ISSET(server_fd, &readfds)) {
      t_env *env = get_env();
      if (!env) {
        perror("Failed to allocate memory for env");
        continue;
      }
      strcpy(env->files_path, files_path);
      env->client_fd =
          accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
      if (env->client_fd == -1) {
        perror("could not accept the connection");
        release_env(env);
        continue;
      }

      t_Node *node = get_node();
      if (!node) {
        perror("Failed to allocate memory for task node");
        close(env->client_fd);
        release_env(env);
        continue;
      }
      node->env = env;

      pthread_mutex_lock(&pool->lock);
      if (nenqueue(pool->queue, node) != 0) {
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
  free_nq(pool->queue, &pool->lock);

  free_thread_pool(pool);
  close(server_fd);
  destroy_env_pool();
  destroy_node_pool();

  return 0;
}

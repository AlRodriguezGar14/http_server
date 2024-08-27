#include "server.h"

// Queue pool
t_NQueue_node node_pool[NODE_POOL_SIZE];
int node_pool_index = 0;
t_NQueue_node *free_list = NULL;

t_NQueue_node *allocate_node() {
	if (free_list) {
		t_NQueue_node *node = free_list;
		free_list = node->next;
		return node;
	} else if (node_pool_index < NODE_POOL_SIZE) {
		return &node_pool[node_pool_index++];
	} else {
		return NULL;
	}
}

void free_node(t_NQueue_node *node) {
	node->next = free_list;
	free_list = node;
}

// Queue node pool
t_node_pool *global_node_pool = NULL;

t_node_pool *create_node_pool() {
	t_node_pool *pool = malloc(sizeof(t_node_pool));
	if (!pool)
		return NULL;

	for (int i = 0; i < NODE_POOL_SIZE; i++) {
		pool->used[i] = 0;
		pool->nodes[i].env = NULL;
	}
	pool->next_free = 0;
	pthread_mutex_init(&pool->lock, NULL);
	return pool;
}

t_Node *get_node() {
	if (!global_node_pool) {
		global_node_pool = create_node_pool();
		if (!global_node_pool)
			return NULL;
	}

	pthread_mutex_lock(&global_node_pool->lock);

	if (global_node_pool->next_free >= NODE_POOL_SIZE) {
		pthread_mutex_unlock(&global_node_pool->lock);
		return NULL; // Pool is full
	}

	int index = global_node_pool->next_free;
	global_node_pool->used[index] = 1;

	// Find next free slot
	while (global_node_pool->next_free < NODE_POOL_SIZE &&
		   global_node_pool->used[global_node_pool->next_free]) {
		global_node_pool->next_free++;
	}

	pthread_mutex_unlock(&global_node_pool->lock);
	return &global_node_pool->nodes[index];
}

void release_node(t_Node *node) {
	if (!node || !global_node_pool)
		return;

	pthread_mutex_lock(&global_node_pool->lock);

	int index = (int)(node - global_node_pool->nodes);
	if (index >= 0 && index < NODE_POOL_SIZE) {
		global_node_pool->used[index] = 0;
		if (index < global_node_pool->next_free) {
			global_node_pool->next_free = index;
		}
		// Free the env if it exists
		if (node->env) {
			release_env(node->env);
			node->env = NULL;
		}
	}

	pthread_mutex_unlock(&global_node_pool->lock);
}

void destroy_node_pool() {
	if (global_node_pool) {
		pthread_mutex_lock(&global_node_pool->lock);
		// Free any remaining env structs
		for (int i = 0; i < NODE_POOL_SIZE; i++) {
			if (global_node_pool->used[i] && global_node_pool->nodes[i].env) {
				release_env(global_node_pool->nodes[i].env);
			}
		}
		pthread_mutex_unlock(&global_node_pool->lock);
		pthread_mutex_destroy(&global_node_pool->lock);
		free(global_node_pool);
		global_node_pool = NULL;
	}
}

// env
t_env_pool *global_env_pool = NULL;

t_env_pool *create_env_pool() {
	t_env_pool *pool = malloc(sizeof(t_env_pool));
	if (!pool)
		return NULL;

	for (int i = 0; i < ENV_POOL_SIZE; i++) {
		pool->used[i] = 0;
	}
	pool->next_free = 0;
	pthread_mutex_init(&pool->lock, NULL);
	return pool;
}

t_env *get_env() {
	if (!global_env_pool) {
		global_env_pool = create_env_pool();
		if (!global_env_pool)
			return NULL;
	}

	pthread_mutex_lock(&global_env_pool->lock);

	if (global_env_pool->next_free >= ENV_POOL_SIZE) {
		pthread_mutex_unlock(&global_env_pool->lock);
		return NULL;
	}

	int index = global_env_pool->next_free;
	global_env_pool->used[index] = 1;

	// Find next free slot
	while (global_env_pool->next_free < ENV_POOL_SIZE &&
		   global_env_pool->used[global_env_pool->next_free]) {
		global_env_pool->next_free++;
	}

	t_env *env = &global_env_pool->envs[index];

	bzero(env->request, BUFFER_LEN);
	bzero(env->method, METHOD_LEN);
	bzero(env->path, PATH_LEN);
	bzero(env->endpoint, ENDPOINT_LEN);
	bzero(env->argument, ARGUMENT_LEN);
	bzero(env->response_body, BODY_MAX_LEN);
	bzero(env->content_length_str, 16); // TODO: define a size
	bzero(env->content_type, CONTENT_TYPE_LEN);
	bzero(env->encoding, 256); // TODO: define a size
	env->content_length = 0;
	env->gzip_encoding = false;
	env->client_fd = -1;

	pthread_mutex_unlock(&global_env_pool->lock);
	return &global_env_pool->envs[index];
}

void release_env(t_env *env) {
	if (!env || !global_env_pool)
		return;

	pthread_mutex_lock(&global_env_pool->lock);

	int index = (int)(env - global_env_pool->envs);
	if (index >= 0 && index < ENV_POOL_SIZE) {
		global_env_pool->used[index] = 0;
		if (index < global_env_pool->next_free) {
			global_env_pool->next_free = index;
		}
	}

	pthread_mutex_unlock(&global_env_pool->lock);
}

void destroy_env_pool() {
	if (global_env_pool) {
		pthread_mutex_lock(&global_env_pool->lock);
		// Any cleanup needed for individual envs can be done here
		pthread_mutex_unlock(&global_env_pool->lock);
		pthread_mutex_destroy(&global_env_pool->lock);
		free(global_env_pool);
		global_env_pool = NULL;
	}
}

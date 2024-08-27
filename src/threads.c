#include "server.h"

t_thread_pool *new_thread_pool(int num_threads) {
	t_thread_pool *pool = malloc(sizeof(t_thread_pool));
	if (!pool)
		return NULL;
	pool->threads = malloc(sizeof(pthread_t) * num_threads);
	if (!pool->threads) {
		free(pool);
		return NULL;
	}
	pool->queue = new_nqueue();
	if (!pool->queue) {
		free(pool->threads);
		free(pool);
		return NULL;
	}
	pool->num_threads = num_threads;
	pool->active = 1;
	pthread_mutex_init(&pool->lock, NULL);
	pthread_cond_init(&pool->signal, NULL);
	for (int i = 0; i < num_threads; i++) {
		pthread_create(&pool->threads[i], NULL, worker_thread, pool);
	}
	return pool;
}

void free_thread_pool(t_thread_pool *pool) {
	if (!pool)
		return;

	// Signal all worker threads to exit
	pthread_mutex_lock(&pool->lock);
	pool->active = 0;
	pthread_cond_broadcast(&pool->signal);
	pthread_mutex_unlock(&pool->lock);

	// Wait for all worker threads to exit
	for (int i = 0; i < pool->num_threads; i++) {
		pthread_join(pool->threads[i], NULL);
	}
	free(pool->threads);
	pthread_mutex_destroy(&pool->lock);
	pthread_cond_destroy(&pool->signal);
	free(pool);
}

/* Function executed by each thread */
void *worker_thread(void *arg) {
	t_thread_pool *pool = (t_thread_pool *)arg;

	while (1) {
		pthread_mutex_lock(&pool->lock);

		// Wait for a task to be available in the queue
		while (pool->active && pool->queue->len == 0) {
			pthread_cond_wait(&pool->signal, &pool->lock);
		}

		// If the pool is no longer active, exit the thread
		if (!pool->active) {
			pthread_mutex_unlock(&pool->lock);
			pthread_exit(NULL);
		}

		t_Node *task = NULL;
		// Dequeue a task and process it
		if (pool->queue->len > 0) {
			task = pool->queue->head->value;
			if (task)
				ndequeue(pool->queue);
		}

		pthread_mutex_unlock(&pool->lock);
		if (task) {
			handle_client(task->env);
			// free(task);
			release_node(task);
		}
	}

	return NULL;
}

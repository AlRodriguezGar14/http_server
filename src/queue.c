#include "server.h"

t_NQueue *new_nqueue() {
	t_NQueue *Q = malloc(sizeof(t_NQueue));
	if (!Q)
		return NULL;

	Q->len = 0;
	Q->head = NULL;
	Q->tail = NULL;

	return Q;
}

int nenqueue(t_NQueue *queue, t_Node *value) {
	if (!queue)
		return -1;
	t_NQueue_node *node = allocate_node();
	if (!node)
		return -1;
	node->value = value;
	node->next = NULL;
	node->prev = queue->tail;
	if (!queue->head) {
		queue->head = node;
	} else {
		queue->tail->next = node;
	}
	queue->tail = node;
	queue->len++;
	return 0;
}

int ndequeue(t_NQueue *queue) {
	if (!queue || queue->len < 1)
		return -1;

	t_NQueue_node *tmp = queue->head;
	queue->head = tmp->next;
	if (queue->head) {
		queue->head->prev = NULL;
	} else {
		queue->tail = NULL;
	}
	free_node(tmp);
	queue->len--;
	return 0;
}

void free_nq(t_NQueue *queue, pthread_mutex_t *lock) {
	if (!queue)
		return;
	pthread_mutex_lock(lock);
	t_NQueue_node *node = queue->head;
	while (node) {
		t_NQueue_node *next = node->next;
		release_env(node->value->env);
		release_node(node->value);
		free_node(node);
		node = next;
	}
	free(queue);
	pthread_mutex_unlock(lock);
}

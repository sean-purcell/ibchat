#include <stdlib.h>
#include <errno.h>

#include "message.h"

const struct message_queue EMPTY_MESSAGE_QUEUE = {0, NULL, NULL};

void message_queue_init(struct message_queue *queue) {
	*queue = EMPTY_MESSAGE_QUEUE;
}

struct message *message_queue_top(struct message_queue *queue) {
	if(queue->size == 0) return NULL;
	return queue->first->m;
}

struct message *message_queue_pop(struct message_queue *queue) {
	if(queue->size == 0) return NULL;
	struct message *m = queue->first->m;

	struct message_queue_element *next = queue->first->next;

	free(queue->first);

	queue->first = next;
	queue->size--;

	if(queue->size == 0) {
		queue->first = NULL;
		queue->last = NULL;
	}

	return m;
}

int message_queue_push(struct message_queue *queue, struct message *message) {
	struct message_queue_element *next = malloc(sizeof(struct message_queue_element));
	if(next == NULL) {
		errno = ENOMEM;
		return -1;
	}

	next->m = message;
	next->next = NULL;

	if(queue->size != 0) {
		queue->last->next = next;
		queue->last = next;
	} else {
		queue->first = next;
		queue->last = next;
	}

	queue->size++;

	return 0;
}


#ifndef AWSS_MSG_QUEUE_H
#define AWSS_MSG_QUEUE_H

#include "lite-list.h"
#include "iot_import.h"
#include "awss_ap.h"

#define AWSS_URI_STR_MAX_LENGTH         (256)
#define AWSS_METHOD_STR_MAX_LENGTH      (128)

typedef struct awss_request_queue {
    list_head_t list;
    void *mutex;
    void *psem;
    int length;
} awss_request_queue_t;


typedef struct awss_msg {
    uint32_t msg_id;
    int32_t code;
    uint32_t payload_length;
    char method[AWSS_URI_STR_MAX_LENGTH];
    char uri[AWSS_METHOD_STR_MAX_LENGTH];
    char payload[];//coap:表示payload,cmp:表示params or data
} awss_msg_t;

typedef struct awss_msg_session {
    void *psem;
    awss_msg_t *request;
    awss_msg_t *response;
    unsigned int id;
} awss_msg_session_t;


typedef struct awss_request_node {
    list_head_t list_head;
    awss_msg_session_t session;
} awss_request_node_t;

void awss_msg_queue_init(awss_request_queue_t **ppqueue);
void awss_msg_queue_destroy(awss_request_queue_t *pqueue);
int awss_request_queue_push(awss_request_queue_t *req_queue, awss_request_node_t *node);
int awss_request_queue_pop(awss_request_queue_t *req_queue, awss_request_node_t *req_node);
awss_request_node_t * awss_request_queue_trigger(awss_request_queue_t *req_queue, awss_msg_t *rsp);
awss_request_node_t *awss_request_queue_timeout(awss_request_queue_t * req_queue, uint32_t msg_id);

void awss_msg_request_queue_destroy(awss_request_queue_t *req_queue);

#endif

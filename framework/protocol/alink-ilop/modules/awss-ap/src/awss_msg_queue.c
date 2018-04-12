#include <stddef.h>
#include "awss_msg_queue.h"
#include "awss_network.h"
#include "iot_import.h"
#include "lite-log.h"
#include "lite-utils.h"

#define AWSS_MSG_MAX_QUEUE_LENGTH   8

void awss_msg_queue_init(awss_request_queue_t **req_queue) {
    awss_request_queue_t *pqueue;

    if (req_queue)
        *req_queue = NULL;

    pqueue = (awss_request_queue_t *)LITE_malloc(sizeof(awss_request_queue_t));
    if ( NULL == pqueue )
    {
        log_warning("memory allocate fail.");
        return;
    }

    memset(pqueue, 0, sizeof(awss_request_queue_t));

    pqueue->mutex = HAL_MutexCreate();
    if ( NULL == pqueue->mutex )
    {
        log_warning("create mutex fail.");
        goto do_error;
    }

    pqueue->psem = HAL_SemaphoreCreate();
    if ( NULL == pqueue->psem )
    {
        log_warning("create semaphore fail.");
        goto do_error;
    }

    INIT_LIST_HEAD(&pqueue->list);
    pqueue->length = 0;


    if (req_queue)
        *req_queue = pqueue;

    return ;

do_error:
    awss_msg_queue_destroy(pqueue);

    return;
}

//destroy the queue
void awss_msg_queue_destroy(awss_request_queue_t *req_queue)
{
    if (!req_queue) {
        return;
    }

    HAL_MutexLock(req_queue->mutex);
    list_head_t *list = &req_queue->list;

    awss_request_node_t *node, *next;
    list_for_each_entry_safe(node, next, list, list_head, awss_request_node_t) {
        if (node) {
            awss_msg_session_t session = node->session;
            if (session.request)
                LITE_free(session.request);
            if (session.response)
                LITE_free(session.response);
            LITE_free(node);
        }
    }
    HAL_MutexUnlock(req_queue->mutex);
    HAL_MutexDestroy(req_queue->mutex);
    HAL_SemaphoreDestroy(req_queue->psem);

    LITE_free(req_queue);
}

int awss_request_queue_push(awss_request_queue_t * req_queue, awss_request_node_t * req_node)
{
    if (!req_node || !req_queue || req_queue->length >= AWSS_MSG_MAX_QUEUE_LENGTH) {
        log_debug("!!!awss_request_queue_push err, length=%d", req_queue->length);
        return -1;
    }

    HAL_MutexLock(req_queue->mutex);
    list_add(&req_node->list_head, &req_queue->list);
    req_queue->length++;
    HAL_MutexUnlock(req_queue->mutex);

    return 0;
}

int awss_request_queue_pop(awss_request_queue_t * req_queue, awss_request_node_t * req_node)
{
    if (!req_node || !req_queue || !req_queue->length) {
        log_debug("!!!awss_request_queue_pop err, length=%d", req_queue->length);
        return -1;
    }

    HAL_MutexLock(req_queue->mutex);
    list_del(&req_node->list_head);
    req_queue->length--;
    HAL_MutexUnlock(req_queue->mutex);

    return 0;
}

awss_request_node_t *awss_request_queue_trigger(awss_request_queue_t * req_queue, awss_msg_t * rsp)
{
    awss_request_node_t *ret = NULL;
    uint32_t msg_id = 0;

    if (!req_queue || !rsp) {
        log_debug("!!!awss_request_queue_trigger error");
        return ret;
    }
    memcpy(&msg_id, &rsp->msg_id, sizeof(uint32_t));

    HAL_MutexLock(req_queue->mutex);
    list_head_t *list = &req_queue->list;
    awss_request_node_t *node = NULL;
    list_for_each_entry(node, list, list_head, awss_request_node_t) {
        awss_msg_session_t *session = &node->session;
        if (session && session->id == msg_id) {
            session->response = rsp;
            ret = node;
            break;
        }
    }
    HAL_MutexUnlock(req_queue->mutex);

    return ret;
}

awss_request_node_t *awss_request_queue_timeout(awss_request_queue_t * req_queue, uint32_t msg_id)
{
    awss_request_node_t *ret = NULL;
    if (!req_queue) {
        log_debug("!!!awss_request_queue_timeout error");
        return ret;
    }

    HAL_MutexLock(req_queue->mutex);
    list_head_t *list = &req_queue->list;
    awss_request_node_t *node = NULL;
    list_for_each_entry(node, list, list_head, awss_request_node_t) {
        awss_msg_session_t *session = &node->session;
        if (session && session->id == msg_id) {
            ret = node;
            break;
        }
    }
    HAL_MutexUnlock(req_queue->mutex);

    return ret;
}



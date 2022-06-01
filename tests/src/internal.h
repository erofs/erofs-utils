#include "cachefiles.h"

int daemon_get_devfd(const char *fscachedir, const char *tag);

int process_open_req(int devfd, struct cachefiles_msg *msg);
int process_close_req(int devfd, struct cachefiles_msg *msg);
int process_read_req(int devfd, struct cachefiles_msg *msg);
int process_read_req_ra(int devfd, struct cachefiles_msg *msg);


int process_open_req_fail(int devfd, struct cachefiles_msg *msg);
int process_close_req_fail(int devfd, struct cachefiles_msg *msg);
int process_read_req_fail(int devfd, struct cachefiles_msg *msg);

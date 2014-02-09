#ifndef _NGX_MPUT_MODULE_H_INCLUDE_
#define _NGX_MPUT_MODULE_H_INCLUDE_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_module_t ngx_http_mput_module;

typedef struct {
    ngx_http_upstream_conf_t upstream;
} ngx_http_mput_loc_conf_t;

typedef struct {
    ngx_http_request_t *request;
} ngx_http_mput_ctx_t;

static ngx_int_t
ngx_http_mput_handler(ngx_http_request_t *r);


#endif /* _NGX_MPUT_MODULE_H_INCLUDE_ */

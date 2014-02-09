#include "ngx_http_mput_module.h"

static ngx_int_t
ngx_http_mput_init(ngx_conf_t *cf);

static char *
ngx_http_mput_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *
ngx_http_mput_create_loc_conf(ngx_conf_t *cf);

/*
static char *
ngx_http_mput_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
*/

static ngx_command_t ngx_http_mput_commands[] = {
    { ngx_string("mput_pass"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_mput_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
};

static ngx_http_module_t ngx_http_mput_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_mput_init,                 /* postconfiguration */
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    ngx_http_mput_create_loc_conf,      /* create location configration */
    NULL,                               /* merge location configuration */
};

ngx_module_t ngx_http_mput_module = {
    NGX_MODULE_V1,                  
    &ngx_http_mput_module_ctx,      /* module context */
    ngx_http_mput_commands,         /* module directive */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_mput_init(ngx_conf_t *cf) {
    ngx_conf_log_error(NGX_LOG_ALERT, cf, 0, "ngx_http_mput_init");
    return NGX_OK;
}

static void *
ngx_http_mput_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_mput_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mput_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     */
    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = 60000;
    conf->upstream.send_timeout = 60000;
    conf->upstream.read_timeout = 60000;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = ngx_pagesize;

    conf->upstream.busy_buffers_size_conf = 2*ngx_pagesize;
    conf->upstream.max_temp_file_size_conf = 20*ngx_pagesize;
    conf->upstream.temp_file_write_size_conf = 2*ngx_pagesize;;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

#if (NGX_HTTP_CACHE)
    conf->upstream.cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_lock = NGX_CONF_UNSET;
    conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
#endif

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.intercept_errors = NGX_CONF_UNSET;

    conf->upstream.cyclic_temp_file = 0;

    ngx_str_set(&conf->upstream.module, "mput");

    return conf;
}

/*
static char *
ngx_http_mput_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_mput_loc_conf_t *prev = parent;
    ngx_http_mput_loc_conf_t *conf = child;

    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
                &prev->upstream, ngx_http_proxy_hide_headers, &hash)
            != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}*/

static char *
ngx_http_mput_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_mput_loc_conf_t *mlcf = conf;

    ngx_str_t *value;
    ngx_url_t u;

    ngx_http_core_loc_conf_t *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }
    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.no_resolve = 1;

    mlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mput_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mput_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mput_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mput_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_mput_filter_init(void *data);
static ngx_int_t ngx_http_mput_filter(void *data, ssize_t bytes);
static void ngx_http_mput_abort_request(ngx_http_request_t *r);
static void ngx_http_mput_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t
ngx_http_mput_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "enter mput upstream");

    //ngx_int_t rc;
    ngx_http_upstream_t *u;
    ngx_http_mput_ctx_t *ctx;
    ngx_http_mput_loc_conf_t *mlcf;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;
    ngx_str_set(&u->schema, "mput://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_mput_module;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mput_module);
    
    u->conf = &mlcf->upstream;
    u->buffering = mlcf->upstream.buffering;

    u->create_request = ngx_http_mput_create_request;
    u->reinit_request = ngx_http_mput_reinit_request;
    u->process_header = ngx_http_mput_process_header;
    u->abort_request = ngx_http_mput_abort_request;
    u->finalize_request = ngx_http_mput_finalize_request;

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_mput_ctx_t));

    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ngx_http_set_ctx(r, ctx, ngx_http_mput_module);
    u->input_filter_init = ngx_http_mput_filter_init;
    u->input_filter = ngx_http_mput_filter;
    u->input_filter_ctx = ctx;

    r->main->count ++;

    ngx_http_upstream_init(r);
    return NGX_DONE;
}

static ngx_int_t
ngx_http_mput_create_request(ngx_http_request_t *r) {
    ngx_int_t length;
    ngx_buf_t *b;
    ngx_chain_t *cl;
    //ngx_http_mput_ctx_t *ctx;
    //ngx_http_mput_loc_conf_t *mlcf;

    static ngx_str_t cmd = ngx_string("put proc.loadavg.1m 1391953118 0.36 host=foo");
    length = cmd.len - 1;
    b = ngx_create_temp_buf(r->pool, length);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    b->last = ngx_copy(b->last, cmd.data, cmd.len);
    *b->last++ = CR;
    *b->last++ = LF;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mput_reinit_request(ngx_http_request_t *r) {
    return NGX_OK;
}

static ngx_int_t
ngx_http_mput_process_header(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "process mput header");
    //u_char *p;
    ngx_str_t line;
    ngx_http_upstream_t *u;
    ngx_buf_t *b;

    u = r->upstream;
    b = &u->buffer;

    line.len = b->last - b->pos - 1;
    line.data = b->pos;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "buffer %V", &line);
    
    //if (b->last - b->pos < (ssize_t) sizeof(u_char)) {
    //    return NGX_AGAIN;
    //}

    u->headers_in.content_length_n = line.len;
    u->headers_in.status_n = NGX_HTTP_OK;
    u->state->status = NGX_HTTP_OK;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mput_filter_init(void *data) {
    return NGX_OK;
}

static void
ngx_http_mput_abort_request(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "abort http mput request");
    return;

}

static void
ngx_http_mput_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "finalize http mput request");
    return;
}

static ngx_int_t
ngx_http_mput_filter(void *data, ssize_t bytes) {
    ngx_http_request_t  *r = data;
 
    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;
 
    u = r->upstream;
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }
 
    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }
 
    *ll = cl;
 
    cl->buf->flush = 1;
    cl->buf->memory = 1;
    b = &u->buffer;
 
    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;
    if (u->length == NGX_MAX_SIZE_T_VALUE) {
        return NGX_OK;
    }
    u->length -= bytes;
 
    return NGX_OK;
}

/*
 * Copyright (C) Simon Lee@Huawei Tech.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    off_t        start;
    off_t        end;
    off_t        ffix;
    off_t        length;
    ngx_str_t    range;
} ngx_http_nphase_range_t;

typedef struct {
    ngx_str_t   uri;
    ngx_int_t   uri_var_index;
    ngx_int_t   range_var_index;
} ngx_http_nphase_conf_t;

typedef struct {
    ngx_uint_t                pr_status;
    ngx_str_t                 uri_var_value;

    ngx_array_t               range_in;
    ngx_http_nphase_range_t   range_sent;
    
    ngx_str_t                 loc_body_c;
    unsigned                  sr_done:1;
    unsigned                  sr_error:1;
    unsigned                  header_sent:1;
    unsigned                  body_ready:1;
    unsigned                  loc_ready:1;
    unsigned                  loc_body:1;
} ngx_http_nphase_ctx_t;

typedef struct {
    ngx_str_t                 bk_addr;
} ngx_http_nphase_sub_ctx_t;

typedef struct {
    ngx_int_t                 index;
    ngx_http_complex_value_t  value;
    ngx_http_set_variable_pt  set_handler;
} ngx_http_nphase_variable_t;


static void * ngx_http_nphase_create_conf(ngx_conf_t *cf);
static char * ngx_http_nphase_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_nphase_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_nphase_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_nphase_content_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_nphase_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
ngx_int_t    ngx_http_nphase_filter_init(ngx_conf_t *cf);    
static ngx_int_t ngx_http_nphase_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_nphase_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
void ngx_http_nphase_discard_bufs(ngx_pool_t *pool, ngx_chain_t *in);
static char *ngx_http_nphase_uri(ngx_conf_t *cf, ngx_command_t *cmd, void *conf); 
static char *ngx_http_nphase_set_uri_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_nphase_set_range_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_http_nphase_range_parse(ngx_http_request_t *r, ngx_http_nphase_ctx_t *ctx);
ngx_int_t ngx_http_nphase_content_range_parse(u_char *p, ngx_http_nphase_range_t *range);
ngx_int_t ngx_http_nphase_copy_header_value(ngx_list_t *headers, ngx_str_t *k, ngx_str_t *v);
ngx_int_t ngx_http_nphase_run_subrequest(ngx_http_request_t *r, ngx_http_nphase_ctx_t *ctx,
                                                        ngx_str_t *uri, ngx_str_t *args);

static ngx_command_t  ngx_http_nphase_commands[] = {

    { ngx_string("nphase_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_nphase_uri,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
    { ngx_string("nphase_set_uri_var"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_nphase_set_uri_var,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("nphase_set_range_var"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_nphase_set_range_var,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_nphase_module_ctx = {
    NULL,                            /* preconfiguration */
    ngx_http_nphase_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_nphase_create_conf,     /* create location configuration */
    ngx_http_nphase_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_nphase_module = {
    NGX_MODULE_V1,
    &ngx_http_nphase_module_ctx,     /* module context */
    ngx_http_nphase_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt    ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static void *
ngx_http_nphase_create_conf(ngx_conf_t *cf)
{
    ngx_http_nphase_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_nphase_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->uri_var_index = NGX_CONF_UNSET_UINT;
    conf->range_var_index = NGX_CONF_UNSET_UINT;
    return conf;
}


static char *
ngx_http_nphase_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_nphase_conf_t *prev = parent;
    ngx_http_nphase_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");
    ngx_conf_merge_value(conf->uri_var_index, prev->uri_var_index, -1);
    ngx_conf_merge_value(conf->range_var_index, prev->range_var_index, -1);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_nphase_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_nphase_access_handler;

    ngx_http_nphase_filter_init(cf);
    return NGX_OK;
}


static ngx_int_t
ngx_http_nphase_access_handler(ngx_http_request_t *r)
{
    ngx_http_nphase_ctx_t             *ctx;
    ngx_http_nphase_conf_t            *npcf;
    ngx_http_variable_value_t         *var;
    ngx_int_t                     rc;
    ngx_http_nphase_range_t  *rin;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "nphase access handler");

    npcf = ngx_http_get_module_loc_conf(r, ngx_http_nphase_module);

    if (npcf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_nphase_module);

    if (ctx != NULL) {
        if (ctx->sr_error == 1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        /* phase 2 process */
        if (ctx->body_ready == 1) {
            if (ctx->sr_done == 0) {
                return NGX_AGAIN;
            }
            
            if (ctx->range_in.nelts > 1) {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            rin = ctx->range_in.elts;
            if (rin->end == -1) {
                rin->end = r->headers_out.content_length_n - 1;
            }
            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "nphase range_in s:%O e:%O ffix:%O, range_sent s:%O e:%O", 
                   rin->start, rin->end, rin->ffix, 
                   ctx->range_sent.start, ctx->range_sent.end);
            
            /* todo: compare range_in and range_sent to find out range need send */

            if (ctx->range_sent.end < rin->end + 1) {
                ctx->loc_ready = 0;
                ctx->body_ready = 0;

                /* change range variable */
                var = ngx_http_get_indexed_variable(r, npcf->range_var_index);
                if (var == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                                
                var->data = ngx_pnalloc(r->pool, 
                                sizeof("bytes=-") + 2 * NGX_OFF_T_LEN);
                if (var->data == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                var->len = ngx_sprintf(var->data, "bytes=%O-%O", 
                                            ctx->range_sent.end, rin->end)
                                    - var->data;
                
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                "nphase create a new range_var:%V", var);

                /* restore next phase subrequest uri to phase 1 uri */
                var = ngx_http_get_indexed_variable(r, npcf->uri_var_index);
                if (var == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                var->data = ctx->uri_var_value.data;
                var->len  = ctx->uri_var_value.len;
                
                if (ngx_http_nphase_run_subrequest(r, ctx, &npcf->uri, NULL) 
                        != NGX_OK) 
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                return NGX_AGAIN;
            }
            return NGX_OK;
        }

        /* phase 1 process */
        if (ctx->loc_ready == 1) {
            /* run subrequest by loc_body_c */
            if (ctx->loc_body_c.len == 0) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ctx->loc_body_c.data[0] == '/') {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            var = ngx_http_get_indexed_variable(r, npcf->uri_var_index);
            if (var == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            var->len = ctx->loc_body_c.len;
            var->data = ctx->loc_body_c.data;
            
            if (ngx_http_nphase_run_subrequest(r, ctx, &npcf->uri, NULL) 
                    != NGX_OK) 
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
        
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "nphase location uri and body both not ready");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;    
    }

    /* initial module ctx */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_nphase_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* get "nphase_set_uri_var" variable  and concat request uri to it 
    u_char      *p;
    u_char      *ptmp;
    size_t      len;

    var = ngx_http_get_indexed_variable(r, npcf->uri_var_index);
    if (var == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    len = r->uri.len + var->len;
    p = ngx_palloc(r->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ptmp = p;
    p = ngx_copy(p, var->data, var->len);
    p = ngx_copy(p, r->uri.data, r->uri.len);
    var->data = ptmp;
    */ 

    /* parse headers_in range to ctx->range_in*/
    if (r->headers_in.range != NULL) {
        if (r->headers_in.range->value.len >= 7
            && ngx_strncasecmp(r->headers_in.range->value.data,
                           (u_char *) "bytes=", 6)
               == 0) 
        {
            if (ngx_array_init(&ctx->range_in, r->pool, 1, sizeof(ngx_http_nphase_range_t))
                != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rc = ngx_http_nphase_range_parse(r, ctx);
            
            if (rc == NGX_OK) {
                if (ctx->range_in.nelts > 1) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "multipart range request not supported");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                r->allow_ranges = 1;
            } else {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }
        } else {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }
    } else {
        if (ngx_array_init(&ctx->range_in, r->pool, 1, sizeof(ngx_http_nphase_range_t))
            != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        ngx_http_nphase_range_t  *range;

        range = ngx_array_push(&ctx->range_in);
        if (range == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        range->start = 0;
        range->end   = -1;
        range->ffix  = -1;
    }
    
    /* run a subrequest to nphase_uri */
    if (ngx_http_nphase_run_subrequest(r, ctx, &npcf->uri, NULL) 
            != NGX_OK) 
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_nphase_module);

    /* save phase 1 uri to ctx->uri_var_value */
    var = ngx_http_get_indexed_variable(r, npcf->uri_var_index);
    if (var == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->uri_var_value.data = var->data;
    ctx->uri_var_value.len  = var->len;
    
    return NGX_AGAIN;
}

static ngx_int_t
ngx_http_nphase_content_handler(ngx_http_request_t *r)
{
    ngx_http_nphase_ctx_t   *ctx;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "nphase content handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_nphase_module);

    /* Entering content phase means valid response has been 
            received by subrequest. */
    
    if (ctx == NULL) {
        return NGX_DECLINED;
    }

    if (! ctx->header_sent) {
        if (ngx_http_send_header(r) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    /* send out buf in case of not sending by subrequest */
    if (r->out && r->out->buf && r->out->buf->pos) {
        return ngx_http_output_filter(r, NULL);
    }
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_nphase_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_nphase_ctx_t   *ctx = data;   /* parent ctx */

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "nphase subrequest done s:%d", r->headers_out.status);

    if (r->headers_out.status >= NGX_HTTP_SPECIAL_RESPONSE 
        && r->headers_out.status != NGX_HTTP_MOVED_TEMPORARILY ) 
    {
        ctx->sr_error = 1;
    }

    ctx->sr_done = 1;
    
    return rc;
}

ngx_int_t
ngx_http_nphase_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_nphase_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_nphase_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_nphase_header_filter(ngx_http_request_t *r)
{
    ngx_http_nphase_ctx_t                   *pr_ctx;
    ngx_http_nphase_sub_ctx_t               *sr_ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "nphase header filter status:%d", 
                   r->headers_out.status);
                   
    if (r == r->main) {
        /* parent request */
        pr_ctx = ngx_http_get_module_ctx(r, ngx_http_nphase_module);

        if (! pr_ctx) {
            return ngx_http_next_header_filter(r);
        }
        
        if (pr_ctx->header_sent) {
            return NGX_OK;
        }
        
        pr_ctx->header_sent = 1;

        r->headers_out.status = pr_ctx->pr_status;
        
        if (r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT) {
            /* set http code 200 for next range filter */
            r->headers_out.status = NGX_HTTP_OK;
            r->headers_out.status_line.len = 0;
        }
        
        return ngx_http_next_header_filter(r);
    }else{
        /* sub request */
        sr_ctx = ngx_http_get_module_ctx(r, ngx_http_nphase_module);
        
        if (! sr_ctx) {
            return ngx_http_next_header_filter(r);
        }

        if (! r->parent) {
            return ngx_http_next_header_filter(r);
        }
        
        pr_ctx = ngx_http_get_module_ctx(r->parent, ngx_http_nphase_module);
        
        if (! pr_ctx) {
            return ngx_http_next_header_filter(r);
        }

        if (pr_ctx->body_ready) {
            return NGX_OK;
        }

        if (r->headers_out.status >= NGX_HTTP_SPECIAL_RESPONSE 
            && r->headers_out.status != NGX_HTTP_MOVED_TEMPORARILY ) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY ) {
        
            if (! r->headers_out.location) {
                u_char              *p;
                size_t              len = 0;
                
                ngx_str_t           val;
                ngx_str_t           key = ngx_string("Location");

                if (ngx_http_nphase_copy_header_value(
                        &r->headers_out.headers, &key, &val) == NGX_OK) 
                {
                    if ( val.data[0] == '/' ) {
                        len += r->upstream->schema.len;
                        len += r->upstream->resolved->host.len;
                        if (len == 0) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }

                    len += val.len;
                    p = ngx_palloc(r->pool, len);
                    if (p == NULL) {
                        return NGX_ERROR;
                    }
                    pr_ctx->loc_body_c.data = p;
                    pr_ctx->loc_body_c.len = len;
                                    
                    if ( val.data[0] == '/' ) {
                        p = ngx_copy(p, r->upstream->schema.data, 
                                        r->upstream->schema.len);
                        p = ngx_copy(p, r->upstream->resolved->host.data, 
                                        r->upstream->resolved->host.len);
                    }
                    
                    p = ngx_copy(p, val.data, val.len);
                    
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                    "nphase get next phase loc: %V", 
                                    &pr_ctx->loc_body_c);
                    
                    pr_ctx->loc_ready = 1;
                    return NGX_OK;                
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "nphase get 302 from upstream without location string");
                return NGX_ERROR;
            }
            
            pr_ctx->loc_body_c.data = ngx_palloc(r->pool, 
                                        r->headers_out.location->value.len);
            if (pr_ctx->loc_body_c.data == NULL) {
                return NGX_ERROR;
            }
                            
            ngx_memcpy(pr_ctx->loc_body_c.data, 
                        r->headers_out.location->value.data,
                        r->headers_out.location->value.len);
            pr_ctx->loc_body_c.len = r->headers_out.location->value.len;
            
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "nphase get next phase loc: %V", 
                            &pr_ctx->loc_body_c);
            
            pr_ctx->loc_ready = 1;
            return NGX_OK;
        }

        /* upstream return 20x
                parse upstream header Content-Range  */
        ngx_str_t val;
        ngx_str_t key = ngx_string("Content-Range");
        
        if (ngx_http_nphase_copy_header_value(&r->headers_out.headers, &key, &val) == NGX_OK) 
        {
            if (val.len >= sizeof("bytes ")
                && ngx_strncasecmp(val.data, (u_char *) "bytes ", sizeof("bytes ") - 1) == 0)
            {
                ngx_http_nphase_range_t range;
                ngx_int_t               rc;

                rc = ngx_http_nphase_content_range_parse(
                        (u_char *)(val.data + sizeof("bytes ") - 1), &range);
                
                if (rc == NGX_OK) {
                    /* set  content_length_n to whole file size,
                                            rather than content length per request
                                        */
                    r->parent->headers_out.content_length_n = range.length;
                } else {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
        }
        
        pr_ctx->body_ready = 1;
        return NGX_OK;
    }
    
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_nphase_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_nphase_sub_ctx_t       *sr_ctx;
    ngx_http_nphase_ctx_t           *pr_ctx;
    
    if (in == NULL) {
        return ngx_http_next_body_filter(r, NULL);
    }

    
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "nphase body filter status:%d", 
                   r->headers_out.status);
    
    if (r == r->main) {
        /* parent request */
        return ngx_http_next_body_filter(r, in);
    }else{
        sr_ctx = ngx_http_get_module_ctx(r, ngx_http_nphase_module);
        
        if (!sr_ctx) {
            return ngx_http_next_body_filter(r, in);
        }
    
        if (! r->parent) {
            return ngx_http_next_header_filter(r);
        }
        
        pr_ctx = ngx_http_get_module_ctx(r->parent, ngx_http_nphase_module);
        
        if (! pr_ctx) {
            return ngx_http_next_header_filter(r);
        }

        if (! pr_ctx->body_ready) {
            return NGX_OK;
        }
        
        if (! pr_ctx->header_sent){
            pr_ctx->pr_status = r->headers_out.status;

            if (r->parent->headers_out.content_length_n == -1) {
                r->parent->headers_out.content_length_n = 
                    r->headers_out.content_length_n;
            }
            
            if (ngx_http_send_header(r->parent) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        /* todo: update ctx->range_sent */
        if (r->upstream 
            && r->upstream->pipe
            && r->upstream->pipe->downstream) 
        {
            pr_ctx->range_sent.end = 
                r->upstream->pipe->downstream->sent - r->parent->header_size;
        }

        return ngx_http_output_filter(r->parent, in);        
    }
}

void
ngx_http_nphase_discard_bufs(ngx_pool_t *pool, ngx_chain_t *in)
{
    ngx_chain_t         *cl;

    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
        cl->buf->file_pos = cl->buf->file_last;
    }
}

static char *
ngx_http_nphase_uri(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_nphase_conf_t      *npcf = conf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_str_t        *value;

    if (npcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        npcf->uri.len = 0;
        npcf->uri.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    npcf->uri = value[1];

    /* register content phase handler */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    clcf->handler = ngx_http_nphase_content_handler;

    return NGX_CONF_OK;
}

static char *
ngx_http_nphase_set_uri_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_nphase_conf_t      *npcf = conf;
    ngx_str_t                   *value;
    
    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    npcf->uri_var_index = ngx_http_get_variable_index(cf, &value[1]);
    if (npcf->uri_var_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_nphase_set_range_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_nphase_conf_t      *npcf = conf;
    ngx_str_t                   *value;
    
    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    npcf->range_var_index = ngx_http_get_variable_index(cf, &value[1]);
    if (npcf->range_var_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_nphase_range_parse(ngx_http_request_t *r, ngx_http_nphase_ctx_t *ctx)
{
    u_char            *p;
    off_t              start, end, ffix;
    ngx_uint_t         suffix;
    ngx_http_nphase_range_t  *range;

    p = r->headers_in.range->value.data + 6;

    for ( ;; ) {
        start = 0;
        end = 0;
        suffix = 0;
        ffix = -1;

        while (*p == ' ') { p++; }

        if (*p != '-') {
            if (*p < '0' || *p > '9') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p >= '0' && *p <= '9') {
                start = start * 10 + *p++ - '0';
            }

            while (*p == ' ') { p++; }

            if (*p++ != '-') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p == ' ') { p++; }

            if (*p == ',' || *p == '\0') {
                range = ngx_array_push(&ctx->range_in);
                if (range == NULL) {
                    return NGX_ERROR;
                }

                range->start = start;
                range->end = -1;
                range->ffix = ffix;

                if (*p++ != ',') {
                    return NGX_OK;
                }

                continue;
            }

        } else {
            suffix = 1;
            p++;
        }

        if (*p < '0' || *p > '9') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            end = end * 10 + *p++ - '0';
        }

        while (*p == ' ') { p++; }

        if (*p != ',' && *p != '\0') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        if (suffix) {
            ffix = end;
            start = -1;
            end = -1;
        }

        if (start > end) {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        range = ngx_array_push(&ctx->range_in);
        if (range == NULL) {
            return NGX_ERROR;
        }

        range->start = start;
        range->end = end;
        range->ffix = ffix;

        if (*p++ != ',') {
            return NGX_OK;
        }
    }
}


ngx_int_t
ngx_http_nphase_content_range_parse(u_char *p, ngx_http_nphase_range_t *range)
{
    off_t              start, end, length;
    ngx_uint_t         suffix;

    start = 0;
    end = 0;
    length = 0;
    suffix = 0;

    while (*p == ' ') { p++; }

    if (*p != '-') {
        if (*p < '0' || *p > '9') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            start = start * 10 + *p++ - '0';
        }

        while (*p == ' ') { p++; }

        if (*p++ != '-') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p == ' ') { p++; }

        if (*p == ',' || *p == '\0') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

    } else {
        suffix = 1;
        p++;
    }

    if (*p < '0' || *p > '9') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    while (*p >= '0' && *p <= '9') {
        end = end * 10 + *p++ - '0';
    }
    if (start > end) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }
    if (!suffix) {
       range->start = start;
    }
    range->end = end;

    while (*p == ' ') { p++; }

    if (*p != '/') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }
    p++;
    
    if (*p < '0' || *p > '9') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }
    while (*p >= '0' && *p <= '9') {
        length = length * 10 + *p++ - '0';
    }
    range->length = length;
    if (*p++ != ',') {
        return NGX_OK;
    }
    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
}


ngx_int_t
ngx_http_nphase_copy_header_value(ngx_list_t *headers, ngx_str_t *k, ngx_str_t *v)
{
    ngx_uint_t          n;
    ngx_table_elt_t     *ho;
    u_char              *p;
    size_t              len = 0;

    for (n = 0; n < headers->part.nelts; n++) {
        ho = &((ngx_table_elt_t *)headers->part.elts)[n];
        if (ngx_strncmp(ho->key.data, k->data, k->len) == 0) {

            len += ho->value.len;
            p = ngx_palloc(headers->pool, len);
            if (p == NULL) {
                return NGX_ERROR;
            }
            
            v->data = p;
            v->len = len;
            p = ngx_copy(p, ho->value.data, ho->value.len);
            p = 0;
            
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_http_nphase_run_subrequest(ngx_http_request_t *r, 
                                            ngx_http_nphase_ctx_t *ctx,
                                            ngx_str_t *uri,
                                            ngx_str_t *args)
{
    ngx_http_post_subrequest_t      *ps;
    ngx_http_nphase_sub_ctx_t       *sr_ctx;
    ngx_http_request_t              *sr;

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_nphase_subrequest_done;
    ps->data = ctx;
    ctx->sr_done = 0;

    if (ngx_http_subrequest(r, uri, args, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sr_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_nphase_sub_ctx_t));
    if (sr_ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(sr, sr_ctx, ngx_http_nphase_module);

    return NGX_OK;
}

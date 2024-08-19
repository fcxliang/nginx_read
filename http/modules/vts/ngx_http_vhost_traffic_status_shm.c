
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_filter.h"
#include "ngx_http_vhost_traffic_status_shm.h"


static ngx_int_t ngx_http_vhost_traffic_status_shm_add_node(ngx_http_request_t *r,
    ngx_str_t *key, unsigned type);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_node_upstream(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, unsigned init);

#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_node_cache(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, unsigned init);
#endif

static ngx_int_t ngx_http_vhost_traffic_status_shm_add_filter_node(ngx_http_request_t *r,
    ngx_array_t *filter_keys);

//从node开始遍历所有的树节点，计算每个节点的容量，累积到shm_info上
//如果是计数节点的stat_upstream.typeFG类型的，看目前节点filter key是否能匹配上
//filter_max_node_matches数组里的字符串，内匹配上的话也要记录shm_info
void
ngx_http_vhost_traffic_status_shm_info_node(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_shm_info_t *shm_info,
    ngx_rbtree_node_t *node)
{
    ngx_str_t                              filter;
    ngx_uint_t                             size;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
        // 这是一个节点真实大小
        // ngx_rbtree_node_t + ngx_http_vhost_traffic_status_node_t + data的空间
        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_vhost_traffic_status_node_t, data)
               + vtsn->len;

        shm_info->used_size += size;
        shm_info->used_node++;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            filter.data = vtsn->data;
            filter.len = vtsn->len;
            // 从filter中找到第一个key，也就是filterkey  第0个事type，第2个是filtername
            (void) ngx_http_vhost_traffic_status_node_position_key(&filter, 1);
            //现在filter已经只有filterkey了
            if (ngx_http_vhost_traffic_status_filter_max_node_match(r, &filter) == NGX_OK) {
                shm_info->filter_used_size += size;
                shm_info->filter_used_node++;
            }
        }

        ngx_http_vhost_traffic_status_shm_info_node(r, shm_info, node->left);
        ngx_http_vhost_traffic_status_shm_info_node(r, shm_info, node->right);
    }
}


void
ngx_http_vhost_traffic_status_shm_info(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_shm_info_t *shm_info)
{
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    ngx_memzero(shm_info, sizeof(ngx_http_vhost_traffic_status_shm_info_t));

    shm_info->name = &ctx->shm_name;
    shm_info->max_size = ctx->shm_size;

    // 从树根开始统计树中的节点数量、容量，记录到shm_info上
    ngx_http_vhost_traffic_status_shm_info_node(r, shm_info, ctx->rbtree->root);
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_node(ngx_http_request_t *r,
    ngx_str_t *key, unsigned type)
{
    size_t                                     size;
    unsigned                                   init;
    uint32_t                                   hash;
    ngx_slab_pool_t                           *shpool;
    ngx_rbtree_node_t                         *node, *lrun;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;
    ngx_http_vhost_traffic_status_shm_info_t  *shm_info;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (key->len == 0) {
        return NGX_ERROR;
    }

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* find node */
    hash = ngx_crc32_short(key->data, key->len);  //根据key计算hash
    // 找到计数节点
    node = ngx_http_vhost_traffic_status_find_node(r, key, type, hash);

    /* set common */
    if (node == NULL) { //没有计数节点
        init = NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE;

        /* delete lru node */ //找一个filterkey的最老的节点
        lrun = ngx_http_vhost_traffic_status_find_lru(r);
        if (lrun != NULL) { //释放这个最老的节点，还回slab，复用
            ngx_rbtree_delete(ctx->rbtree, lrun);
            ngx_slab_free_locked(shpool, lrun);
        }
        //lrun可能为null，不需要释放
        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_vhost_traffic_status_node_t, data)
               + key->len;

        node = ngx_slab_alloc_locked(shpool, size); //申请一个计数node
        if (node == NULL) {
            shm_info = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_shm_info_t));
            if (shm_info == NULL) {
                return NGX_ERROR;
            }

            ngx_http_vhost_traffic_status_shm_info(r, shm_info);

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_node::ngx_slab_alloc_locked() failed: "
                          "used_size[%ui], used_node[%ui]",
                          shm_info->used_size, shm_info->used_node);

            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }
        //从color开始往后存放的是vtsn
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        node->key = hash; //节点hash值
        vtsn->len = (u_short) key->len; //实际key的长度
        ngx_http_vhost_traffic_status_node_init(r, vtsn); // <--------------------------- 第一次
        vtsn->stat_upstream.type = type; //NO UG FG等等

        // holyzone 为upstream统计加上域名
        ngx_memset(vtsn->domain,0,255);
        if(type==NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG
        && r->upstream->peer.data != NULL
        && r->upstream->upstream->servers != NULL
        ){
            ngx_http_upstream_server_t *elt = r->upstream->upstream->servers->elts; //member
            ngx_http_upstream_rr_peer_data_t  *rrp = r->upstream->peer.data; //round robin连接信息
            ngx_uint_t i;
            //大致是找到当前连接的beckend，然后把他的名字赋值给计数节点的domain字段
            for(i = 0;i < r->upstream->upstream->servers->nelts;i++){
                if(ngx_memcmp(rrp->current->server.data,elt[i].name.data, rrp->current->server.len) == 0){
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                  "find match domain is %V",
                                  &elt[i].name);
                    ngx_memcpy(vtsn->domain,elt[i].name.data,elt[i].name.len);
                    break;
                }
            }
        }
		//holyzone end

        // 把key赋值到key->data
        ngx_memcpy(vtsn->data, key->data, key->len);
        //新节点放到树上
        ngx_rbtree_insert(ctx->rbtree, node);

    } else {
        init = NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_FIND;
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
        ngx_http_vhost_traffic_status_node_set(r, vtsn);  // <----------------------------------后续
    }

    /* set addition */
    switch(type) {
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        (void) ngx_http_vhost_traffic_status_shm_add_node_upstream(r, vtsn, init);
        break;

#if (NGX_HTTP_CACHE)
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        (void) ngx_http_vhost_traffic_status_shm_add_node_cache(r, vtsn, init);
        break;
#endif

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        break;
    }

    vtscf->node_caches[type] = node;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_node_upstream(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, unsigned init)
{
    ngx_msec_int_t                             ms,hms; //holyzone modified
    ngx_http_vhost_traffic_status_node_t       ovtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    ovtsn = *vtsn;
    ms = ngx_http_vhost_traffic_status_upstream_response_time(r);

    ngx_http_vhost_traffic_status_node_time_queue_insert(&vtsn->stat_upstream.response_times,
                                                         ms);
    ngx_http_vhost_traffic_status_node_histogram_observe(&vtsn->stat_upstream.response_buckets,
                                                         ms);
	// holyzone
    hms = ngx_http_vhost_traffic_status_upstream_header_time(r);

    ngx_http_vhost_traffic_status_node_time_queue_insert(&vtsn->stat_upstream.header_times,
                                                         hms);
    ngx_http_vhost_traffic_status_node_histogram_observe(&vtsn->stat_upstream.header_buckets,
                                                         hms);
	// holyzone end

    if (init == NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE) {
        vtsn->stat_upstream.response_time_counter = (ngx_atomic_uint_t) ms;
        vtsn->stat_upstream.response_time = (ngx_msec_t) ms;
        vtsn->stat_upstream.header_time = (ngx_msec_t) hms; //holyzone
    } else {
        vtsn->stat_upstream.response_time_counter += (ngx_atomic_uint_t) ms;
        vtsn->stat_upstream.response_time = ngx_http_vhost_traffic_status_node_time_queue_average(
                                                &vtsn->stat_upstream.response_times,
                                                vtscf->average_method, vtscf->average_period);  //holyzone
        vtsn->stat_upstream.header_time = ngx_http_vhost_traffic_status_node_time_queue_average(  //holyzone
                &vtsn->stat_upstream.header_times,		//holyzone
                vtscf->average_method, vtscf->average_period);

        if (ovtsn.stat_upstream.response_time_counter > vtsn->stat_upstream.response_time_counter)
        { 
            vtsn->stat_response_time_counter_oc++;
        }
    }

    return NGX_OK;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_node_cache(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, unsigned init)
{
    ngx_http_cache_t       *c;
    ngx_http_upstream_t    *u;
    ngx_http_file_cache_t  *cache;

    u = r->upstream;

    if (u != NULL && u->cache_status != 0 && r->cache != NULL) {
        c = r->cache;
        cache = c->file_cache;

    } else {
        return NGX_OK;
    }

    /*
     * If max_size in proxy_cache_path directive is not specified,
     * the system dependent value NGX_MAX_OFF_T_VALUE is assigned by default.
     *
     * proxy_cache_path ... keys_zone=name:size [max_size=size] ...
     *
     *     keys_zone's shared memory size:
     *         cache->shm_zone->shm.size
     *
     *     max_size's size:
     *         cache->max_size
     */

    if (init == NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE) {
        vtsn->stat_cache_max_size = (ngx_atomic_uint_t) (cache->max_size * cache->bsize);

    } else {
        ngx_shmtx_lock(&cache->shpool->mutex);

        vtsn->stat_cache_used_size = (ngx_atomic_uint_t) (cache->sh->size * cache->bsize);

        ngx_shmtx_unlock(&cache->shpool->mutex);
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_filter_node(ngx_http_request_t *r,
    ngx_array_t *filter_keys)
{
    u_char                                  *p;
    unsigned                                 type;
    ngx_int_t                                rc;
    ngx_str_t                                key, dst, filter_key, filter_name;
    ngx_uint_t                               i, n;
    ngx_http_vhost_traffic_status_filter_t  *filters;

    if (filter_keys == NULL) {
        return NGX_OK;
    }

    filters = filter_keys->elts; // 遍历所有的filter key
    n = filter_keys->nelts;

    for (i = 0; i < n; i++) {
        if (filters[i].filter_key.value.len <= 0) { //没有key      key  name
            continue;
        }

        if (ngx_http_complex_value(r, &filters[i].filter_key, &filter_key) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &filters[i].filter_name, &filter_name) != NGX_OK) {
            return NGX_ERROR;
        }

        if (filter_key.len == 0) { //filter key为空直接过掉，所以第一个参数是key，第二个参数是name
            continue;
        }

        // 计算key，分为带name和不带name。不带name的转为NO，带name的转为FG
        if (filter_name.len == 0) {
            type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO; //没有设置name的，放进NO
            // 将key转换为 NO+filterkey
            rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &filter_key, type);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }
            // NO+分隔符+filter_key

        } else { //filter_name不等于0 ，设置了name的放进FG
            type = filter_name.len
                   ? NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG
                   : NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
            //将filtername拷贝到dst
            dst.len = filter_name.len + sizeof("@") - 1 + filter_key.len;
            dst.data = ngx_pnalloc(r->pool, dst.len);
            if (dst.data == NULL) {
                return NGX_ERROR;
            }

            p = dst.data;
            p = ngx_cpymem(p, filter_name.data, filter_name.len);
            *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
            p = ngx_cpymem(p, filter_key.data, filter_key.len);
            // dst的形式： filtername + 分隔符 + filterkey, 下面的函数生成key还会在最前面加上类型
            // 最总key返回：FG+name+key
            rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }
            // NO+分隔符+name+分隔符+key
        }

        // 计分
        rc = ngx_http_vhost_traffic_status_shm_add_node(r, &key, type);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter_node::shm_add_node(\"%V\") failed", &key);
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r)
{
    unsigned                                   type;
    ngx_int_t                                  rc;
    ngx_str_t                                  key, dst;
    ngx_http_core_srv_conf_t                  *cscf;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (vtscf->filter && vtscf->filter_host && r->headers_in.server.len) { //设置了server
        /* set the key by host header */
        dst = r->headers_in.server; //由客户端设置的server，比如客户端的软件名，一般客户端不设置这个

    } else {
        /* set the key by server_name variable */
        dst = cscf->server_name; //server块配置了server_name
        if (dst.len == 0) {
            dst.len = 1;
            dst.data = (u_char *) "_"; //如果没有server_name就设置成_
        }
    }

    type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

    // 追加上了类型头， NO
    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_vhost_traffic_status_shm_add_node(r, &key, type);
}


ngx_int_t
ngx_http_vhost_traffic_status_shm_add_filter(ngx_http_request_t *r)
{
    ngx_int_t                                  rc;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (!vtscf->filter) {
        return NGX_OK;
    }

    if (ctx->filter_keys != NULL) { //http块里的filterkey
        rc = ngx_http_vhost_traffic_status_shm_add_filter_node(r, ctx->filter_keys);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter::shm_add_filter_node(\"http\") failed");
        }
    }

    if (vtscf->filter_keys != NULL) { //server及loc块里的filterkey
        rc = ngx_http_vhost_traffic_status_shm_add_filter_node(r, vtscf->filter_keys);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter::shm_add_filter_node(\"server\") failed");
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r)
{
    u_char                         *p;
    unsigned                        type;
    ngx_int_t                       rc;
    ngx_str_t                      *host, key, dst;
    ngx_uint_t                      i;
    ngx_http_upstream_t            *u;
    ngx_http_upstream_state_t      *state;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0
        || r->upstream->state == NULL)
    {
        return NGX_OK;
    }

    u = r->upstream;

    if (u->resolved == NULL) {
        uscf = u->conf->upstream;

    } else {
        host = &u->resolved->host;

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        /* routine for proxy_pass|fastcgi_pass|... $variables */
        uscf = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_srv_conf_t));
        if (uscf == NULL) {
            return NGX_ERROR;
        }

        uscf->host = u->resolved->host;
        uscf->port = u->resolved->port;
    }

found:

    state = r->upstream_states->elts;
    if (state[0].peer == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::peer failed");
        return NGX_ERROR;
    }

    dst.len = (uscf->port ? 0 : uscf->host.len + sizeof("@") - 1) + state[0].peer->len;
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    p = dst.data;
    if (uscf->port) {
        p = ngx_cpymem(p, state[0].peer->data, state[0].peer->len);
        type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;

    } else {
        p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
        *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
        p = ngx_cpymem(p, state[0].peer->data, state[0].peer->len);
        type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;
    }

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_vhost_traffic_status_shm_add_node(r, &key, type);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::shm_add_node(\"%V\") failed", &key);
    }

    return NGX_OK;
}


#if (NGX_HTTP_CACHE)

ngx_int_t
ngx_http_vhost_traffic_status_shm_add_cache(ngx_http_request_t *r)
{
    unsigned                type;
    ngx_int_t               rc;
    ngx_str_t               key;
    ngx_http_cache_t       *c;
    ngx_http_upstream_t    *u;
    ngx_http_file_cache_t  *cache;

    u = r->upstream;

    if (u != NULL && u->cache_status != 0 && r->cache != NULL) {
        c = r->cache;
        cache = c->file_cache;

    } else {
        return NGX_OK;
    }

    type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &cache->shm_zone->shm.name,
                                                         type);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_vhost_traffic_status_shm_add_node(r, &key, type);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_cache::shm_add_node(\"%V\") failed", &key);
    }

    return NGX_OK;
}

#endif

// holyzone 
static ngx_int_t
ngx_http_vhost_traffic_status_shm_modify_node(ngx_http_request_t *r,ngx_str_t *key,unsigned us_type,unsigned ud_type){
    uint32_t hash;
    ngx_slab_pool_t *shpool;
    ngx_rbtree_node_t  *node;
    ngx_http_vhost_traffic_status_node_t *vtsn;
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r,ngx_http_vhost_traffic_status_module);

    if(key->len == 0){
        return NGX_ERROR;
    }

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    hash = ngx_crc32_short(key->data,key->len);

    node = ngx_http_vhost_traffic_status_find_node(r,key,us_type,hash);

    if(node == NULL){
        ngx_shmtx_unlock(&shpool->mutex);
//        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
//                      "not found!");
        return NGX_ERROR;
    }


    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
    if(ud_type == 1){
        vtsn->stat_active++;
    }else{
        if(vtsn->stat_active > 0){
            vtsn->stat_active--;
        }
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

ngx_int_t
ngx_http_vhost_traffic_status_shm_modify_server(ngx_http_request_t *r,unsigned ud_type)
{
    ngx_int_t rc;
    ngx_str_t key,dst;
    ngx_http_core_srv_conf_t *cscf;
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf;

    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    if (ctx->enable == 0) {
        return NGX_ERROR;
    }

    vtscf = ngx_http_get_module_loc_conf(r,ngx_http_vhost_traffic_status_module);

    cscf = ngx_http_get_module_srv_conf(r,ngx_http_core_module);
    //TODO count '_' address
    if(vtscf->filter && vtscf->filter_host && r->headers_in.server.len){
        dst = r->headers_in.server;
        rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool,&key,&dst,NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO);
        if(rc != NGX_OK){
            return NGX_ERROR;
        }
        ngx_http_vhost_traffic_status_shm_modify_node(r, &key, NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO, ud_type);
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_vhost_traffic_status_shm_modify_upstream(ngx_http_request_t *r,unsigned ud_type)
{
    u_char                         *p;
    unsigned                        type;
    ngx_int_t                       rc;
    ngx_str_t                      *host, key, dst;
    ngx_uint_t                      i;
    ngx_http_upstream_t            *u;
    ngx_http_upstream_state_t      *state;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    if (ctx->enable == 0) {
        return NGX_ERROR;
    }

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0
        || r->upstream->state == NULL)
    {
        return NGX_OK;
    }

    u = r->upstream;

    if (u->resolved == NULL) {
        uscf = u->conf->upstream;

    } else {
        host = &u->resolved->host;

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                    || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        /* routine for proxy_pass|fastcgi_pass|... $variables */
        uscf = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_srv_conf_t));
        if (uscf == NULL) {
            return NGX_ERROR;
        }

        uscf->host = u->resolved->host;
        uscf->port = u->resolved->port;
    }

    found:

    state = r->upstream_states->elts;
    if (state[0].peer == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::peer failed");
        return NGX_ERROR;
    }

    dst.len = (uscf->port ? 0 : uscf->host.len + sizeof("@") - 1) + state[0].peer->len;
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    p = dst.data;
    if (uscf->port) {
        p = ngx_cpymem(p, state[0].peer->data, state[0].peer->len);
        type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;

    } else {
        p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
        *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
        p = ngx_cpymem(p, state[0].peer->data, state[0].peer->len);
        type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;
    }

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }
//    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
//                  "key(\"%V\")", &key);
    rc = ngx_http_vhost_traffic_status_shm_modify_node(r, &key, type,ud_type);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::shm_add_node(\"%V\") failed", &key);
    }
    return NGX_OK;
}
// holyzone
/* vi:set ft=c ts=4 sw=4 et fdm=marker: */

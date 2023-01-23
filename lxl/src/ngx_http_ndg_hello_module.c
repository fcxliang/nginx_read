static ngx_http_variable_t ngx_http_ndg_vars[]=
{
	{
		ngx_string("current_method"),
		NULL,
		ngx_http_current_method_variable,
		0, 
		0, 
		0 
	},
	ngx_http_null_variable
		
};

static ngx_int_t ngx_http_current_method_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{

	v->len = r->method_name.len;
	v->data = r->method_name.data;
	v->valid = 1;
	v->not_found = 0;
	v->no_cacheable = 0;

	return NGX_OK;
}

static ngx_int_t ngx_http_ndg_add_variables(ngx_conf_t * cf)
{
	ngx_http_variable_t *var, *v;
	for (v = ngx_http_ndg_vars; v->name.len; v++){
		var = ngx_http_add_variable(cf, &v->name, v->flags);
		var->get_handler = v->get_handler;
		var->data = v->data;
	}

	return NGX_OK;
}


static ngx_http_module_t ngx_http_ndg_variable_module_ctx = 
{
	ngx_http_ndg_add_variables,
	ngx_http_ndg_variable_init,
};


typedef struct {
	ngx_flag_t enable;
} ngx_http_ndg_hello_loc_conf_t;

static ngx_command_t ngx_http_ndg_hello_cmds[] = {
	{
		ngx_string("ndg_hello"),
		NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_ndg_hello_loc_conf_t, enable),
		NULL
	},

	ngx_null_command
};

static void *
ngx_http_ndg_hello_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_ndg_hello_loc_conf_t * conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ndg_hello_loc_conf_t));
	if (conf == NULL)
	{
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET;
	return conf;
}

static ngx_int_t
ngx_http_ndg_hello_handler(ngx_http_request_t *r)
{
	ngx_http_ndg_hello_loc_conf_t* lcf;

	lcf = ngx_http_get_module_loc_conf(r, ngx_http_ndg_hello_module);

	if (lcf->enable) {
		printf("hello nginx\n");
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "hello ansi c");
	} else {
		printf("hello disabled\n");
	}

	return NGX_DECLINED;
}


static ngx_int_t
ngx_http_ndg_hello_init(ngx_conf_t* cf)
{
	ngx_http_handler_pt   *h;
	ngx_http_core_main_conf_t *cmcf;
	cmcf = ngx_http_get_module_main_conf(cf, ngx_http_core_module)
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
	*h = ngx_http_ndg_hello_handler;

	return NGX_OK;
}

static ngx_http_module_t ngx_http_ndg_hello_module_ctx = 
{
	NULL,
	ngx_http_ndg_hello_init,
	NULL,
	NULL,
	NULL,
	NULL,
	ngx_http_ndg_hello_create_loc_conf,
	NULL,
};

ngx_module_t ngx_http_ndg_hello_module = 
{
	NGX_MODULE_V1,
	&ngx_http_ndg_hello_module_ctx,
	ngx_http_ndg_hello_cmds,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};



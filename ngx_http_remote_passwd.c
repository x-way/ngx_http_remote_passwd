/*
 * ngx_http_remote_passwd - Make the Basic Auth password available as $remote_passwd variable
 *
 * Copyright (c) 2011, Andreas Jaggi <andreas.jaggi@waterwave.ch>
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



static ngx_int_t ngx_http_remote_passwd_add_variable(ngx_conf_t *cf);
static ngx_int_t ngx_http_variable_remote_passwd(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);



static ngx_http_module_t ngx_http_remote_passwd_module_ctx = {
	ngx_http_remote_passwd_add_variable, /* preconfiguration */
	NULL,                                /* postconfiguration */

	NULL,                                /* create main configuration */
	NULL,                                /* init main configuration */

	NULL,                                /* create server configuration */
	NULL,                                /* merge server configuration */

	NULL,                                /* create location configuration */
	NULL,                                /* merge location configuration */
};

ngx_module_t ngx_http_remote_passwd_module = {
	NGX_MODULE_V1,
	&ngx_http_remote_passwd_module_ctx, /* module context */
	NULL,                               /* module directives */
	NGX_HTTP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	NULL,                               /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_str_t ngx_http_remote_passwd_variable_name = ngx_string("remote_passwd");



static ngx_int_t ngx_http_remote_passwd_add_variable(ngx_conf_t *cf) {
	ngx_http_variable_t *v;

	v = ngx_http_add_variable(cf, &ngx_http_remote_passwd_variable_name, 0);
	if (v == NULL) {
		return NGX_ERROR;
	}

	v->get_handler = ngx_http_variable_remote_passwd;

	return NGX_OK;
}

static ngx_int_t ngx_http_variable_remote_passwd(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_int_t  rc;

	rc = ngx_http_auth_basic_user(r);

	if (rc == NGX_DECLINED) {
		v->not_found = 1;
		return NGX_OK;
	}

	if (rc == NGX_ERROR) {
		return NGX_ERROR;
	}

	v->len = r->headers_in.passwd.len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = r->headers_in.passwd.data;

	return NGX_OK;
}

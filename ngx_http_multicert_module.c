#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <assert.h>

#include <ngx_keyless_module.h>

typedef enum {
	ecdsa_only = 0x1,
	sha2_only = 0x2,
	ecdsa_sha2 = ecdsa_only|sha2_only
} cert_qualifier_et;

typedef struct {
	ngx_array_t *certificate;
	ngx_array_t *certificate_key;

	ngx_ssl_t *ssl;
	ngx_ssl_t ssl_ecdsa;
	ngx_ssl_t ssl_rsa_sha2;
	ngx_ssl_t ssl_ecdsa_sha2;
} srv_conf_t;

typedef struct {
	ngx_str_t val;
	cert_qualifier_et qal;
} cert_str_st;

typedef struct {
	ngx_conf_post_handler_pt post_handler;

	ngx_uint_t offset;
} ssl_module_default_post_st;

static void *create_srv_conf(ngx_conf_t *cf);
static char *merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static char *set_opt_qualifier_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *set_ssl_module_default(ngx_conf_t *cf, void *post, void *data);

static int select_certificate_cb(const struct ssl_early_callback_ctx *ctx);

static int g_ssl_ctx_exdata_srv_data_index = -1;

static ngx_str_t ngx_http_ssl_sess_id_ctx = ngx_string("HTTP");

static ssl_module_default_post_st ssl_multicert_post =
	{ set_ssl_module_default,
	  offsetof(ngx_http_ssl_srv_conf_t, certificate) };

static ssl_module_default_post_st ssl_multicert_key_post =
	{ set_ssl_module_default,
	  offsetof(ngx_http_ssl_srv_conf_t, certificate_key) };

static ngx_command_t module_commands[] = {
	{ ngx_string("ssl_multicert"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
	  set_opt_qualifier_str,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(srv_conf_t, certificate),
	  &ssl_multicert_post },

	{ ngx_string("ssl_multicert_key"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
	  set_opt_qualifier_str,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(srv_conf_t, certificate_key),
	  &ssl_multicert_key_post },

	ngx_null_command
};

static ngx_http_module_t module_ctx = {
	NULL,            /* preconfiguration */
	NULL,            /* postconfiguration */

	NULL,            /* create main configuration */
	NULL,            /* init main configuration */

	create_srv_conf, /* create server configuration */
	merge_srv_conf,  /* merge server configuration */

	NULL,            /* create location configuration */
	NULL             /* merge location configuration */
};

ngx_module_t ngx_http_multicert_module = {
	NGX_MODULE_V1,
	&module_ctx,     /* module context */
	module_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL,            /* init master */
	NULL,            /* init module */
	NULL,            /* init process */
	NULL,            /* init thread */
	NULL,            /* exit thread */
	NULL,            /* exit process */
	NULL,            /* exit master */
	NGX_MODULE_V1_PADDING
};

static void *create_srv_conf(ngx_conf_t *cf)
{
	srv_conf_t *mcscf;

	mcscf = ngx_pcalloc(cf->pool, sizeof(srv_conf_t));
	if (!mcscf) {
		return NULL;
	}

	mcscf->certificate = NGX_CONF_UNSET_PTR;
	mcscf->certificate_key = NGX_CONF_UNSET_PTR;

	return mcscf;
}

static char *merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	srv_conf_t *prev = parent;
	srv_conf_t *conf = child;

	ngx_http_ssl_srv_conf_t *ssl;
	cert_str_st *cert_elt;
	cert_str_st *key_elt;
	ngx_ssl_t *new_ssl;
	size_t i;
	ngx_pool_cleanup_t *cln;

	ngx_conf_merge_ptr_value(conf->certificate, prev->certificate, NULL);
	ngx_conf_merge_ptr_value(conf->certificate_key, prev->certificate_key, NULL);

	if (!conf->certificate && !conf->certificate_key) {
		return NGX_CONF_OK;
	}

	if (!conf->certificate || !conf->certificate_key || conf->certificate->nelts != conf->certificate_key->nelts) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "must have same number of ssl_multicert and ssl_multicert_key directives");
		return NGX_CONF_ERROR;
	}

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
	if (!ssl || !ssl->ssl.ctx) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no ssl configured for the server");
		return NGX_CONF_ERROR;
	}

	conf->ssl = &ssl->ssl;

	cert_elt = conf->certificate->elts;
	key_elt = conf->certificate_key->elts;
	for (i = 0; i < conf->certificate->nelts; i++) {
		switch (cert_elt[i].qal) {
			case ecdsa_sha2:
				new_ssl = &conf->ssl_ecdsa_sha2;
				break;
			case sha2_only:
				new_ssl = &conf->ssl_rsa_sha2;
				break;
			case ecdsa_only:
				new_ssl = &conf->ssl_ecdsa;
				break;
			default:
				continue;
		}

		if (cert_elt[i].qal != key_elt[i].qal) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "mismatched ssl_multicert and ssl_multicert_key directives");
			return NGX_CONF_ERROR;
		}

		if (ngx_ssl_create(new_ssl, ssl->protocols, ssl) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

		cln = ngx_pool_cleanup_add(cf->pool, 0);
		if (!cln) {
			return NGX_CONF_ERROR;
		}

		cln->handler = ngx_ssl_cleanup_ctx;
		cln->data = new_ssl;

		if (ngx_ssl_certificate(cf, new_ssl, &cert_elt[i].val, &key_elt[i].val, ssl->passwords) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

		if (ngx_ssl_session_cache(new_ssl, &ngx_http_ssl_sess_id_ctx, ssl->builtin_session_cache, ssl->shm_zone, ssl->session_timeout) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}

	if (g_ssl_ctx_exdata_srv_data_index == -1) {
		g_ssl_ctx_exdata_srv_data_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_ctx_exdata_srv_data_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_get_ex_new_index failed");
			return NGX_CONF_ERROR;
		}
	}

	if (!SSL_CTX_set_ex_data(ssl->ssl.ctx, g_ssl_ctx_exdata_srv_data_index, conf)) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_set_ex_data failed");
		return NGX_CONF_ERROR;
	}

	SSL_CTX_set_select_certificate_cb(ssl->ssl.ctx, select_certificate_cb);

	return NGX_CONF_OK;
}

static char *set_opt_qualifier_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char *p = conf;

	ngx_str_t *value;
	cert_str_st *s;
	ngx_array_t **a;
	ngx_conf_post_t *post;
	size_t i;

	a = (ngx_array_t **)(p + cmd->offset);
	if (*a == NGX_CONF_UNSET_PTR) {
		*a = ngx_array_create(cf->pool, 4, sizeof(cert_str_st));
		if (*a == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	s = ngx_array_push(*a);
	if (s == NULL) {
		return NGX_CONF_ERROR;
	}

	value = cf->args->elts;
	s->val = value[1];
	s->qal = 0;

	for (i = 2; i < cf->args->nelts; i++) {
		if (ngx_strcmp(value[i].data, "ecdsa") == 0) {
			s->qal |= ecdsa_only;
		} else if (ngx_strcmp(value[i].data, "sha2") == 0) {
			s->qal |= sha2_only;
		} else {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid flag, only ecdsa and sha2 supported");
			return NGX_CONF_ERROR;
		}
	}

	if (cmd->post) {
		post = cmd->post;
		return post->post_handler(cf, post, s);
	}

	return NGX_CONF_OK;
}

static char *set_ssl_module_default(ngx_conf_t *cf, void *post, void *data)
{
	ssl_module_default_post_st *p = post;
	cert_str_st *s = data;

	ngx_http_ssl_srv_conf_t *ssl;
	ngx_str_t *a;

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

	a = (ngx_str_t *)((char *)ssl + p->offset);

	if (s->qal && a->data) {
		return NGX_CONF_OK;
	}

	*a = s->val;

	return NGX_CONF_OK;
}

static int select_certificate_cb(const struct ssl_early_callback_ctx *ctx)
{
	srv_conf_t *conf;
	const uint8_t *sig_algs_ptr, *dummy;
	size_t sig_algs_len, len;
	CBS cipher_suites, sig_algs, supported_sig_algs;
	int has_ecdsa, has_sha2rsa, has_sha2ecdsa;
	uint16_t cipher_suite;
	uint8_t hash, sign;
	ngx_ssl_t *new_ssl;
	X509 *cert;
	STACK_OF(X509) *cert_chain;
	EVP_PKEY *pkey;
	KEYLESS_CTX *keyless;
	const SSL_CIPHER *cipher;

	conf = SSL_CTX_get_ex_data(ctx->ssl->ctx, g_ssl_ctx_exdata_srv_data_index);

	if ((conf->ssl_ecdsa_sha2.ctx || conf->ssl_rsa_sha2.ctx || conf->ssl_ecdsa.ctx)
		&& SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_signature_algorithms, &sig_algs_ptr, &sig_algs_len)) {
		has_ecdsa = 0;
		has_sha2rsa = 0;
		has_sha2ecdsa = 0;

		if (conf->ssl_ecdsa_sha2.ctx || conf->ssl_ecdsa.ctx) {
			CBS_init(&cipher_suites, ctx->cipher_suites, ctx->cipher_suites_len);

			while (CBS_len(&cipher_suites) != 0) {
				if (!CBS_get_u16(&cipher_suites, &cipher_suite)) {
					return -1;
				}

				cipher = SSL_get_cipher_by_value(cipher_suite);
				if (cipher && SSL_CIPHER_is_ECDSA(cipher)) {
					has_ecdsa = 1;
					break;
				}
			}
		}

		if (conf->ssl_ecdsa_sha2.ctx || conf->ssl_rsa_sha2.ctx) {
			CBS_init(&sig_algs, sig_algs_ptr, sig_algs_len);

			if (!CBS_get_u16_length_prefixed(&sig_algs, &supported_sig_algs)
				|| CBS_len(&sig_algs) != 0
				|| CBS_len(&supported_sig_algs) == 0) {
				return -1;
			}

			if (CBS_len(&supported_sig_algs) % 2 != 0) {
				return -1;
			}

			while (CBS_len(&supported_sig_algs) != 0) {
				if (!CBS_get_u8(&supported_sig_algs, &hash) || !CBS_get_u8(&supported_sig_algs, &sign)) {
					return -1;
				}

				if (hash != TLSEXT_hash_sha256) {
					continue;
				}

				switch (sign) {
					case TLSEXT_signature_rsa:
						has_sha2rsa = 1;
						break;
					case TLSEXT_signature_ecdsa:
						has_sha2ecdsa = 1;
						break;
					default:
						continue;
				}

				if (has_sha2rsa && has_sha2ecdsa) {
					break;
				}
			}
		}

		if (conf->ssl_ecdsa_sha2.ctx && has_ecdsa && has_sha2ecdsa) {
			new_ssl = &conf->ssl_ecdsa_sha2;
			goto set_ssl;
		}

		if (conf->ssl_rsa_sha2.ctx && has_sha2rsa) {
			new_ssl = &conf->ssl_rsa_sha2;
			goto set_ssl;
		}

		if (conf->ssl_ecdsa.ctx && has_ecdsa) {
			new_ssl = &conf->ssl_ecdsa;
			goto set_ssl;
		}
	}

	if (conf->ssl_rsa_sha2.ctx && SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_server_name, &dummy, &len)) {
		new_ssl = &conf->ssl_rsa_sha2;
		goto set_ssl;
	}

	return 1;

set_ssl:
	SSL_certs_clear(ctx->ssl);

	// Set certificate
	cert = SSL_CTX_get0_certificate(new_ssl->ctx);
	if (!cert) {
		return -1;
	}

	if (!SSL_use_certificate(ctx->ssl, cert)) {
		return -1;
	}

	assert(cert == SSL_CTX_get_ex_data(new_ssl->ctx, ngx_ssl_certificate_index));

	// Set certificate chain
	if (!SSL_CTX_get0_chain_certs(new_ssl->ctx, &cert_chain)) {
		return -1;
	}

	if (!SSL_set1_chain(ctx->ssl, cert_chain)) {
		return -1;
	}

	// Set private key
	pkey = SSL_CTX_get0_privatekey(new_ssl->ctx);
	if (pkey && !SSL_use_PrivateKey(ctx->ssl, pkey)) {
		return -1;
	}

	// Set session id context
	if (!SSL_set_session_id_context(ctx->ssl, new_ssl->ctx->sid_ctx, new_ssl->ctx->sid_ctx_length)) {
		return -1;
	}

	// Set keyless-nginx
	keyless = ssl_ctx_get_keyless_ctx(new_ssl->ctx);
	if (keyless && !keyless_attach_ssl(ctx->ssl, keyless)) {
		return -1;
	}

	return 1;
}

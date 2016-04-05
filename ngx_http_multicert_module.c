#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <assert.h>

#ifdef NGX_HTTP_MUTLICERT_HAVE_NGXLUA
#include "../ngx_http_lua_common.h"
#include "../ngx_http_lua_ssl_certby.h"
#endif /* NGX_HTTP_MUTLICERT_HAVE_NGXLUA */

#ifdef NGX_HTTP_MUTLICERT_HAVE_KEYLESS
#include <ngx_keyless_module.h>
#endif /* NGX_HTTP_MUTLICERT_HAVE_KEYLESS */

/* taken from boringssl-1e4ae00/ssl/internal.h */
#define SSL_CURVE_SECP256R1 23
#define SSL_CURVE_SECP384R1 24
#define SSL_CURVE_SECP521R1 25

typedef struct {
	ngx_array_t *certificate;
	ngx_array_t *certificate_key;

	ngx_queue_t ssl;

	ngx_ssl_t ssl_rsa;
	ngx_ssl_t ssl_rsa_sha256;
} srv_conf_t;

typedef struct {
	ngx_conf_post_handler_pt post_handler;

	ngx_uint_t multicert_offset;
	ngx_uint_t ssl_offset;
} set_first_to_ssl_conf_post_st;

typedef struct {
	int nid;
	int curve_nid;

	ngx_ssl_t ssl;

	ngx_queue_t queue;
} ssl_ctx_st;

static void *create_srv_conf(ngx_conf_t *cf);
static char *merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static char *set_first_to_ssl_conf(ngx_conf_t *cf, void *post, void *data);

static ngx_ssl_t *set_conf_ssl_for_ctx(ngx_conf_t *cf, srv_conf_t *conf, ngx_ssl_t *ssl);

static int select_certificate_cb(const struct ssl_early_callback_ctx *ctx);

static ngx_int_t cmp_ssl_ctx_st(const ngx_queue_t *one, const ngx_queue_t *two);

static int g_ssl_ctx_exdata_srv_data_index = -1;

static ngx_str_t ngx_http_ssl_sess_id_ctx = ngx_string("HTTP");

static set_first_to_ssl_conf_post_st ssl_multicert_post =
	{ set_first_to_ssl_conf,
	  offsetof(srv_conf_t, certificate),
	  offsetof(ngx_http_ssl_srv_conf_t, certificate) };

static set_first_to_ssl_conf_post_st ssl_multicert_key_post =
	{ set_first_to_ssl_conf,
	  offsetof(srv_conf_t, certificate_key),
	  offsetof(ngx_http_ssl_srv_conf_t, certificate_key) };

static ngx_command_t module_commands[] = {
	{ ngx_string("ssl_multicert"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_array_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(srv_conf_t, certificate),
	  &ssl_multicert_post },

	{ ngx_string("ssl_multicert_key"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_array_slot,
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
	ngx_str_t *cert_elt, *key_elt;
	ngx_ssl_t new_ssl, *new_ssl_ptr;
	size_t i;
	ngx_pool_cleanup_t *cln;
	ngx_queue_t *q;
	ssl_ctx_st *ssl_ctx;
#ifdef NGX_HTTP_MUTLICERT_HAVE_NGXLUA
	ngx_http_lua_srv_conf_t *lua;
#endif /* NGX_HTTP_MUTLICERT_HAVE_NGXLUA */

	ngx_conf_merge_ptr_value(conf->certificate, prev->certificate, NULL);
	ngx_conf_merge_ptr_value(conf->certificate_key, prev->certificate_key, NULL);

	if (!conf->certificate && !conf->certificate_key) {
		return NGX_CONF_OK;
	}

	if (!conf->certificate || !conf->certificate_key
		|| conf->certificate->nelts != conf->certificate_key->nelts) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
			"must have same number of ssl_multicert and ssl_multicert_key directives");
		return NGX_CONF_ERROR;
	}

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
	if (!ssl || !ssl->ssl.ctx) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no ssl configured for the server");
		return NGX_CONF_ERROR;
	}

	ngx_queue_init(&conf->ssl);

	if (!set_conf_ssl_for_ctx(cf, conf, &ssl->ssl)) {
		return NGX_CONF_ERROR;
	}

#ifdef NGX_HTTP_MUTLICERT_HAVE_NGXLUA
	lua = ngx_http_conf_get_module_srv_conf(cf, ngx_http_lua_module);
#endif /* NGX_HTTP_MUTLICERT_HAVE_NGXLUA */

	cert_elt = conf->certificate->elts;
	key_elt = conf->certificate_key->elts;
	for (i = 1; i < conf->certificate->nelts; i++) {
		new_ssl.ctx = SSL_CTX_dup(ssl->ssl.ctx);
		if (!new_ssl.ctx) {
			return NGX_CONF_ERROR;
		}

		cln = ngx_pool_cleanup_add(cf->pool, 0);
		if (!cln) {
			return NGX_CONF_ERROR;
		}

		cln->handler = ngx_ssl_cleanup_ctx;
		cln->data = &new_ssl;

		if (ngx_ssl_certificate(cf, &new_ssl, &cert_elt[i], &key_elt[i], ssl->passwords)
			!= NGX_OK) {
			return NGX_CONF_ERROR;
		}

		if (ngx_ssl_session_cache(&new_ssl, &ngx_http_ssl_sess_id_ctx, NGX_SSL_NO_SCACHE,
				NULL, ssl->session_timeout) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

#ifdef NGX_HTTP_MUTLICERT_HAVE_NGXLUA
		if (lua && lua->ssl.cert_src.len) {
			SSL_CTX_set_cert_cb(new_ssl.ctx, ngx_http_lua_ssl_cert_handler, NULL);
		}
#endif /* NGX_HTTP_MUTLICERT_HAVE_NGXLUA */

		new_ssl_ptr = set_conf_ssl_for_ctx(cf, conf, &new_ssl);
		if (!new_ssl_ptr) {
			return NGX_CONF_ERROR;
		}
		cln->data = new_ssl_ptr;
	}

	ngx_queue_sort(&conf->ssl, cmp_ssl_ctx_st);

	for (q = ngx_queue_last(&conf->ssl);
		q != ngx_queue_sentinel(&conf->ssl);
		q = ngx_queue_prev(q)) {
		ssl_ctx = ngx_queue_data(q, ssl_ctx_st, queue);

		switch (ssl_ctx->nid) {
			case NID_sha1WithRSAEncryption:
				conf->ssl_rsa = ssl_ctx->ssl;
				break;
			case NID_sha256WithRSAEncryption:
				conf->ssl_rsa_sha256 = ssl_ctx->ssl;
				break;
			default:
				continue;
		}

		if (conf->ssl_rsa.ctx && conf->ssl_rsa_sha256.ctx) {
			break;
		}
	}

	SSL_CTX_set_tlsext_servername_callback(ssl->ssl.ctx, NULL);

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

static ngx_int_t cmp_ssl_ctx_st(const ngx_queue_t *one, const ngx_queue_t *two)
{
	ssl_ctx_st *a, *b;

	a = ngx_queue_data(one, ssl_ctx_st, queue);
	b = ngx_queue_data(two, ssl_ctx_st, queue);

	/* shift ecdsa keys to the start */
	if (a->curve_nid && !b->curve_nid) {
		return -1;
	} else if (!a->curve_nid && b->curve_nid) {
		return 1;
	}

	/* this only works becuase the currently limited NIDs are ordered
	 * as we want the certificates to be */
	if (a->curve_nid < b->curve_nid) {
		return 1;
	} else if (a->curve_nid > b->curve_nid) {
		return -1;
	}

	/* this only works becuase the currently limited NIDs are ordered
	 * as we want the certificates to be */
	if (a->nid < b->nid) {
		return 1;
	} else if (a->nid > b->nid) {
		return -1;
	}

	return 0;
}

static char *set_first_to_ssl_conf(ngx_conf_t *cf, void *post, void *data)
{
	set_first_to_ssl_conf_post_st *p = post;
	srv_conf_t *conf_multicert;
	ngx_http_ssl_srv_conf_t *conf_ssl;
	ngx_array_t *arr;
	ngx_str_t *s = data, *str;

	conf_multicert = ngx_http_conf_get_module_srv_conf(cf, ngx_http_multicert_module);
	arr = *(ngx_array_t **)((char *)conf_multicert + p->multicert_offset);

	if (arr->nelts != 1) {
		return NGX_CONF_OK;
	}

	conf_ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
	str = (ngx_str_t *)((char *)conf_ssl + p->ssl_offset);

	if (str->data) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
			"ssl_certificate* and ssl_multicert* cannot be used together");
		return NGX_CONF_ERROR;
	}

	*str = *s;
	return NGX_CONF_OK;
}

static ngx_ssl_t *set_conf_ssl_for_ctx(ngx_conf_t *cf, srv_conf_t *conf, ngx_ssl_t *ssl)
{
	X509 *cert;
	EVP_PKEY *pkey;
	const EC_KEY *ec_key;
	int nid, curve_nid = NID_undef;
	ngx_queue_t *q;
	ssl_ctx_st *ssl_ctx;

	cert = SSL_CTX_get0_certificate(ssl->ctx);
	if (!cert) {
		return NULL;
	}

	nid = X509_get_signature_nid(cert);

	pkey = X509_get_pubkey(cert);
	if (pkey) {
		ec_key = EVP_PKEY_get0_EC_KEY(pkey);
		if (ec_key) {
			curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
		}

		EVP_PKEY_free(pkey);
	}

	switch (nid) {
		case NID_sha1WithRSAEncryption:
		case NID_sha256WithRSAEncryption:
		case NID_sha384WithRSAEncryption:
		case NID_sha512WithRSAEncryption:
			assert(curve_nid == NID_undef);
			break;
		case NID_ecdsa_with_SHA256:
		case NID_ecdsa_with_SHA384:
		case NID_ecdsa_with_SHA512:
			switch (curve_nid) {
				case NID_X9_62_prime256v1:
				case NID_secp384r1:
				case NID_secp521r1:
					break;
				default:
					ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
						"invalid ec group type");
					return NULL;
			}

			break;
		default:
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid certificate type");
			return NULL;
	}

	for (q = ngx_queue_head(&conf->ssl);
		q != ngx_queue_sentinel(&conf->ssl);
		q = ngx_queue_next(q)) {
		ssl_ctx = ngx_queue_data(q, ssl_ctx_st, queue);

		if (ssl_ctx->nid == nid && ssl_ctx->curve_nid == curve_nid) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "certificate type is duplicate");
			return NULL;
		}
	}

	ssl_ctx = ngx_pcalloc(cf->cycle->pool, sizeof(ssl_ctx_st));
	if (!ssl_ctx) {
		return NULL;
	}

	ngx_queue_insert_tail(&conf->ssl, &ssl_ctx->queue);

	ssl_ctx->nid = nid;
	ssl_ctx->curve_nid = curve_nid;

	ssl_ctx->ssl = *ssl;
	return &ssl_ctx->ssl;
}

static int select_certificate_cb(const struct ssl_early_callback_ctx *ctx)
{
	srv_conf_t *conf;
	const uint8_t *extension_ptr, *server_name_ext = NULL;
	size_t extension_len;
	CBS cipher_suites, extension, server_name_list, host_name, sig_algs, ec_curves;
	int has_ecdsa, has_sha1_rsa,
		has_sha256_rsa, has_sha256_ecdsa,
		has_sha384_rsa, has_sha384_ecdsa,
		has_sha512_rsa, has_sha512_ecdsa,
		has_secp256r1, has_secp384r1, has_secp521r1;
	uint16_t cipher_suite, ec_curve;
	uint8_t name_type, hash, sign;
	const SSL_CIPHER *cipher;
	ngx_queue_t *q;
	ssl_ctx_st *ssl_ctx;

	if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_server_name,
			&server_name_ext, &extension_len)) {
		CBS_init(&extension, server_name_ext, extension_len);

		if (!CBS_get_u16_length_prefixed(&extension, &server_name_list)
			|| CBS_len(&server_name_list) == 0
			|| CBS_len(&extension) != 0) {
			return -1;
		}

		while (CBS_len(&server_name_list) != 0) {
			if (!CBS_get_u8(&server_name_list, &name_type)
				|| !CBS_get_u16_length_prefixed(&server_name_list, &host_name)) {
				return -1;
			}

			if (name_type != TLSEXT_NAMETYPE_host_name) {
				continue;
			}

			if (CBS_len(&host_name) == 0
				|| CBS_len(&host_name) > TLSEXT_MAXLEN_host_name
				|| CBS_contains_zero_byte(&host_name)
				|| !CBS_strdup(&host_name, &ctx->ssl->tlsext_hostname)) {
				return -1;
			}

			if (ngx_http_ssl_servername(ctx->ssl, NULL, NULL) == SSL_TLSEXT_ERR_NOACK) {
				ctx->ssl->s3->tmp.should_ack_sni = 0;
			}

			OPENSSL_free(ctx->ssl->tlsext_hostname);
			ctx->ssl->tlsext_hostname = NULL;
			break;
		}
	}

	conf = SSL_CTX_get_ex_data(ctx->ssl->ctx, g_ssl_ctx_exdata_srv_data_index);
	if (!conf) {
		return 1;
	}

	if (!ngx_queue_empty(&conf->ssl) && SSL_early_callback_ctx_extension_get(ctx,
			TLSEXT_TYPE_signature_algorithms, &extension_ptr, &extension_len)) {
		has_ecdsa = has_sha1_rsa = 0;
		has_sha256_rsa = has_sha256_ecdsa = 0;
		has_sha384_rsa = has_sha384_ecdsa = 0;
		has_sha512_rsa = has_sha512_ecdsa = 0;
		has_secp256r1 = has_secp384r1 = has_secp521r1 = 0;

		CBS_init(&extension, extension_ptr, extension_len);

		if (!CBS_get_u16_length_prefixed(&extension, &sig_algs)
			|| CBS_len(&sig_algs) == 0
			|| CBS_len(&extension) != 0) {
			return -1;
		}

		if (CBS_len(&sig_algs) % 2 != 0) {
			return -1;
		}

		while (CBS_len(&sig_algs) != 0) {
			if (!CBS_get_u8(&sig_algs, &hash)
				|| !CBS_get_u8(&sig_algs, &sign)) {
				return -1;
			}

			switch (((uint16_t)sign << 8) | hash) {
				case (TLSEXT_signature_rsa << 8) | TLSEXT_hash_sha1:
					has_sha1_rsa = 1;
					break;
				case (TLSEXT_signature_rsa << 8) | TLSEXT_hash_sha256:
					has_sha256_rsa = 1;
					break;
				case (TLSEXT_signature_rsa << 8) | TLSEXT_hash_sha384:
					has_sha384_rsa = 1;
					break;
				case (TLSEXT_signature_rsa << 8) | TLSEXT_hash_sha512:
					has_sha512_rsa = 1;
					break;
				case (TLSEXT_signature_ecdsa << 8) | TLSEXT_hash_sha256:
					has_sha256_ecdsa = 1;
					break;
				case (TLSEXT_signature_ecdsa << 8) | TLSEXT_hash_sha384:
					has_sha384_ecdsa = 1;
					break;
				case (TLSEXT_signature_ecdsa << 8) | TLSEXT_hash_sha512:
					has_sha512_ecdsa = 1;
					break;
				default:
					continue;
			}

			if (has_sha1_rsa && has_sha256_rsa && has_sha384_rsa && has_sha512_rsa
				&& has_sha256_ecdsa && has_sha384_ecdsa && has_sha512_ecdsa) {
				break;
			}
		}

		if (has_sha256_ecdsa || has_sha384_ecdsa || has_sha512_ecdsa) {
			CBS_init(&cipher_suites, ctx->cipher_suites, ctx->cipher_suites_len);

			while (CBS_len(&cipher_suites) != 0) {
				if (!CBS_get_u16(&cipher_suites, &cipher_suite)) {
					return -1;
				}

				cipher = SSL_get_cipher_by_value(cipher_suite);
				if (cipher && SSL_CIPHER_is_ECDSA(cipher)
					&& sk_SSL_CIPHER_find(ctx->ssl->ctx->cipher_list_by_id,
						NULL, cipher)) {
					has_ecdsa = 1;
					break;
				}
			}
		}

		if (has_ecdsa && SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_elliptic_curves,
				&extension_ptr, &extension_len)) {
			CBS_init(&extension, extension_ptr, extension_len);

			if (!CBS_get_u16_length_prefixed(&extension, &ec_curves)
				|| CBS_len(&ec_curves) == 0
				|| CBS_len(&extension) != 0) {
				return -1;
			}

			if (CBS_len(&ec_curves) % 2 != 0) {
				return -1;
			}

			while (CBS_len(&ec_curves) != 0) {
				if (!CBS_get_u16(&ec_curves, &ec_curve)) {
					return -1;
				}

				switch (ec_curve) {
					case SSL_CURVE_SECP256R1:
						has_secp256r1 = 1;
						break;
					case SSL_CURVE_SECP384R1:
						has_secp384r1 = 1;
						break;
					case SSL_CURVE_SECP521R1:
						has_secp521r1 = 1;
						break;
					default:
						continue;
				}

				if (has_secp256r1 && has_secp384r1 && has_secp521r1) {
					break;
				}
			}
		} else {
			/* Clients are not required to send a supported_curves extension. In this
			 * case, the server is free to pick any curve it likes. See RFC 4492,
			 * section 4, paragraph 3. */
			has_secp256r1 = has_ecdsa;
		}

		for (q = ngx_queue_head(&conf->ssl);
			q != ngx_queue_sentinel(&conf->ssl);
			q = ngx_queue_next(q)) {
			ssl_ctx = ngx_queue_data(q, ssl_ctx_st, queue);

			if ((ssl_ctx->nid == NID_sha1WithRSAEncryption && !has_sha1_rsa)
				|| (ssl_ctx->nid == NID_sha256WithRSAEncryption && !has_sha256_rsa)
				|| (ssl_ctx->nid == NID_sha384WithRSAEncryption && !has_sha384_rsa)
				|| (ssl_ctx->nid == NID_sha512WithRSAEncryption && !has_sha512_rsa)
				|| (ssl_ctx->nid == NID_ecdsa_with_SHA256 && !has_sha256_ecdsa)
				|| (ssl_ctx->nid == NID_ecdsa_with_SHA384 && !has_sha384_ecdsa)
				|| (ssl_ctx->nid == NID_ecdsa_with_SHA512 && !has_sha512_ecdsa)
				|| (ssl_ctx->curve_nid == NID_X9_62_prime256v1 && !has_secp256r1)
				|| (ssl_ctx->curve_nid == NID_secp384r1 && !has_secp384r1)
				|| (ssl_ctx->curve_nid == NID_secp521r1 && !has_secp521r1)) {
				continue;
			}

			SSL_set_SSL_CTX(ctx->ssl, ssl_ctx->ssl.ctx);
			break;
		}
	} else if (conf->ssl_rsa_sha256.ctx && server_name_ext) {
		SSL_set_SSL_CTX(ctx->ssl, conf->ssl_rsa_sha256.ctx);
	} else if (conf->ssl_rsa.ctx) {
		SSL_set_SSL_CTX(ctx->ssl, conf->ssl_rsa.ctx);
	}

	return 1;
}

/*
 * Copyright (c) 2022 Tomoyuki Sakurai <y@trombik.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <lwip/ip.h>
#include <lwip/netdb.h>
#include <lwip/err.h>
#include <lwip/sys.h>
#include <lwip/tcpip.h>
#include <lwip/priv/tcpip_priv.h>
#include <esp_err.h>
#include <esp_log.h>
#include <esp_wireguard.h>
#include <mbedtls/base64.h>

#include "wireguard-platform.h"
#include "wireguardif.h"

#define TAG "esp_wireguard"
#define WG_KEY_LEN  (32)
#define WG_B64_KEY_LEN (4 * ((WG_KEY_LEN + 2) / 3))
#if defined(CONFIG_LWIP_IPV6)
#define WG_ADDRSTRLEN  INET6_ADDRSTRLEN
#else
#define WG_ADDRSTRLEN  INET_ADDRSTRLEN
#endif

/*
 * Threading
 *
 * lwIP is built without core locking (CONFIG_LWIP_TCPIP_CORE_LOCKING=n), so netif, udp and
 * sys_timeout calls are only safe on the tcpip thread. Every step below that touches lwIP or
 * the WireGuard device runs there, through tcpip_api_call(), or directly when the caller is
 * already on it. Name resolution waits on the tcpip thread, so esp_wireguard_connect()
 * resolves the peer in the calling task first and refuses to run on the tcpip thread.
 *
 * There is one WireGuard netif (wg_netif_struct). wg_netif is non-NULL exactly while that
 * netif is registered with lwIP, and only the tcpip thread changes it. A connect that fails
 * after registering the netif removes it again, so a failed attempt never blocks the next one.
 *
 * Callers still serialize connect and disconnect: this file keeps one peer and one context.
 */
EXT_RAM_BSS_ATTR static struct netif wg_netif_struct = {0};
EXT_RAM_BSS_ATTR static struct netif *wg_netif = NULL;
EXT_RAM_BSS_ATTR static struct wireguardif_peer peer = {0};
EXT_RAM_BSS_ATTR static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
EXT_RAM_BSS_ATTR static uint8_t preshared_key_decoded[WG_KEY_LEN];

static esp_err_t esp_wireguard_peer_init(const wireguard_config_t *config, struct wireguardif_peer *peer)
{
    esp_err_t err;
    char addr_str[WG_ADDRSTRLEN];
    struct addrinfo *res = NULL;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;

    if (!config || !peer) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    peer->public_key = config->public_key;
    if (config->preshared_key != NULL) {
        size_t len;
        int res;

        ESP_LOGI(TAG, "using preshared_key");
        ESP_LOGD(TAG, "preshared_key: %s", config->preshared_key);
#if defined(CONFIG_WIREGUARD_x25519_IMPLEMENTATION_DEFAULT)
        ESP_LOGI(TAG, "X25519: default");
#elif defined(CONFIG_WIREGUARD_x25519_IMPLEMENTATION_NACL)
        ESP_LOGI(TAG, "X25519: NaCL");
#endif
        res = mbedtls_base64_decode(preshared_key_decoded, WG_KEY_LEN, &len, (unsigned char *)config->preshared_key, WG_B64_KEY_LEN);
        if (res != 0 || len != WG_KEY_LEN) {
            err = ESP_FAIL;
            ESP_LOGE(TAG, "base64_decode: %i", res);
            if (len != WG_KEY_LEN) {
                ESP_LOGE(TAG, "invalid decoded length, len: %u, should be %u", len, WG_KEY_LEN);
            }
            goto fail;
        }
        peer->preshared_key = preshared_key_decoded;
    } else {
        peer->preshared_key = NULL;
    }
    peer->keep_alive = config->persistent_keepalive;

    /* Allow all IPs through tunnel */
    {
        ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer->allowed_ip = allowed_ip;
        ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer->allowed_mask = allowed_mask;
    }

    /* resolve peer name or IP address */
    {
        ip_addr_t endpoint_ip;
        memset(&endpoint_ip, 0, sizeof(endpoint_ip));

        /* XXX lwip_getaddrinfo returns only the first address of a host at the moment */
        if (getaddrinfo(config->endpoint, NULL, &hints, &res) != 0) {
            err = ESP_FAIL;

            /* XXX gai_strerror() is not implemented */
            ESP_LOGE(TAG, "getaddrinfo: unable to resolve `%s`", config->endpoint);
            goto fail;
        }

        if (res->ai_family == AF_INET) {
            struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
            inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
        } else {
#if defined(CONFIG_LWIP_IPV6)
            struct in6_addr addr6 = ((struct sockaddr_in6 *) (res->ai_addr))->sin6_addr;
            inet6_addr_to_ip6addr(ip_2_ip6(&endpoint_ip), &addr6);
#endif
        }
        peer->endpoint_ip = endpoint_ip;

        if (inet_ntop(res->ai_family, &(peer->endpoint_ip), addr_str, WG_ADDRSTRLEN) == NULL) {
            ESP_LOGW(TAG, "inet_ntop: %i", errno);
        } else {
            ESP_LOGI(TAG, "Peer: %s (%s:%i)",
                                            config->endpoint,
                                            addr_str,
                                            config->port);
        }
    }
    peer->endport_port = config->port;
    peer->keep_alive = config->persistent_keepalive;
    err = ESP_OK;
fail:
    freeaddrinfo(res);
    return err;
}

typedef esp_err_t (*wg_tcpip_fn_t)(void *arg);

struct wg_tcpip_call {
    struct tcpip_api_call_data call; /* first: tcpip_api_call() hands this pointer back */
    wg_tcpip_fn_t fn;
    void *arg;
    esp_err_t ret;
};

static err_t wg_tcpip_trampoline(struct tcpip_api_call_data *data)
{
    struct wg_tcpip_call *c = (struct wg_tcpip_call *)data;
    c->ret = c->fn(c->arg);
    return ERR_OK;
}

static esp_err_t wg_run_on_tcpip(wg_tcpip_fn_t fn, void *arg)
{
    struct wg_tcpip_call c;

    if (sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
        return fn(arg);
    }
    memset(&c, 0, sizeof(c));
    c.fn = fn;
    c.arg = arg;
    c.ret = ESP_FAIL;
    if (tcpip_api_call(wg_tcpip_trampoline, &c.call) != ERR_OK) {
        return ESP_FAIL;
    }
    return c.ret;
}

/* tcpip thread. Registers wg_netif_struct; wg_netif is set only once the netif is up. */
static esp_err_t esp_wireguard_netif_create(const wireguard_config_t *config)
{
    esp_err_t err;
    ip_addr_t ip_addr;
    ip_addr_t netmask;
    ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    struct wireguardif_init_data wg = {0};
    struct netif *netif;

    if (!config) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    /* netif_add() on the registered struct would rewrite a live netif, and its init fails
     * anyway because the listen port is still bound. */
    if (wg_netif != NULL) {
        ESP_LOGE(TAG, "netif_add: a WireGuard netif is already registered");
        err = ESP_ERR_INVALID_STATE;
        goto fail;
    }

    /* Setup the WireGuard device structure */
    wg.private_key = config->private_key;
    wg.listen_port = config->listen_port;
    wg.bind_netif = NULL;

    ESP_LOGI(TAG, "allowed_ip: %s", config->allowed_ip);

    if (ipaddr_aton(config->allowed_ip, &ip_addr) != 1) {
        ESP_LOGE(TAG, "ipaddr_aton: invalid allowed_ip: `%s`", config->allowed_ip);
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }
    if (ipaddr_aton(config->allowed_ip_mask, &netmask) != 1) {
        ESP_LOGE(TAG, "ipaddr_aton: invalid allowed_ip_mask: `%s`", config->allowed_ip_mask);
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    /* Register the new WireGuard network interface with lwIP */
    netif = netif_add(
            &wg_netif_struct,
            ip_2_ip4(&ip_addr),
            ip_2_ip4(&netmask),
            ip_2_ip4(&gateway),
            &wg, &wireguardif_init,
            &ip_input);
    if (netif == NULL) {
        ESP_LOGE(TAG, "netif_add: failed");
        err = ESP_FAIL;
        goto fail;
    }
    wg_netif = netif;

    /* Mark the interface as administratively up, link up flag is set
     * automatically when peer connects */
    netif_set_up(wg_netif);
    err = ESP_OK;
fail:
    return err;
}

/* tcpip thread. Removes the WireGuard netif and everything attached to it. */
static void wg_netif_teardown(void)
{
    err_t lwip_err;

    if (wg_netif == NULL) {
        return;
    }

    // Clear the IP address to gracefully disconnect any clients while the
    // peers are still valid
    netif_set_ipaddr(wg_netif, IP4_ADDR_ANY4);

    if (wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) {
        lwip_err = wireguardif_disconnect(wg_netif, wireguard_peer_index);
        if (lwip_err != ERR_OK) {
            ESP_LOGW(TAG, "wireguardif_disconnect: peer_index: %" PRIu8 " err: %i", wireguard_peer_index, lwip_err);
        }

        lwip_err = wireguardif_remove_peer(wg_netif, wireguard_peer_index);
        if (lwip_err != ERR_OK) {
            ESP_LOGW(TAG, "wireguardif_remove_peer: peer_index: %" PRIu8 " err: %i", wireguard_peer_index, lwip_err);
        }
        wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
    }

    wireguardif_shutdown(wg_netif);
    netif_remove(wg_netif);
    wireguardif_fini(wg_netif);
    wg_netif = NULL;
}

struct wg_attach_args {
    wireguard_ctx_t *ctx;
    const struct wireguardif_peer *peer;
};

/* tcpip thread. Creates the netif and adds the resolved peer, or leaves nothing behind. */
static esp_err_t wg_attach_on_tcpip(void *arg)
{
    struct wg_attach_args *args = (struct wg_attach_args *)arg;
    esp_err_t err;
    err_t lwip_err;

    err = esp_wireguard_netif_create(args->ctx->config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_netif_create: %s", esp_err_to_name(err));
        goto fail;
    }

    /* Register the new WireGuard peer with the network interface */
    peer = *args->peer;
    wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
    lwip_err = wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);
    if (lwip_err != ERR_OK || wireguard_peer_index == WIREGUARDIF_INVALID_INDEX) {
        ESP_LOGE(TAG, "wireguardif_add_peer: %i", lwip_err);
        wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
        wg_netif_teardown();
        err = ESP_FAIL;
        goto fail;
    }
    args->ctx->netif = wg_netif;
    args->ctx->netif_default = netif_default;
    err = ESP_OK;
fail:
    return err;
}

/* tcpip thread */
static esp_err_t wg_peer_connect_on_tcpip(void *arg)
{
    wireguard_ctx_t *ctx = (wireguard_ctx_t *)arg;
    err_t lwip_err;

    if (ctx->netif == NULL || ctx->netif != wg_netif) {
        return ESP_ERR_INVALID_STATE;
    }
    lwip_err = wireguardif_connect(wg_netif, wireguard_peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGE(TAG, "wireguardif_connect: %i", lwip_err);
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* tcpip thread */
static esp_err_t wg_disconnect_on_tcpip(void *arg)
{
    wireguard_ctx_t *ctx = (wireguard_ctx_t *)arg;
    bool was_default;

    if (ctx->netif == NULL || ctx->netif != wg_netif) {
        return ESP_ERR_INVALID_STATE;
    }
    was_default = (netif_default == wg_netif);
    wg_netif_teardown();
    /* netif_remove() clears the default when it was this netif; restore the one saved at
     * connect. Otherwise leave the default alone: the saved pointer may be stale. */
    if (was_default) {
        netif_set_default(ctx->netif_default);
    }
    ctx->netif = NULL;
    return ESP_OK;
}

/* tcpip thread */
static esp_err_t wg_set_default_on_tcpip(void *arg)
{
    wireguard_ctx_t *ctx = (wireguard_ctx_t *)arg;

    netif_set_default(ctx->netif);
    return ESP_OK;
}

/* tcpip thread */
static esp_err_t wg_peer_is_up_on_tcpip(void *arg)
{
    wireguard_ctx_t *ctx = (wireguard_ctx_t *)arg;
    err_t lwip_err;

    if (ctx->netif == NULL || ctx->netif != wg_netif || wireguard_peer_index == WIREGUARDIF_INVALID_INDEX) {
        return ESP_FAIL;
    }
    lwip_err = wireguardif_peer_is_up(
            wg_netif,
            wireguard_peer_index,
            &peer.endpoint_ip,
            &peer.endport_port);
    return lwip_err == ERR_OK ? ESP_OK : ESP_FAIL;
}

esp_err_t esp_wireguard_init(wireguard_config_t *config, wireguard_ctx_t *ctx)
{
    esp_err_t err = ESP_FAIL;

    if (!config || !ctx) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    /* Clearing ctx->netif here would orphan a registered netif. */
    if (ctx->netif != NULL) {
        ESP_LOGE(TAG, "esp_wireguard_init: still connected, disconnect first");
        err = ESP_ERR_INVALID_STATE;
        goto fail;
    }

    err = wireguard_platform_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wireguard_platform_init: %s", esp_err_to_name(err));
        goto fail;
    }
    ctx->config = config;
    ctx->netif = NULL;
    ctx->netif_default = netif_default;

    err = ESP_OK;
fail:
    return err;
}

esp_err_t esp_wireguard_connect(wireguard_ctx_t *ctx)
{
    esp_err_t err = ESP_FAIL;
    struct wireguardif_peer resolved;
    struct wg_attach_args args;

    if (!ctx) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    /* getaddrinfo() below waits on the tcpip thread. */
    if (sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
        ESP_LOGE(TAG, "esp_wireguard_connect: called on the tcpip thread");
        err = ESP_ERR_INVALID_STATE;
        goto fail;
    }

    if (ctx->netif == NULL) {
        /* Resolve the peer before registering anything with lwIP, so a DNS failure leaves
         * no netif behind. */
        memset(&resolved, 0, sizeof(resolved));
        err = esp_wireguard_peer_init(ctx->config, &resolved);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_wireguard_peer_init: %s", esp_err_to_name(err));
            goto fail;
        }
        if (ip_addr_isany(&resolved.endpoint_ip)) {
            ESP_LOGE(TAG, "esp_wireguard_peer_init: endpoint resolved to the any address");
            err = ESP_FAIL;
            goto fail;
        }

        args.ctx = ctx;
        args.peer = &resolved;
        err = wg_run_on_tcpip(wg_attach_on_tcpip, &args);
        if (err != ESP_OK) {
            goto fail;
        }
    }

    ESP_LOGI(TAG, "Connecting to %s:%i", ctx->config->endpoint, ctx->config->port);
    err = wg_run_on_tcpip(wg_peer_connect_on_tcpip, ctx);
fail:
    return err;
}

esp_err_t esp_wireguard_set_default(wireguard_ctx_t *ctx)
{
    if (!ctx) {
        return ESP_ERR_INVALID_ARG;
    }
    return wg_run_on_tcpip(wg_set_default_on_tcpip, ctx);
}

esp_err_t esp_wireguard_disconnect(wireguard_ctx_t *ctx)
{
    if (!ctx) {
        return ESP_ERR_INVALID_ARG;
    }
    return wg_run_on_tcpip(wg_disconnect_on_tcpip, ctx);
}

esp_err_t esp_wireguardif_peer_is_up(wireguard_ctx_t *ctx)
{
    if (!ctx) {
        return ESP_ERR_INVALID_ARG;
    }
    return wg_run_on_tcpip(wg_peer_is_up_on_tcpip, ctx);
}

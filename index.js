/**
 * ╔══════════════════════════════════════════════════════╗
 * ║       🤖 CANTOR8 MULTI-ACCOUNT WALLET BOT V2        ║
 * ║    Auto CC ↔ USDCX Round-Trip Swap (Parallel)       ║
 * ╚══════════════════════════════════════════════════════╝
 *
 * Usage: node index.js
 * Config: config.json (accounts[], swap settings, API URLs)
 */

import { readFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import axios from 'axios';
import chalk from 'chalk';
import { HttpsProxyAgent } from 'https-proxy-agent';

// ── Setup ────────────────────────────────────────────────────────────────
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const config = JSON.parse(readFileSync(new URL('./config.json', import.meta.url), 'utf-8'));

const BACKEND = config.api.backend_url;
const SWAP_API = config.api.swap_url;
const EXCHANGE = config.api.exchange_url;

const ASSET_TO_INSTRUMENT = { '0x0': 'Amulet', 'USDCX': 'USDCx' };

const BASE_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Origin': 'https://wallet.cantor8.tech',
    'Referer': 'https://wallet.cantor8.tech/',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
};

const TOKEN_MAX_AGE_MS = 45 * 60 * 1000;
const SETUP_WAIT_MAX = Infinity;   // max retries waiting for account setup (422)
const SETUP_WAIT_SEC = 10;   // seconds between setup retries

// ── Circuit Breaker ─────────────────────────────────────────────────────
const CIRCUIT_BREAKER_MS = 60 * 60 * 1000;  // 5 min: max time retryOnNetwork keeps retrying
const CIRCUIT_BREAKER_COOLDOWN = 30;       // seconds to wait before soft restart

class CircuitBreakerError extends Error {
    constructor(originalError, attempts, elapsedMs) {
        super(`Circuit breaker tripped after ${attempts} attempts (${Math.round(elapsedMs / 1000)}s): ${originalError.message}`);
        this.name = 'CircuitBreakerError';
        this.originalError = originalError;
        this.attempts = attempts;
        this.elapsedMs = elapsedMs;
    }
}

class RateLimitError extends Error {
    constructor(originalError) {
        super(`Rate limited (429): ${originalError.message}`);
        this.name = 'RateLimitError';
        this.originalError = originalError;
    }
}

class ServerError extends Error {
    constructor(originalError, statusCode) {
        super(`Server error (${statusCode}): ${originalError.message}`);
        this.name = 'ServerError';
        this.originalError = originalError;
        this.statusCode = statusCode;
    }
}

// ── Crypto ───────────────────────────────────────────────────────────────

function generateKeyPairs(mnemonic) {
    const { path_prefix, path_suffix, key_count } = config.derivation;
    const seed = mnemonicToSeedSync(mnemonic, '');
    const hdkey = HDKey.fromMasterSeed(seed);
    const keyPairs = [];
    for (let i = 0; i < key_count; i++) {
        const path = `${path_prefix}/${i}'/${path_suffix}`;
        const child = hdkey.derive(path);
        const privateKey = child.privateKey;
        if (!privateKey || privateKey.length !== 32) throw new Error(`Key derivation failed at ${path}`);
        const publicKey = ed.getPublicKey(privateKey);
        keyPairs.push({
            index: i, path, privateKey, publicKey,
            publicKeyHex: Buffer.from(publicKey).toString('hex'),
        });
    }
    return keyPairs;
}

function signMessage(privateKey, message) {
    const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    return ed.sign(msg, privateKey);
}

function toHex(bytes) { return Buffer.from(bytes).toString('hex'); }
function toBase64(bytes) { return Buffer.from(bytes).toString('base64'); }

function generateOrderId() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = randomBytes(20);
    let id = 'ord_';
    for (let i = 0; i < 20; i++) id += chars[bytes[i] % chars.length];
    return id;
}

// ── Helpers ──────────────────────────────────────────────────────────────

const sleep = (sec) => new Promise(r => setTimeout(r, sec * 1000));
const shortId = (id) => id.length > 20 ? `${id.slice(0, 12)}...${id.slice(-8)}` : id;

// ── Retry on Network Error ──────────────────────────────────────────────

const RETRYABLE_CODES = ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'EPIPE', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH', 'ERR_SOCKET_CONNECTION_TIMEOUT', 'ECONNABORTED'];

function isRetryableError(err) {
    if (RETRYABLE_CODES.includes(err.code)) return true;
    if (err.response?.status >= 500) return true;
    if (err.response?.status === 429) return true;
    if (err.response?.status === 400) {
        const detail = String(err.response?.data?.detail || err.response?.data?.message || JSON.stringify(err.response?.data || ''));
        if (detail.toLowerCase().includes('challenge')) return true;
    }
    if (err.message?.includes('socket hang up')) return true;
    if (err.message?.includes('ECONNRESET')) return true;
    if (err.message?.includes('network')) return true;
    if (err.message?.includes('timeout')) return true;
    if (err.code === 'ERR_BAD_RESPONSE') return true;
    return false;
}

async function retryOnNetwork(fn, { maxRetries = Infinity, baseDelay = 3, label = '', log = null, circuitBreakerMs = CIRCUIT_BREAKER_MS } = {}) {
    const startTime = Date.now();
    for (let attempt = 0; ; attempt++) {
        try {
            return await fn();
        } catch (err) {
            // 429 Rate Limit → langsung throw RateLimitError, biar caller handle (istirahat 5 menit)
            if (err.response?.status === 429) {
                if (log) log(`🚦 [${label}] Rate limited (429)! Akan istirahat 5 menit...`);
                throw new RateLimitError(err);
            }

            // 5xx Server Error → langsung throw ServerError, biar caller soft restart
            if (err.response?.status >= 500) {
                if (log) log(`🔴 [${label}] Server error (${err.response.status})! Akan soft restart...`);
                throw new ServerError(err, err.response.status);
            }

            if (!isRetryableError(err)) throw err;
            if (attempt >= maxRetries) throw err;

            // Circuit breaker: if we've been retrying for too long, force a soft restart
            const elapsed = Date.now() - startTime;
            if (circuitBreakerMs > 0 && elapsed > circuitBreakerMs) {
                if (log) log(`🔴 [${label}] Circuit breaker! ${attempt + 1} attempts over ${Math.round(elapsed / 1000)}s — forcing restart`);
                throw new CircuitBreakerError(err, attempt + 1, elapsed);
            }

            const delay = Math.min(baseDelay * Math.pow(2, attempt), 60);
            if (log) log(`🔄 [${label || 'retry'}] ${formatError(err)} (attempt ${attempt + 1}, wait ${delay}s)`);
            await sleep(delay);
        }
    }
}

function formatUptime(startMs) {
    const sec = Math.floor((Date.now() - startMs) / 1000);
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `${h}h${String(m).padStart(2, '0')}m${String(s).padStart(2, '0')}s`;
    return `${m}m${String(s).padStart(2, '0')}s`;
}

function formatError(err) {
    if (err.response) {
        const code = err.response.status;
        if (code >= 500) return `[${code}] Server error. Retrying...`;
        if (code === 401) return `[${code}] Auth expired, refreshing...`;
        if (code === 400) {
            const detail = String(err.response.data?.detail || err.response.data?.message || JSON.stringify(err.response.data) || '');
            return `[400] Bad Request: ${detail.slice(0, 150)}`;
        }
        if (code === 409) return `[${code}] Conflict — active order exists`;
        if (code === 422) {
            const detail = String(err.response.data?.detail || '');
            if (detail.includes('Account setup not complete')) return `[422] Account setup pending, waiting...`;
            return `[422] Server rejected request`;
        }
        if (code === 429) return `[${code}] Rate limited. Retrying...`;
        return `[${code}] Server error. Retrying...`;
    }
    if (['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND'].includes(err.code)) {
        return `[${err.code}] Network error. Retrying...`;
    }
    return err.message;
}

function ts() {
    return new Date().toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }).replace(/:/g, '.');
}

// ── Axios Factory (per-account proxy) ────────────────────────────────────

function createAxiosInstance(proxyUrl) {
    const opts = { timeout: 30000 };
    if (proxyUrl) {
        const agent = new HttpsProxyAgent(proxyUrl, { keepAlive: false });
        opts.httpAgent = agent;
        opts.httpsAgent = agent;
        opts.proxy = false;
    }
    return axios.create(opts);
}

// ── API Factories ────────────────────────────────────────────────────────

function createWalletApi(ax) {
    const h = BASE_HEADERS;
    const auth = (token) => ({ ...h, Authorization: `Bearer ${token}` });
    return {
        recoverAccount: (keys) =>
            ax.post(`${BACKEND}/accounts/recovery_v3`, { public_keys: keys }, { headers: h }).then(r => r.data),
        getChallenge: (pid) =>
            ax.post(`${BACKEND}/auth/challenge`, { party_id: pid }, { headers: h }).then(r => r.data),
        login: (pid, ch, sig) =>
            ax.post(`${BACKEND}/auth/login`, { party_id: pid, challenge: ch, signature: sig }, { headers: h }).then(r => r.data),
        getBalance: (token) =>
            ax.get(`${BACKEND}/balance`, { headers: auth(token) }).then(r => r.data),
        getHistory: (token) =>
            ax.get(`${BACKEND}/transfer/history`, { headers: auth(token) }).then(r => r.data),
        getMyTag: (token) =>
            ax.get(`${BACKEND}/tags/my`, { headers: auth(token) }).then(r => r.data),
        prepareTransfer: (token, body) =>
            ax.post(`${BACKEND}/transfer/prepare`, {
                instrument_admin_id: body.instrumentAdminId,
                instrument_id: body.instrumentId,
                receiver_party_id: body.receiverPartyId,
                amount: body.amount,
                reason: body.reason || '',
                app_name: body.appName || 'swap-v1',
                metadata: body.metadata || {}
            }, { headers: auth(token) }).then(r => r.data),
        executeTransaction: (token, body) =>
            ax.post(`${BACKEND}/transaction/execute`, {
                command_id: body.commandId,
                prepared_tx_b64: body.preparedTxB64,
                hashing_scheme_version: body.hashingSchemeVersion,
                signature_b64: body.signatureB64,
            }, { headers: auth(token) }).then(r => r.data),
        getCommandStatus: (token, commandId) =>
            ax.get(`${BACKEND}/command/${commandId}/status`, { headers: auth(token) }).then(r => r.data),
        getOffers: (token) =>
            ax.get(`${BACKEND}/offers`, { headers: auth(token) }).then(r => r.data),
        acceptOfferPrepare: (token, body) =>
            ax.post(`${BACKEND}/offer/accept/prepare`, {
                contract_id: body.contractId, party_id: body.partyId
            }, { headers: auth(token) }).then(r => r.data),
        getTransferStatus: (token, commandId) =>
            ax.get(`${BACKEND}/transfer/status`, { params: { command_id: commandId }, headers: auth(token) }).then(r => r.data),
        getRegisterStatus: (token) =>
            ax.get(`${BACKEND}/register/status_v2`, { headers: auth(token) }).then(r => r.data),
        postConfirmV2: (token) =>
            ax.post(`${BACKEND}/register/post_confirm_v2`, {}, { headers: auth(token) }).then(r => r.data),
        getOutgoingExpired: (token) =>
            ax.get(`${BACKEND}/offers/outgoing_expired`, { headers: auth(token) }).then(r => r.data),
    };
}

function createSwapApi(ax) {
    const h = BASE_HEADERS;
    const auth = (token) => ({ ...h, Authorization: `Bearer ${token}` });
    return {
        getNonce: () =>
            ax.get(`${SWAP_API}/auth/nonce`, { headers: h }).then(r => r.data),
        bindSignature: (nonce, cantonAddress) =>
            ax.post(`${SWAP_API}/auth/signature`, { nonce, cantonAddress, signature: null }, { headers: h }).then(r => r.data),
        getQuote: (fromChain, fromAsset, toChain, toAsset, sendAmount) =>
            ax.post(`${SWAP_API}/quotes`, {
                fromChain, fromAsset, toChain, toAsset, sendAmount: String(sendAmount)
            }, { headers: h }).then(r => r.data),
        createOrder: (swapToken, orderId, quoteId, toAddress, slippageBps = 200) =>
            ax.post(`${SWAP_API}/orders`, { orderId, quoteId, toAddress, slippageBps }, { headers: auth(swapToken) }).then(r => r.data),
        getOrderStatus: (swapToken, orderId) =>
            ax.get(`${SWAP_API}/orders/${encodeURIComponent(orderId)}`, { headers: auth(swapToken) }).then(r => r.data),
        getActiveOrder: (swapToken, filters = {}) =>
            ax.get(`${SWAP_API}/orders/active`, { params: filters, headers: auth(swapToken) }).then(r => r.data),
        cancelOrder: (swapToken, orderId) =>
            ax.post(`${SWAP_API}/orders/${encodeURIComponent(orderId)}/cancel`, {}, { headers: auth(swapToken) }).then(r => r.data),
        checkExchange: () =>
            ax.head(EXCHANGE, { headers: h, timeout: 5000 }).then(() => true).catch(() => false),
        getLeaderboard: (address = null) =>
            ax.get(`${SWAP_API}/leaderboard`, {
                params: { limit: 50, includeRewards: true, includeAll: true, ...(address ? { address } : {}) },
                headers: h,
            }).then(r => r.data),
        checkEligibility: (partyId) =>
            ax.get(`${SWAP_API}/party/check-eligibility`, { params: { partyId }, headers: h }).then(r => r.data),
    };
}

// ── Per-Account Dashboard + Log ──────────────────────────────────────────

const MAX_ACC_LOGS = 3;

const dashboard = {
    accounts: [],
    _timer: null,
    _renderPending: false,

    init(accountConfigs) {
        this.accounts = accountConfigs.map((acc, i) => ({
            name: acc.name || `Acc ${i + 1}`,
            startTime: Date.now(),
            cc: 0, usdcx: 0,
            swapsCCtoU: 0, swapsUtCC: 0,
            maxCCtoU: config.swap.rounds || 0, maxUtCC: 0,
            totalSwaps: 0, lastSwapDir: '',
            monthReward: 0, monthVolume: 0, monthTxns: 0,
            totalReward: 0, pendingReward: 0, rank: 0,
            rewardDate: '',
            nonce: false, swap: false, proxy: !!acc.proxy,
            status: 'init',
            logs: [],
        }));
    },

    update(index, data) {
        Object.assign(this.accounts[index], data);
        this._scheduleRender();
    },

    log(index, msg) {
        const a = this.accounts[index];
        a.logs.push(`${ts()} ${msg}`);
        while (a.logs.length > MAX_ACC_LOGS) a.logs.shift();
        this._scheduleRender();
    },

    _scheduleRender() {
        if (this._renderPending) return;
        this._renderPending = true;
        setTimeout(() => {
            this._renderPending = false;
            this._render();
        }, 200);
    },

    _render() {
        const out = process.stdout;
        out.write('\x1B[H\x1B[2J');

        for (let i = 0; i < this.accounts.length; i++) {
            const a = this.accounts[i];
            const up = formatUptime(a.startTime);

            const swapTotal = `${a.totalSwaps}(${a.lastSwapDir || '-'})`;
            out.write(
                chalk.yellow('🏦 ') + chalk.white.bold(a.name) + '\n' +
                `  CC: ${chalk.white.bold(a.cc.toFixed(2))}  USDCx: ${chalk.white.bold(a.usdcx.toFixed(4))}  Up: ${chalk.cyan(up)}\n`
            );

            out.write(
                `  Swaps: ${chalk.white(swapTotal)}  CC→U:${chalk.cyan(a.swapsCCtoU)}/${chalk.gray(a.maxCCtoU)} U→CC:${chalk.cyan(a.swapsUtCC)}/${chalk.gray(a.maxUtCC)}\n`
            );

            const dateStr = a.rewardDate || new Date().toISOString().slice(0, 10);
            if (a.monthReward > 0 || a.rank > 0) {
                out.write(
                    `  🏆 Reward [${chalk.gray(dateStr)}]: ${chalk.green(a.monthReward.toFixed(2) + ' CC')} Vol ${chalk.cyan('$' + a.monthVolume.toFixed(0))} ${chalk.yellow(a.monthTxns + ' Txns')}  Rank ${chalk.magenta('#' + a.rank)}\n`
                );
            } else {
                out.write(`  🏆 Reward [${chalk.gray(dateStr)}]: ${chalk.gray('loading...')}\n`);
            }

            for (const line of a.logs) {
                out.write(chalk.gray(`  ${line}`) + '\n');
            }
            out.write('\n');
        }
    },

    startAutoRefresh() {
        if (this._timer) return;
        this._timer = setInterval(() => this._scheduleRender(), 10000);
    },

    stop() {
        if (this._timer) { clearInterval(this._timer); this._timer = null; }
    },
};

// ── Session Factory ──────────────────────────────────────────────────────

function createSession() {
    return {
        walletToken: null,
        swapToken: null,
        partyId: null,
        keyPair: null,
        keyPairs: null,
        matchIdx: 0,
        walletLoginTime: 0,
        swapLoginTime: 0,

        async refreshWalletToken(walletApi, log) {
            log('🔑 Refreshing wallet token...');
            await retryOnNetwork(async () => {
                const { challenge } = await walletApi.getChallenge(this.partyId);
                const sig = toHex(signMessage(this.keyPair.privateKey, challenge));
                const { access_token } = await walletApi.login(this.partyId, challenge, sig);
                this.walletToken = access_token;
                this.walletLoginTime = Date.now();
            }, { maxRetries: 8, baseDelay: 3, label: 'refreshWallet', log });
        },

        async refreshSwapToken(swapApi, log) {
            log('🔑 Refreshing swap token...');
            await retryOnNetwork(async () => {
                const { nonce } = await swapApi.getNonce();
                const swapAuth = await swapApi.bindSignature(nonce, this.partyId);
                this.swapToken = swapAuth.accessToken;
                this.swapLoginTime = Date.now();
            }, { maxRetries: 8, baseDelay: 3, label: 'refreshSwap', log });
        },

        async ensureFreshTokens(walletApi, swapApi, log) {
            const now = Date.now();
            if (this.walletLoginTime && (now - this.walletLoginTime) > TOKEN_MAX_AGE_MS) {
                try {
                    await this.refreshWalletToken(walletApi, log);
                } catch (err) {
                    log(`⚠️ Wallet token refresh failed: ${formatError(err)}`);
                }
            }
            if (this.swapLoginTime && (now - this.swapLoginTime) > TOKEN_MAX_AGE_MS) {
                try {
                    await this.refreshSwapToken(swapApi, log);
                } catch (err) {
                    log(`⚠️ Swap token refresh failed: ${formatError(err)}`);
                }
            }
        },

        async withRetry(fn, tokenType, walletApi, swapApi, log) {
            // Wrap with network retry first, then handle 401 inside
            return await retryOnNetwork(async () => {
                try {
                    return await fn();
                } catch (err) {
                    if (err.response?.status === 401) {
                        if (tokenType === 'swap') {
                            await this.refreshSwapToken(swapApi, log);
                        } else {
                            await this.refreshWalletToken(walletApi, log);
                        }
                        return await fn();
                    }
                    throw err;
                }
            }, { maxRetries: 5, baseDelay: 3, label: 'apiCall', log });
        },
    };
}

// ── Resolve Active Order Helper ──────────────────────────────────────────

async function resolveActiveOrder(ctx) {
    const { session, swapApi, walletApi, log } = ctx;
    const TERMINAL_S = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
    try {
        const active = await swapApi.getActiveOrder(session.swapToken, {});
        if (!active?.orderId || TERMINAL_S.includes(active.status)) return false;
        log(`🔄 Active order ${shortId(active.orderId)} (${active.status}), polling...`);
        for (let rp = 0; rp < 60; rp++) {
            await sleep(5);
            if (rp % 12 === 0 && rp > 0) await session.ensureFreshTokens(walletApi, swapApi, log);
            try {
                const st = await retryOnNetwork(
                    () => swapApi.getOrderStatus(session.swapToken, active.orderId),
                    { maxRetries: 3, baseDelay: 3, label: 'resolveOrder', log }
                );
                log(`🔄 ${shortId(active.orderId)} → ${st.status}`);
                if (TERMINAL_S.includes(st.status)) {
                    log(`✅ Order ${shortId(active.orderId)} → ${st.status}`);
                    return true;
                }
            } catch (pe) {
                if (pe.response?.status === 401) { await session.refreshSwapToken(swapApi, log); continue; }
                log(`⚠️ resolveOrder poll error: ${formatError(pe)}`);
                break;
            }
        }
        return true;
    } catch { return false; }
}

// ── Per-Account Runner ───────────────────────────────────────────────────

const MAX_ACCOUNT_RETRIES = Infinity;
const ACCOUNT_RETRY_BASE_DELAY = 15; // seconds

async function runAccount(accConfig, index) {
    const name = accConfig.name || `Acc ${index + 1}`;
    const log = (msg) => dashboard.log(index, msg);

    for (let accountAttempt = 1; ; accountAttempt++) {
        try {
            await runAccountOnce(accConfig, index, name, log);
            return; // success, exit retry loop
        } catch (err) {
            const isRateLimit = err instanceof RateLimitError;
            const isServerError = err instanceof ServerError;
            const isCircuitBreaker = err instanceof CircuitBreakerError;

            if (isRateLimit) {
                // 429 Rate Limit → istirahat 5 menit lalu restart
                const RATE_LIMIT_COOLDOWN = 5 * 60; // 5 menit dalam detik
                log(`🚦 Rate limited! Istirahat 5 menit sebelum restart...`);
                dashboard.update(index, { status: 'rate-limited 5m' });
                await sleep(RATE_LIMIT_COOLDOWN);
                log(`🔄 Selesai istirahat, restart akun (attempt ${accountAttempt})`);
                dashboard.update(index, { status: `restart #${accountAttempt}` });
            } else if (isServerError) {
                // 5xx Server Error → soft restart dengan jeda pendek
                log(`🔴 Server error (${err.statusCode})! Soft restart akun...`);
                dashboard.update(index, { status: 'server-err restart' });
                await sleep(CIRCUIT_BREAKER_COOLDOWN); // 30s cooldown
                log(`🔄 Soft restart akun (attempt ${accountAttempt})`);
                dashboard.update(index, { status: `restart #${accountAttempt}` });
            } else if (isCircuitBreaker) {
                log(`🔴 Circuit breaker triggered — soft-restarting account (fresh connections + re-auth)...`);
                dashboard.update(index, { status: `restart #${accountAttempt}` });
                await sleep(CIRCUIT_BREAKER_COOLDOWN);
            } else {
                log(`❌ ${formatError(err)}`);
                const delay = Math.min(ACCOUNT_RETRY_BASE_DELAY * Math.pow(1.5, accountAttempt - 1), 120);
                log(`🔄 Restarting in ${Math.round(delay)}s (attempt ${accountAttempt})`);
                dashboard.update(index, { status: `restart #${accountAttempt}` });
                await sleep(delay);
            }
        }
    }
}

async function runAccountOnce(accConfig, index, name, log) {
    const ax = createAxiosInstance(accConfig.proxy || '');
    const walletApi = createWalletApi(ax);
    const swapApi = createSwapApi(ax);
    const session = createSession();

    if (accConfig.proxy) {
        log(`Proxy: ${accConfig.proxy.replace(/\/\/.*@/, '//***@')}`);
    }

    // Step 1: Derive keys
    dashboard.update(index, { status: 'deriving' });
    log('🔑 Deriving key pairs...');
    const keyPairs = generateKeyPairs(accConfig.mnemonic);
    log(`🔑 ${keyPairs.length} key pairs derived`);

    // Step 2: Recover account (with network retry)
    dashboard.update(index, { status: 'recovering' });
    log('🔍 Recovering account...');
    const recovery = await retryOnNetwork(
        () => walletApi.recoverAccount(keyPairs.map(k => k.publicKeyHex)),
        { maxRetries: 5, baseDelay: 3, label: 'recover', log }
    );
    const matchIdx = (recovery.results || []).findIndex(r => r !== null);
    if (matchIdx === -1) throw new Error('No account found for this mnemonic');
    const acct = recovery.results[matchIdx];
    log(`🆔 Party: ${shortId(acct.party_id)}`);

    // Step 3: Login (with network retry)
    dashboard.update(index, { status: 'auth', nonce: true });
    log('🔐 Authenticating...');
    session.partyId = acct.party_id;
    session.keyPairs = keyPairs;
    session.matchIdx = matchIdx;
    session.keyPair = keyPairs[matchIdx];

    await retryOnNetwork(async () => {
        const { challenge } = await walletApi.getChallenge(acct.party_id);
        const sig = toHex(signMessage(keyPairs[matchIdx].privateKey, challenge));
        const { access_token } = await walletApi.login(acct.party_id, challenge, sig);
        session.walletToken = access_token;
        session.walletLoginTime = Date.now();
    }, { maxRetries: 5, baseDelay: 3, label: 'login', log });
    log('✅ Authenticated');

    // Step 3b: Post-login registration checks (HAR flow)
    try {
        const regStatus = await walletApi.getRegisterStatus(session.walletToken);
        log(`📋 Registration: ${regStatus.is_registered ? '✅' : '⏳'}`);
        await walletApi.postConfirmV2(session.walletToken);
        await walletApi.getOutgoingExpired(session.walletToken);
    } catch { /* non-critical */ }

    // Step 4: Dashboard data
    const ctx = { session, walletApi, swapApi, log, name, index };
    log('📊 Fetching balance & stats...');
    const holdings = await refreshAccountData(ctx);

    // Step 5: Swap
    if (config.swap.enabled) {
        dashboard.update(index, { swap: true });
        await performSwap(ctx, holdings);
    } else {
        log('⏸ Swap disabled');
        dashboard.update(index, { status: 'idle' });
    }

    log('🏁 Completed');
    dashboard.update(index, { status: 'done' });
}

// ── Refresh Account Data ─────────────────────────────────────────────────

async function refreshAccountData(ctx) {
    const { session, walletApi, swapApi, log, index } = ctx;

    const { holdings = {} } = await session.withRetry(
        () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
    );

    let cc = 0, usdcx = 0;
    for (const [tok, info] of Object.entries(holdings)) {
        if (tok === 'Amulet' || tok === 'CC (Amulet)' || tok === 'CC') cc = info.balance || 0;
        if (tok === 'USDCx' || tok === 'USDCX') usdcx = info.balance || 0;
    }

    let monthReward = 0, monthVolume = 0, monthTxns = 0;
    let totalReward = 0, pendingReward = 0, rank = 0;
    try {
        const lb = await swapApi.getLeaderboard(session.partyId);
        const me = lb.requestedAddress || null;
        if (me) {
            monthReward = parseFloat(me.rewardAccruedCc ?? 0);
            monthVolume = parseFloat(me.rewardVolumeUsd ?? me.volumeUsd ?? 0);
            monthTxns = parseInt(me.rewardSwapCount ?? me.swapCount ?? 0);
            totalReward = parseFloat(me.rewardTotalCc ?? 0);
            pendingReward = parseFloat(me.rewardAccruedCc ?? 0);
            rank = parseInt(me.rank ?? me.position ?? 0);
        }
    } catch { /* skip */ }

    dashboard.update(index, {
        cc, usdcx,
        monthReward, monthVolume, monthTxns,
        totalReward, pendingReward, rank,
        rewardDate: new Date().toISOString().slice(0, 10),
    });

    return holdings;
}

// ── Wait for Account Setup (422 handling) ────────────────────────────────

async function waitForAccountSetup(swapApi, swapToken, partyId, log) {
    for (let i = 1; i <= SETUP_WAIT_MAX; i++) {
        log(`⏳ Account setup pending (${i}/${SETUP_WAIT_MAX}), waiting ${SETUP_WAIT_SEC}s...`);
        await sleep(SETUP_WAIT_SEC);
        try {
            // Test with a dummy quote + order to see if setup is done
            const q = await swapApi.getQuote('CC', '0x0', 'CC', 'USDCX', 1);
            const testId = generateOrderId();
            await swapApi.createOrder(swapToken, testId, q.quoteId, partyId);
            // Success — cancel the test order and return
            try { await swapApi.cancelOrder(swapToken, testId); } catch { /* ignore */ }
            log('✅ Account setup complete');
            return true;
        } catch (err) {
            const detail = String(err.response?.data?.detail || '');
            if (detail.includes('Account setup not complete') || err.response?.status === 422) continue;
            // Different error = setup might be done, or other issue
            return true;
        }
    }
    return false;
}

// ── Instrument Admin ID Helper ───────────────────────────────────────────

function getInstrumentAdminId(holdings, assetKey) {
    // assetKey is '0x0' (Amulet/CC) or 'USDCX'
    const nameMap = {
        '0x0': ['Amulet', 'CC (Amulet)', 'CC'],
        'USDCX': ['USDCx', 'USDCX'],
    };
    const names = nameMap[assetKey] || [assetKey];
    for (const n of names) {
        if (holdings?.[n]?.instrument_admin_id) return holdings[n].instrument_admin_id;
    }
    return '';
}

// ── Perform Swap ─────────────────────────────────────────────────────────

async function performSwap(ctx, holdings) {
    const { session, walletApi, swapApi, log, name, index } = ctx;
    const { rounds, delay_seconds, min_amount, pair_a, pair_b } = config.swap;

    dashboard.update(index, { status: 'checking', maxCCtoU: rounds });

    log('🌐 Checking exchange status...');
    const exchangeOk = await swapApi.checkExchange();
    if (!exchangeOk) {
        log('❌ Exchange offline');
        dashboard.update(index, { status: 'offline', swap: false });
        return;
    }

    let ccBalance = holdings?.['Amulet']?.balance || holdings?.['CC (Amulet)']?.balance || holdings?.['CC']?.balance || 0;
    let usdcxBalance = holdings?.['USDCx']?.balance || holdings?.['USDCX']?.balance || 0;
    let holdingsCache = holdings || {}; // cache for instrument_admin_id lookups

    // Auth swap API
    dashboard.update(index, { status: 'swap-auth' });
    log('🔐 Authenticating swap API...');
    await retryOnNetwork(async () => {
        const { nonce } = await swapApi.getNonce();
        const swapAuth = await swapApi.bindSignature(nonce, session.partyId);
        session.swapToken = swapAuth.accessToken;
        session.swapLoginTime = Date.now();
    }, { maxRetries: 8, baseDelay: 5, label: 'swapAuth', log });
    dashboard.update(index, { swap: true });
    log('✅ Swap API ready');

    // Check eligibility
    try {
        const eligibility = await swapApi.checkEligibility(session.partyId);
        if (!eligibility.eligible) {
            log('❌ Account not eligible for swap');
            dashboard.update(index, { status: 'ineligible', swap: false });
            return;
        }
        log('✅ Eligible for swap');
    } catch { /* non-critical, continue */ }

    // ── Recovery: check for in-flight orders from previous session ──
    log('🔍 Checking for unfinished orders...');
    try {
        const activeOrder = await swapApi.getActiveOrder(session.swapToken, {});
        if (activeOrder?.orderId) {
            const TERMINAL = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
            if (!TERMINAL.includes(activeOrder.status)) {
                log(`🔄 Resuming order ${shortId(activeOrder.orderId)} (${activeOrder.status})`);
                dashboard.update(index, { status: `resuming ${activeOrder.status}` });

                const maxResumeDurationMs = 10 * 60 * 1000; // 10 minutes max
                const resumeStartTime = Date.now();
                let resumeCount = 0;
                let lastResumeStatus = activeOrder.status;
                while (true) {
                    // Time-limit: don't poll forever
                    if (Date.now() - resumeStartTime > maxResumeDurationMs) {
                        log(`🔴 Order resume timed out after 10m — forcing restart`);
                        throw new CircuitBreakerError(new Error('Order resume poll timeout'), resumeCount, Date.now() - resumeStartTime);
                    }
                    await sleep(5);
                    resumeCount++;
                    if (resumeCount % 12 === 0) await session.ensureFreshTokens(walletApi, swapApi, log);
                    try {
                        const check = await swapApi.getOrderStatus(session.swapToken, activeOrder.orderId);
                        if (check.status !== lastResumeStatus) {
                            log(`⏳ Order: ${lastResumeStatus} → ${check.status}`);
                            lastResumeStatus = check.status;
                        }
                        if (TERMINAL.includes(check.status)) {
                            log(`✅ Order ${shortId(activeOrder.orderId)} → ${check.status}`);
                            break;
                        }
                    } catch (pollErr) {
                        if (pollErr.response?.status === 401) {
                            await session.refreshSwapToken(swapApi, log);
                            continue;
                        }
                        log(`✅ Order resolved`);
                        break;
                    }
                }
            } else {
                log(`✅ Previous order already ${activeOrder.status}`);
            }
        } else {
            log('✅ No unfinished orders');
        }
    } catch {
        log('✅ No active orders found');
    }

    log('📩 Checking pending offers...');
    await acceptPendingOffers(ctx);

    log('💰 Refreshing balances...');
    try {
        const { holdings: h } = await session.withRetry(
            () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
        );
        ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || h?.['CC']?.balance || 0;
        usdcxBalance = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;
        holdingsCache = h || holdingsCache;
        dashboard.update(index, { cc: ccBalance, usdcx: usdcxBalance });
        log(`💰 CC: ${ccBalance.toFixed(2)} | USDCx: ${usdcxBalance.toFixed(4)}`);
    } catch { /* use original */ }

    // Bulk-back if CC too low
    if (ccBalance < min_amount && usdcxBalance >= 1) {
        dashboard.update(index, { status: 'bulk-back' });
        log(`💱 CC low (${ccBalance.toFixed(2)}), bulk-back ${usdcxBalance.toFixed(2)} USDCX`);

        let stuckOrder = null;
        try { stuckOrder = await swapApi.getActiveOrder(session.swapToken, {}); } catch { /* none */ }

        if (stuckOrder?.orderId) {
            log(`🚫 Stuck: ${shortId(stuckOrder.orderId)} (${stuckOrder.status || '?'})`);
            const MAX_RETRIES = 60;
            for (let attempt = 1; ; attempt++) {
                dashboard.update(index, { status: `stuck #${attempt}` });
                log(`⏳ Waiting stuck order... (#${attempt})`);
                await sleep(30);
                await session.ensureFreshTokens(walletApi, swapApi, log);
                try {
                    const check = await swapApi.getActiveOrder(session.swapToken, {});
                    if (check?.orderId) {
                        const TERMINAL = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
                        if (TERMINAL.includes(check.status)) { log('🎉 Resolved'); break; }
                        continue;
                    }
                    log('🎉 Resolved'); break;
                } catch { log('🎉 Resolved'); break; }
            }

            try {
                const finalCheck = await swapApi.getActiveOrder(session.swapToken, {});
                const TERMINAL = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
                if (finalCheck?.orderId && !TERMINAL.includes(finalCheck.status)) {
                    log('❌ Stuck 2h. Support: ' + finalCheck.orderId);
                    return;
                }
            } catch { /* good */ }

            try {
                const { holdings: h } = await session.withRetry(
                    () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
                );
                usdcxBalance = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;
                ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || 0;
                dashboard.update(index, { cc: ccBalance, usdcx: usdcxBalance });
            } catch { /* ignore */ }
        }

        let bulkAttempt = 0;
        while (ccBalance < min_amount && usdcxBalance >= 1) {
            bulkAttempt++;
            await session.ensureFreshTokens(walletApi, swapApi, log);
            dashboard.update(index, { status: `bulk #${bulkAttempt}` });
            await sleep(15);

            const bulkResult = await executeSwap(ctx, {
                fromChain: pair_b.chain, fromAsset: pair_b.asset,
                toChain: pair_a.chain, toAsset: pair_a.asset,
                amount: usdcxBalance, fromLabel: pair_b.label, toLabel: pair_a.label,
                instrumentAdminId: getInstrumentAdminId(holdingsCache, pair_b.asset),
            }, { pollTimeoutMinutes: 10 });

            if (bulkResult) {
                dashboard.update(index, { swapsUtCC: (dashboard.accounts[index].swapsUtCC || 0) + 1, lastSwapDir: '↩' });
                log(`✅ Bulk: +${bulkResult.receiveAmount} CC`);
                await refreshAccountData(ctx);
                break;
            }

            log('⚠️ Bulk failed, retry 30s');
            await sleep(30);
            try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
            try {
                const { holdings: h } = await session.withRetry(
                    () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
                );
                ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || h?.['CC']?.balance || 0;
                usdcxBalance = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;
                dashboard.update(index, { cc: ccBalance, usdcx: usdcxBalance });
            } catch { /* cached */ }
        }
    }

    // Wait for enough CC
    while (ccBalance < min_amount) {
        if (usdcxBalance >= 1) {
            dashboard.update(index, { status: 'bulk-back' });
            log(`💱 CC (${ccBalance.toFixed(2)}) < ${min_amount}, bulk-back ${usdcxBalance.toFixed(2)} USDCX → CC`);
            await session.ensureFreshTokens(walletApi, swapApi, log);
            await sleep(15);
            const bulkResult = await executeSwap(ctx, {
                fromChain: pair_b.chain, fromAsset: pair_b.asset,
                toChain: pair_a.chain, toAsset: pair_a.asset,
                amount: usdcxBalance, fromLabel: pair_b.label, toLabel: pair_a.label,
                instrumentAdminId: getInstrumentAdminId(holdingsCache, pair_b.asset),
            }, { pollTimeoutMinutes: 10 });
            if (bulkResult) {
                dashboard.update(index, { swapsUtCC: (dashboard.accounts[index].swapsUtCC || 0) + 1, lastSwapDir: '↩' });
                log(`✅ Bulk: +${bulkResult.receiveAmount} CC`);
            }
        } else {
            dashboard.update(index, { status: `wait CC ${ccBalance.toFixed(1)}` });

            // Check if there's an active order we need to wait for
            const hadOrder = await resolveActiveOrder(ctx);
            if (hadOrder) {
                try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
                try {
                    const { holdings: h } = await session.withRetry(
                        () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
                    );
                    ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || h?.['CC']?.balance || 0;
                    usdcxBalance = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;
                    dashboard.update(index, { cc: ccBalance, usdcx: usdcxBalance });
                    log(`💰 CC: ${ccBalance.toFixed(2)} | USDCx: ${usdcxBalance.toFixed(4)}`);
                } catch { /* ignore */ }
                continue;
            }

            log(`⏳ CC (${ccBalance.toFixed(2)}) < ${min_amount} & USDCx (${usdcxBalance.toFixed(4)}) < 1 — polling...`);
            // Actively poll for orders + offers (6 × 10s = 60s)
            for (let wp = 0; wp < 6; wp++) {
                await sleep(10);
                await session.ensureFreshTokens(walletApi, swapApi, log);
                try {
                    const active = await swapApi.getActiveOrder(session.swapToken, {});
                    if (active?.orderId) {
                        const TS = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
                        if (!TS.includes(active.status)) {
                            log(`🔄 Found order ${shortId(active.orderId)} (${active.status})`);
                            await resolveActiveOrder(ctx);
                        }
                    }
                } catch { /* no active order */ }
                try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
                try {
                    const { holdings: h } = await session.withRetry(
                        () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
                    );
                    ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || h?.['CC']?.balance || 0;
                    usdcxBalance = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;
                    dashboard.update(index, { cc: ccBalance, usdcx: usdcxBalance });
                } catch { /* ignore */ }
                if (ccBalance >= min_amount || usdcxBalance >= 1) break;
            }
        }

        log('🔄 Rechecking balance...');
        await session.ensureFreshTokens(walletApi, swapApi, log);

        // Check for active orders before rechecking balance
        const hadOrderRecheck = await resolveActiveOrder(ctx);
        if (hadOrderRecheck) {
            try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
        }

        try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
        try {
            const { holdings: h } = await session.withRetry(
                () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
            );
            ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || h?.['CC']?.balance || 0;
            usdcxBalance = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;
            dashboard.update(index, { cc: ccBalance, usdcx: usdcxBalance });
            log(`💰 CC: ${ccBalance.toFixed(2)} | USDCx: ${usdcxBalance.toFixed(4)}`);
        } catch { /* cached */ }
    }

    const swapAmount = min_amount;
    log(`⚡ Starting ${rounds} rounds (CC → USDCX, amount: ${swapAmount})`);
    let totalSwaps = 0;
    let consecutiveFails = 0;

    for (let round = 1; round <= rounds; round++) {
        await session.ensureFreshTokens(walletApi, swapApi, log);

        if (round > 1) {
            try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
        }

        if (round > 1) {
            try {
                const { holdings: h } = await session.withRetry(
                    () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
                );
                ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || h?.['CC']?.balance || 0;
                dashboard.update(index, { cc: ccBalance });
            } catch { /* cached */ }
        }

        // Bulk-back if CC too low
        if (ccBalance < swapAmount) {
            dashboard.update(index, { status: 'bulk-back' });
            log(`💱 CC (${ccBalance.toFixed(2)}) < ${swapAmount}, need bulk-back`);

            // First: resolve any active order and accept offers
            await session.ensureFreshTokens(walletApi, swapApi, log);
            const hadOrder = await resolveActiveOrder(ctx);
            if (hadOrder) {
                try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
            } else {
                try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
            }

            // Refresh balance after resolving
            let usdcxBal = 0;
            const BALANCE_RETRIES = [3, 5, 8, 10, 15];
            for (let bi = 0; bi < BALANCE_RETRIES.length; bi++) {
                try {
                    const { holdings: h } = await session.withRetry(
                        () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
                    );
                    usdcxBal = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;
                    ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || 0;
                    dashboard.update(index, { cc: ccBalance, usdcx: usdcxBal });
                } catch { /* ignore */ }
                if (ccBalance >= swapAmount || usdcxBal >= 1) break;
                if (bi < BALANCE_RETRIES.length - 1) {
                    log(`⏳ CC: ${ccBalance.toFixed(2)} USDCx: ${usdcxBal.toFixed(4)} — waiting ${BALANCE_RETRIES[bi]}s...`);
                    await sleep(BALANCE_RETRIES[bi]);
                }
            }

            // If CC already enough after order resolve, skip bulk
            if (ccBalance >= swapAmount) continue;

            if (usdcxBal < 1) {
                log(`⏳ No funds to bulk-back (CC: ${ccBalance.toFixed(2)}, USDCx: ${usdcxBal.toFixed(4)}), polling for orders...`);
                // Actively poll for active orders + offers during wait (6 × 10s = 60s)
                for (let wp = 0; wp < 6; wp++) {
                    await sleep(10);
                    await session.ensureFreshTokens(walletApi, swapApi, log);
                    // Check active order
                    try {
                        const active = await swapApi.getActiveOrder(session.swapToken, {});
                        if (active?.orderId) {
                            const TERMINAL_S = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
                            if (!TERMINAL_S.includes(active.status)) {
                                log(`🔄 Found order ${shortId(active.orderId)} (${active.status}), resolving...`);
                                await resolveActiveOrder(ctx);
                            }
                        }
                    } catch { /* no active order */ }
                    // Accept offers
                    try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
                    // Recheck balance
                    try {
                        const { holdings: h } = await session.withRetry(
                            () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
                        );
                        usdcxBal = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;
                        ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || 0;
                        dashboard.update(index, { cc: ccBalance, usdcx: usdcxBal });
                    } catch { /* ignore */ }
                    if (ccBalance >= swapAmount || usdcxBal >= 1) {
                        log(`💰 Funds found! CC: ${ccBalance.toFixed(2)} USDCx: ${usdcxBal.toFixed(4)}`);
                        break;
                    }
                }
                if (ccBalance >= swapAmount) continue;
                if (usdcxBal >= 1) { /* fall through to bulk swap below */ }
                else { round--; continue; }
            }

            await sleep(10);
            const bulkResult = await executeSwap(ctx, {
                fromChain: pair_b.chain, fromAsset: pair_b.asset,
                toChain: pair_a.chain, toAsset: pair_a.asset,
                amount: usdcxBal, fromLabel: pair_b.label, toLabel: pair_a.label,
                instrumentAdminId: getInstrumentAdminId(holdingsCache, pair_b.asset),
            }, { pollTimeoutMinutes: 5 });

            if (bulkResult) {
                totalSwaps++;
                const utcc = (dashboard.accounts[index].swapsUtCC || 0) + 1;
                dashboard.update(index, { swapsUtCC: utcc, lastSwapDir: '↩' });
                log(`✅ Bulk: +${bulkResult.receiveAmount} CC`);
                try {
                    const { holdings: h } = await session.withRetry(
                        () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
                    );
                    ccBalance = h?.['Amulet']?.balance || h?.['CC (Amulet)']?.balance || 0;
                    dashboard.update(index, { cc: ccBalance });
                } catch { /* ignore */ }
                await refreshAccountData(ctx);
                if (ccBalance < swapAmount) { await sleep(30); round--; continue; }
            } else {
                try {
                    const active = await swapApi.getActiveOrder(session.swapToken, {});
                    if (active?.orderId) {
                        await swapApi.cancelOrder(session.swapToken, active.orderId);
                    }
                } catch (cleanErr) {
                    log(`❌ Cleanup: ${formatError(cleanErr)}`);
                }
                consecutiveFails++;
                await sleep(Math.min(15 * consecutiveFails, 120));
                round--;
                continue;
            }
        }

        // Main swap: CC → USDCX
        const ccU = (dashboard.accounts[index].swapsCCtoU || 0) + 1;
        dashboard.update(index, { swapsCCtoU: ccU, status: `CC→U R${round}/${rounds}`, totalSwaps: totalSwaps + 1 });
        log(`═══ R${round}/${rounds} CC→USDCX`);

        const result = await executeSwap(ctx, {
            fromChain: pair_a.chain, fromAsset: pair_a.asset,
            toChain: pair_b.chain, toAsset: pair_b.asset,
            amount: swapAmount, fromLabel: pair_a.label, toLabel: pair_b.label,
            instrumentAdminId: getInstrumentAdminId(holdingsCache, pair_a.asset),
        });

        if (!result) {
            dashboard.update(index, { swapsCCtoU: ccU - 1 });
            consecutiveFails++;
            const backoff = Math.min(10 * consecutiveFails, 120);
            log(`⚠️ Fail #${consecutiveFails}, retry ${backoff}s`);
            await sleep(backoff);
            // Check for active order after failure
            await resolveActiveOrder(ctx);
            try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
            round--;
            continue;
        }
        consecutiveFails = 0;
        totalSwaps++;
        ccBalance -= swapAmount;
        dashboard.update(index, { totalSwaps, lastSwapDir: '→', cc: ccBalance });
        log(`✅ +${result.receiveAmount} USDCX`);

        try { await refreshAccountData(ctx); } catch { /* ignore */ }

        if (round < rounds && delay_seconds > 0) await sleep(delay_seconds);
    }

    // Final bulk-back
    dashboard.update(index, { status: 'final bulk' });
    log('💱 Final bulk: converting all USDCX → CC');
    await session.ensureFreshTokens(walletApi, swapApi, log);
    try {
        const { holdings: h } = await session.withRetry(
            () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
        );
        let finalUsdcx = h?.['USDCx']?.balance || h?.['USDCX']?.balance || 0;

        if (finalUsdcx < 1 && totalSwaps > 0) {
            await sleep(10);
            const { holdings: h2 } = await session.withRetry(
                () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
            );
            finalUsdcx = h2?.['USDCx']?.balance || h2?.['USDCX']?.balance || 0;
        }

        if (finalUsdcx >= 1) {
            await sleep(10);
            const bulkResult = await executeSwap(ctx, {
                fromChain: pair_b.chain, fromAsset: pair_b.asset,
                toChain: pair_a.chain, toAsset: pair_a.asset,
                amount: finalUsdcx, fromLabel: pair_b.label, toLabel: pair_a.label,
                instrumentAdminId: getInstrumentAdminId(holdingsCache, pair_b.asset),
            }, { pollTimeoutMinutes: 10 });
            if (bulkResult) {
                totalSwaps++;
                dashboard.update(index, { swapsUtCC: (dashboard.accounts[index].swapsUtCC || 0) + 1, totalSwaps, lastSwapDir: '↩' });
                log(`✅ Final: +${bulkResult.receiveAmount} CC`);
            } else {
                log('⚠️ Final bulk stuck');
            }
        }
    } catch (err) {
        log(`⚠️ Final: ${formatError(err)}`);
    }

    await refreshAccountData(ctx);
    log(`🏁 Done! ${totalSwaps} swaps`);
    dashboard.update(index, { status: 'done', totalSwaps });
}

// ── Accept Pending Offers ────────────────────────────────────────────────

async function acceptPendingOffers(ctx) {
    const { session, walletApi, swapApi, log } = ctx;

    let offers = [];
    const OFFER_WAITS = [2, 3];
    for (let attempt = 1; attempt <= OFFER_WAITS.length; attempt++) {
        try {
            const result = await session.withRetry(
                () => walletApi.getOffers(session.walletToken), 'wallet', walletApi, swapApi, log
            );
            offers = result.offers || [];
            if (offers.length > 0) break;
        } catch { /* ignore */ }
        if (attempt < OFFER_WAITS.length) await sleep(OFFER_WAITS[attempt - 1]);
    }

    if (!offers.length) return;

    log(`📩 ${offers.length} offer(s)`);

    for (const offer of offers) {
        const contractId = offer.contract_id || offer.contractId;
        const commandId = offer.command_id || offer.commandId;
        const instrumentId = offer.instrument_id || offer.instrumentId || 'USDCx';
        const amount = offer.amount || '?';

        try {
            const preparedTxB64 = offer.prepared_tx_b64 || offer.preparedTxB64;
            const hashB64 = offer.hash_b64 || offer.hashB64;

            if (preparedTxB64 && hashB64) {
                const signature = signMessage(session.keyPair.privateKey, Buffer.from(hashB64, 'base64'));
                await session.withRetry(() => walletApi.executeTransaction(session.walletToken, {
                    commandId, preparedTxB64,
                    signatureB64: toBase64(signature),
                    hashingSchemeVersion: offer.hashing_scheme_version || 'HASHING_SCHEME_VERSION_V2',
                }), 'wallet', walletApi, swapApi, log);
                log(`✅ Accept ${amount} ${instrumentId}`);
            } else if (contractId) {
                let rawPrepare = null;
                for (const ep of ['/offer/accept/prepare', '/offers/accept/prepare', '/offers/accept']) {
                    try {
                        const authH = { ...BASE_HEADERS, Authorization: `Bearer ${session.walletToken}` };
                        rawPrepare = (await createAxiosInstance(null).post(`${BACKEND}${ep}`, {
                            contract_id: contractId, party_id: session.partyId
                        }, { headers: authH })).data;
                        break;
                    } catch (e) {
                        if (e.response?.status !== 404) continue;
                    }
                }

                if (rawPrepare) {
                    const pTx = rawPrepare.prepared_tx_b64 || rawPrepare.preparedTxB64;
                    const pH = rawPrepare.hash_b64 || rawPrepare.hashB64;
                    if (pTx && pH) {
                        const signature = signMessage(session.keyPair.privateKey, Buffer.from(pH, 'base64'));
                        await session.withRetry(() => walletApi.executeTransaction(session.walletToken, {
                            commandId: rawPrepare.command_id || rawPrepare.commandId,
                            preparedTxB64: pTx,
                            signatureB64: toBase64(signature),
                            hashingSchemeVersion: rawPrepare.hashing_scheme_version || rawPrepare.hashingSchemeVersion || 'HASHING_SCHEME_VERSION_V2',
                        }), 'wallet', walletApi, swapApi, log);
                        log(`✅ Accept ${amount} ${instrumentId}`);
                    }
                }
            }
        } catch (err) {
            log(`❌ Offer: ${formatError(err)}`);
        }
    }
}

// ── Execute Single Swap ──────────────────────────────────────────────────

async function executeSwap(ctx, { fromChain, fromAsset, toChain, toAsset, amount, fromLabel, toLabel, instrumentAdminId }, opts = {}) {
    const { session, walletApi, swapApi, log } = ctx;
    const { pollTimeoutMinutes } = opts;

    try {
        log(`📋 Getting quote ${amount} ${fromLabel} → ${toLabel}...`);
        const quote = await swapApi.getQuote(fromChain, fromAsset, toChain, toAsset, amount);
        log(`💱 Quote: ${quote.sendAmount} ${fromLabel} → ${quote.receiveAmount} ${toLabel} (rate: ${parseFloat(quote.rate).toFixed(6)})`);

        const orderId = generateOrderId();
        log(`📝 Creating order ${shortId(orderId)}...`);
        let order;
        try {
            order = await session.withRetry(
                () => swapApi.createOrder(session.swapToken, orderId, quote.quoteId, session.partyId), 'swap', walletApi, swapApi, log
            );
        } catch (createErr) {
            const errStatus = createErr.response?.status;
            const errDetail = String(createErr.response?.data?.detail || '');

            // Handle 422 "Account setup not complete"
            if (errStatus === 422 && errDetail.includes('Account setup not complete')) {
                const setupOk = await waitForAccountSetup(swapApi, session.swapToken, session.partyId, log);
                if (!setupOk) throw new Error('Account setup timed out');
                // Retry with fresh quote
                const newQuote = await swapApi.getQuote(fromChain, fromAsset, toChain, toAsset, amount);
                Object.assign(quote, newQuote);
                order = await swapApi.createOrder(session.swapToken, orderId, newQuote.quoteId, session.partyId);
            }
            // Handle 409 conflict (active order exists)
            else if (errStatus === 409) {
                const errData = createErr.response?.data;
                let staleId = errData?.message?.match(/ord_\w+/)?.[0]
                    || JSON.stringify(errData).match(/ord_\w+/)?.[0]
                    || null;
                if (!staleId) {
                    try {
                        const active = await swapApi.getActiveOrder(session.swapToken, {});
                        staleId = active?.orderId;
                    } catch { /* ignore */ }
                }
                if (!staleId) throw createErr;

                log(`⚠️ Active order ${shortId(staleId)}, resolving...`);

                let cancelled = false;
                try {
                    await swapApi.cancelOrder(session.swapToken, staleId);
                    cancelled = true;
                    log(`🚫 Cancelled ${shortId(staleId)}`);
                } catch { /* wait */ }

                if (!cancelled) {
                    const TERMINAL = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
                    let pollN = 0;
                    const conflictPollStart = Date.now();
                    const maxConflictPollMs = 10 * 60 * 1000; // 10 minutes max
                    while (true) {
                        if (Date.now() - conflictPollStart > maxConflictPollMs) {
                            log(`🔴 Conflict order poll timed out after 10m`);
                            break;
                        }
                        await sleep(10);
                        pollN++;
                        if (pollN % 6 === 0) await session.ensureFreshTokens(walletApi, swapApi, log);
                        try {
                            const check = await swapApi.getOrderStatus(session.swapToken, staleId);
                            log(`🔄 ${shortId(staleId)} → ${check.status}`);
                            if (TERMINAL.includes(check.status)) break;
                        } catch (pollErr) {
                            if (pollErr.response?.status === 401) {
                                await session.refreshSwapToken(swapApi, log);
                                continue;
                            }
                            break;
                        }
                    }
                }

                await acceptPendingOffers(ctx);
                await sleep(2);
                const newQuote = await swapApi.getQuote(fromChain, fromAsset, toChain, toAsset, amount);
                Object.assign(quote, newQuote);
                order = await swapApi.createOrder(session.swapToken, orderId, newQuote.quoteId, session.partyId);
            }
            // Handle generic 422 (not setup-related)
            else if (errStatus === 422) {
                log(`⚠️ [422] Server rejected, retrying with fresh quote...`);
                await sleep(5);
                const newQuote = await swapApi.getQuote(fromChain, fromAsset, toChain, toAsset, amount);
                Object.assign(quote, newQuote);
                order = await swapApi.createOrder(session.swapToken, orderId, newQuote.quoteId, session.partyId);
            } else {
                throw createErr;
            }
        }

        log(`✅ Order ${shortId(orderId)} created`);

        const instrumentId = ASSET_TO_INSTRUMENT[fromAsset] || fromAsset;
        log(`📦 Preparing transfer ${order.requiredAmount} ${instrumentId}...`);
        let rawPrepare = null;
        for (let retry = 0; retry < 3; retry++) {
            try {
                rawPrepare = await session.withRetry(() => walletApi.prepareTransfer(session.walletToken, {
                    instrumentAdminId: instrumentAdminId || '',
                    instrumentId,
                    receiverPartyId: order.deposit.address,
                    amount: order.requiredAmount,
                    reason: orderId,
                    appName: 'swap-v1',
                    metadata: {},
                }), 'wallet', walletApi, swapApi, log);
                break;
            } catch (prepErr) {
                const msg = prepErr.response?.data?.detail || prepErr.response?.data?.message || prepErr.message;
                const msgStr = typeof msg === 'object' ? JSON.stringify(msg) : String(msg);
                if (msgStr.includes('No holdings') && retry < 2) {
                    await sleep(15);
                    continue;
                }
                throw prepErr;
            }
        }

        const commandId = rawPrepare.command_id || rawPrepare.commandId;
        const preparedTxB64 = rawPrepare.prepared_tx_b64 || rawPrepare.preparedTxB64;
        const hashingSchemeVersion = rawPrepare.hashing_scheme_version || rawPrepare.hashingSchemeVersion || 'HASHING_SCHEME_VERSION_V2';
        const hashB64 = rawPrepare.hash_b64 || rawPrepare.hashB64;

        if (!preparedTxB64 || !hashB64) {
            log('❌ Missing prepared_tx_b64 or hash_b64');
            return false;
        }

        log('✍️ Signing & executing transfer...');
        const signature = signMessage(session.keyPair.privateKey, Buffer.from(hashB64, 'base64'));
        await session.withRetry(() => walletApi.executeTransaction(session.walletToken, {
            commandId, preparedTxB64,
            signatureB64: toBase64(signature),
            hashingSchemeVersion,
        }), 'wallet', walletApi, swapApi, log);

        // Poll transfer/status until confirmed (HAR flow)
        log('⏳ Waiting for deposit confirmation...');
        for (let ts = 0; ts < 20; ts++) {
            await sleep(3);
            try {
                const txStatus = await walletApi.getTransferStatus(session.walletToken, commandId);
                if (txStatus.status === 'success') {
                    log('✅ Deposit confirmed on-chain');
                    break;
                }
            } catch { /* continue polling */ }
        }

        log('📊 Polling order status...');

        await sleep(3);
        const finalStatus = await pollOrderStatus(ctx, orderId, pollTimeoutMinutes, toAsset);

        if (finalStatus === 'COMPLETED' || finalStatus === 'WALLET_CONFIRMED') {
            log('🎉 Swap completed!');
            if (finalStatus === 'WALLET_CONFIRMED') {
                for (let cooldown = 0; cooldown < 6; cooldown++) {
                    await sleep(5);
                    try {
                        const { status } = await swapApi.getOrderStatus(session.swapToken, orderId);
                        const TERMINAL = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
                        if (TERMINAL.includes(status)) break;
                    } catch { break; }
                }
            }
            await acceptPendingOffers(ctx);
            return { receiveAmount: quote.receiveAmount };
        } else if (finalStatus === 'TIMEOUT') {
            log(`⚠️ Timeout ${pollTimeoutMinutes}m`);
            try { await swapApi.cancelOrder(session.swapToken, orderId); } catch { /* ignore */ }
            return false;
        } else {
            log(`❌ Swap: ${finalStatus}`);
            return false;
        }

    } catch (err) {
        log(`❌ ${formatError(err)}`);
        return false;
    }
}

// ── Poll Order Status ────────────────────────────────────────────────────

async function pollOrderStatus(ctx, orderId, maxMinutes = 0, toAsset = null) {
    const { session, walletApi, swapApi, log } = ctx;
    const TERMINAL = ['COMPLETED', 'CANCELLED', 'REFUNDED', 'FAILED'];
    let lastStatus = '';
    let pollCount = 0;
    let stuckSince = 0;
    const ICONS = { COMPLETED: '✅', FAILED: '❌', CANCELLED: '🚫', FUNDED: '💰', EXECUTING: '⚙️', PROCESSING: '🔄', WITHDRAWING: '📤', AWAITING_DEPOSIT: '⏳' };
    const maxPolls = maxMinutes > 0 ? Math.ceil(maxMinutes * 60 / 5) : Infinity;

    let preSwapBalance = null;
    if (toAsset) {
        try {
            const { holdings = {} } = await session.withRetry(
                () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
            );
            const assetNames = toAsset === '0x0' ? ['Amulet', 'CC (Amulet)', 'CC'] : ['USDCx', 'USDCX'];
            for (const n of assetNames) {
                if (holdings[n]?.balance != null) { preSwapBalance = holdings[n].balance; break; }
            }
            preSwapBalance = preSwapBalance || 0;
        } catch { preSwapBalance = 0; }
    }

    async function walletSideCheck() {
        if (!toAsset) return false;
        try {
            const offerResult = await session.withRetry(
                () => walletApi.getOffers(session.walletToken), 'wallet', walletApi, swapApi, log
            );
            if ((offerResult.offers?.length || 0) > 0) {
                try { await acceptPendingOffers(ctx); } catch { /* ignore */ }
                return true;
            }

            const { holdings = {} } = await session.withRetry(
                () => walletApi.getBalance(session.walletToken), 'wallet', walletApi, swapApi, log
            );
            const assetNames = toAsset === '0x0' ? ['Amulet', 'CC (Amulet)', 'CC'] : ['USDCx', 'USDCX'];
            let currentBalance = 0;
            for (const n of assetNames) {
                if (holdings[n]?.balance != null) { currentBalance = holdings[n].balance; break; }
            }
            if (preSwapBalance != null && currentBalance > preSwapBalance + 0.01) return true;

            try {
                const historyData = await session.withRetry(
                    () => walletApi.getHistory(session.walletToken), 'wallet', walletApi, swapApi, log
                );
                const transfers = historyData.transfers || historyData.history || historyData || [];
                if (Array.isArray(transfers) && transfers.length > 0) {
                    const recent = transfers[0];
                    const isIncoming = recent.direction === 'INCOMING' || recent.type === 'RECEIVE'
                        || recent.receiver_party_id === session.partyId
                        || recent.receiverPartyId === session.partyId;
                    if (isIncoming) {
                        const transferAge = Date.now() - new Date(recent.created_at || recent.createdAt || recent.timestamp || 0).getTime();
                        if (transferAge < 5 * 60 * 1000) return true;
                    }
                }
            } catch { /* not critical */ }
        } catch { /* ignore */ }
        return false;
    }

    let consecutiveNetErrors = 0;
    const MAX_CONSECUTIVE_NET_ERRORS = 10;

    while (pollCount < maxPolls) {
        try {
            const { status } = await retryOnNetwork(
                () => swapApi.getOrderStatus(session.swapToken, orderId),
                { maxRetries: 3, baseDelay: 3, label: 'pollStatus', log }
            );
            consecutiveNetErrors = 0; // reset on success

            if (status !== lastStatus) {
                const icon = ICONS[status] || '⏳';
                log(`${icon} Status: ${status} (${pollCount * 5}s)`);
                lastStatus = status;
                stuckSince = pollCount;
            }

            if (status === 'CANCELLED' || status === 'FAILED') {
                if (await walletSideCheck()) return 'WALLET_CONFIRMED';
                return status;
            }
            if (TERMINAL.includes(status)) return status;

            const stuckDuration = pollCount - stuckSince;
            if (toAsset && stuckDuration >= 3 && stuckDuration % 2 === 0) {
                if (await walletSideCheck()) return 'WALLET_CONFIRMED';
            }
        } catch (err) {
            if (err.response?.status === 401) {
                await session.refreshSwapToken(swapApi, log);
                continue;
            }
            // Network error that survived retryOnNetwork retries
            consecutiveNetErrors++;
            log(`⚠️ Poll network error (${consecutiveNetErrors}/${MAX_CONSECUTIVE_NET_ERRORS}): ${formatError(err)}`);
            if (consecutiveNetErrors >= MAX_CONSECUTIVE_NET_ERRORS) {
                log(`❌ Too many consecutive network errors during polling, checking wallet side...`);
                if (await walletSideCheck()) return 'WALLET_CONFIRMED';
                throw err; // propagate to trigger runAccount restart
            }
            await sleep(10); // extra wait on network error
        }
        pollCount++;
        await sleep(5);
    }

    return 'TIMEOUT';
}

// ── Main Entry Point ─────────────────────────────────────────────────────

async function main() {
    const accounts = config.accounts || [];

    if (!accounts.length) {
        console.error(chalk.red('❌ No accounts configured in config.json'));
        process.exit(1);
    }

    process.stdout.write('\x1B[H\x1B[2J');
    console.log(chalk.cyan.bold(`  🤖 CANTOR8 MULTI-ACCOUNT BOT V2 — ${accounts.length} account(s)\n`));

    dashboard.init(accounts);
    dashboard.startAutoRefresh();

    const results = await Promise.allSettled(
        accounts.map((acc, i) => runAccount(acc, i))
    );

    dashboard.stop();

    const ok = results.filter(r => r.status === 'fulfilled').length;
    const fail = results.filter(r => r.status === 'rejected').length;
    console.log(chalk.bold.green(`\n  ✅ All done: ${ok} ok, ${fail} fail\n`));
}

main();

(function(global, factory) {
    'use strict';
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        global.CyberShield = factory();
    }
})(typeof window !== 'undefined' ? window : this, function() {
    'use strict';

    const DEFAULT_CONFIG = {
        xss: true,
        clickjacking: true,
        devtools: true,
        bot: true,
        csp: true,
        logging: true,

        onThreat: null,

        devtoolsAction: 'warn',
        devtoolsRedirectUrl: '/blocked',

        botAction: 'warn',

        botThreshold: 5,

        allowedOrigins: [],
    };

    const Logger = (() => {
        const events = [];

        function log(level, module, message, data = {}) {
            const entry = {
                id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2),
                timestamp: new Date().toISOString(),
                level,
                module,
                message,
                data,
                userAgent: navigator.userAgent,
                url: location.href,
            };
            events.push(entry);

            const style = level === 'CRITICAL' ? 'color:#ff2244;font-weight:bold' :
                level === 'WARN' ? 'color:#ffb300;font-weight:bold' :
                'color:#00cc33';
            console.log(`%c[CyberShield][${level}][${module}] ${message}`, style, data);

            return entry;
        }

        return {
            info: (mod, msg, data) => log('INFO', mod, msg, data),
            warn: (mod, msg, data) => log('WARN', mod, msg, data),
            critical: (mod, msg, data) => log('CRITICAL', mod, msg, data),
            getEvents: () => [...events],
            clear: () => events.splice(0),
        };
    })();

    const AntiXSS = (() => {

        const XSS_PATTERNS = [
            /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
            /javascript\s*:/gi,
            /on\w+\s*=\s*["']?[^"'>]*/gi,
            /data\s*:\s*text\/html/gi,
            /<\s*iframe[\s\S]*?>/gi,
            /<\s*object[\s\S]*?>/gi,
            /<\s*embed[\s\S]*?>/gi,
            /eval\s*\(/gi,
            /expression\s*\(/gi,
            /vbscript\s*:/gi,
            /document\s*\.\s*cookie/gi,
            /document\s*\.\s*write\s*\(/gi,
            /window\s*\.\s*location\s*=/gi,
            /innerHTML\s*=/gi,
            /outerHTML\s*=/gi,
            /\bexec\s*\(/gi,
            /%3Cscript/gi,
            /&#x3C;script/gi,
        ];

        /**
         * Sanitiza uma string removendo padrões XSS.
         * @param {string} input
         * @returns {string} string limpa
         */
        function sanitize(input) {
            if (typeof input !== 'string') return input;
            let clean = input;
            XSS_PATTERNS.forEach(pattern => {
                if (pattern.test(clean)) {
                    Logger.critical('AntiXSS', `Padrão XSS detectado: ${pattern}`, { input });
                    clean = clean.replace(pattern, '');
                }
            });
            return clean;
        }

        //@param { String }str
        //@param { string }


        function escapeHTML(str) {
            if (typeof str !== 'string') return str;
            const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;', '`': '&#x60;' };
            return str.replace(/[&<>"'`]/g, c => map[c]);
        }


        function watchInputs() {
            document.addEventListener('input', function(e) {
                const el = e.target;
                if (!el || !['INPUT', 'TEXTAREA'].includes(el.tagName)) return;
                if (el.type === 'password') return; // nunca tocar em senhas

                const val = el.value;
                XSS_PATTERNS.forEach(pattern => {
                    if (pattern.test(val)) {
                        Logger.critical('AntiXSS', 'Input XSS interceptado', { tag: el.tagName, id: el.id, name: el.name });
                        el.value = sanitize(val);
                    }
                });
            }, true);

            const _setAttribute = Element.prototype.setAttribute;
            Element.prototype.setAttribute = function(name, value) {
                if (typeof value === 'string') {
                    const lower = name.toLowerCase();
                    if (lower.startsWith('on') || /javascript:/i.test(value)) {
                        Logger.critical('AntiXSS', `setAttribute bloqueado: ${name}="${value}"`);
                        return;
                    }
                }
                return _setAttribute.call(this, name, value);
            };


            const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            if (descriptor && descriptor.set) {
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    set(value) {
                        XSS_PATTERNS.forEach(p => {
                            if (typeof value === 'string' && p.test(value)) {
                                Logger.critical('AntiXSS', 'innerHTML XSS interceptado', { snippet: String(value).slice(0, 100) });
                                value = sanitize(value);
                            }
                        });
                        descriptor.set.call(this, value);
                    },
                    get() { return descriptor.get.call(this); },
                    configurable: true,
                });
            }

            Logger.info('AntiXSS', 'Monitoramento de inputs e DOM ativo');
        }

        return { init: watchInputs, sanitize, escapeHTML };
    })();


    const AntiClickjacking = (() => {
        function init(allowedOrigins = []) {
            if (window.self !== window.top) {
                try {
                    const parentOrigin = document.referrer ?
                        new URL(document.referrer).origin :
                        null;

                    const allowed = allowedOrigins.some(o => parentOrigin && parentOrigin.includes(o));

                    if (!allowed) {
                        Logger.critical('AntiClickjacking', 'Página carregada em iFrame não autorizado', { parentOrigin });

                        document.documentElement.style.visibility = 'hidden';

                        try {
                            window.top.location = window.self.location;
                        } catch {
                            document.documentElement.innerHTML =
                                '<body style="background:#000;color:#f00;font-family:monospace;padding:2rem">' +
                                '<h1>⚠ Acesso Bloqueado</h1>' +
                                '<p>Esta página não pode ser carregada em um frame externo.</p>' +
                                '</body>';
                        }
                        return;
                    }
                } catch (err) {
                    Logger.warn('AntiClickjacking', 'Erro ao verificar origem do frame', { err: err.message });
                }
            }

            _setMetaTag('http-equiv', 'X-Frame-Options', 'DENY');

            Logger.info('AntiClickjacking', 'Proteção contra Clickjacking ativa');
        }

        function _setMetaTag(attr, name, content) {
            const existing = document.querySelector(`meta[${attr}="${name}"]`);
            if (!existing) {
                const meta = document.createElement('meta');
                meta.setAttribute(attr, name);
                meta.setAttribute('content', content);
                document.head.appendChild(meta);
            }
        }

        return { init };
    })();

    const AntiDevTools = (() => {
        let detected = false;
        let action = 'warn';
        let redirectUrl = '/blocked';
        const THRESHOLD = 160;

        function _handleDetection() {
            if (detected) return;
            detected = true;
            Logger.critical('AntiDevTools', 'DevTools detectado', {
                outerWidth: window.outerWidth,
                outerHeight: window.outerHeight,
                innerWidth: window.innerWidth,
                innerHeight: window.innerHeight,
            });

            if (action === 'redirect') {
                window.location.href = redirectUrl;
            } else if (action === 'blank') {
                document.documentElement.innerHTML = '';
            } else {
                _showWarning();
            }
        }

        function _showWarning() {
            if (document.getElementById('_cs_devtools_warn')) return;
            const el = document.createElement('div');
            el.id = '_cs_devtools_warn';
            el.style.cssText = [
                'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
                'background:#1a0000', 'color:#ff2244', 'font-family:monospace',
                'font-size:14px', 'padding:12px 20px', 'text-align:center',
                'border-bottom:2px solid #ff2244', 'letter-spacing:.05em',
            ].join(';');
            el.textContent = '⚠ Ferramentas de desenvolvedor detectadas. Esta sessão está sendo monitorada.';
            document.body.prepend(el);
        }

        function _checkSize() {
            const widthDiff = window.outerWidth - window.innerWidth;
            const heightDiff = window.outerHeight - window.innerHeight;
            if (widthDiff > THRESHOLD || heightDiff > THRESHOLD) {
                _handleDetection();
            } else if (detected) {
                detected = false;
                const warn = document.getElementById('_cs_devtools_warn');
                if (warn) warn.remove();
            }
        }

        function _debuggerCheck() {
            const start = performance.now();
            debugger;
            const elapsed = performance.now() - start;
            if (elapsed > 100) _handleDetection();
        }

        function _toStringCheck() {
            const div = document.createElement('div');
            let count = 0;
            Object.defineProperty(div, 'id', {
                get() { count++; return 'probe'; }
            });
            console.log('%c', div);
            if (count > 0) _handleDetection();
        }

        function init(cfg = {}) {
            action = cfg.devtoolsAction || 'warn';
            redirectUrl = cfg.devtoolsRedirectUrl || '/blocked';

            setInterval(_checkSize, 1000);
            window.addEventListener('resize', _checkSize);

            document.addEventListener('keydown', function(e) {
                const blocked = [
                    e.key === 'F12',
                    e.ctrlKey && e.shiftKey && ['I', 'J', 'C'].includes(e.key),
                    e.ctrlKey && e.key === 'U', // view-source
                    e.metaKey && e.altKey && e.key === 'I', // Mac DevTools
                ];
                if (blocked.some(Boolean)) {
                    e.preventDefault();
                    e.stopPropagation();
                    Logger.warn('AntiDevTools', `Atalho bloqueado: ${e.key}`, { ctrl: e.ctrlKey, shift: e.shiftKey });
                    _handleDetection();
                    return false;
                }
            }, true);

            document.addEventListener('contextmenu', function(e) {
                e.preventDefault();
                Logger.info('AntiDevTools', 'Menu de contexto bloqueado');
                return false;
            });

            ['log', 'warn', 'error', 'info', 'debug', 'table', 'dir'].forEach(method => {
                const _orig = console[method].bind(console);
                console[method] = function(...args) {
                    if (args[0] && typeof args[0] === 'string' && args[0].includes('[CyberShield]')) {
                        return _orig(...args);
                    }
                };
            });

            Logger.info('AntiDevTools', 'Proteção contra DevTools ativa');
        }

        return { init };
    })();

    const AntiBot = (() => {
        const state = {
            mouseEvents: 0,
            keyEvents: 0,
            touchEvents: 0,
            scrollEvents: 0,
            suspiciousScore: 0,
            firstInteraction: null,
            lastInteraction: null,
            movementPath: [],
            honeypotTriggered: false,
        };

        let cfg = {};
        let threshold = 5;

        const BOT_UA_PATTERNS = [
            /bot/i, /crawl/i, /spider/i, /scrape/i, /curl/i, /wget/i,
            /python-requests/i, /go-http/i, /java\//i, /httpclient/i,
            /axios/i, /node-fetch/i, /phantomjs/i, /selenium/i, /puppeteer/i,
            /playwright/i, /headless/i, /cypress/i,
        ];

        function _checkUserAgent() {
            const ua = navigator.userAgent;
            const isBot = BOT_UA_PATTERNS.some(p => p.test(ua));
            if (isBot) {
                Logger.critical('AntiBot', 'User-Agent de bot detectado', { ua });
                state.suspiciousScore += 10;
            }
        }

        function _checkWebDriver() {
            if (navigator.webdriver === true) {
                Logger.critical('AntiBot', 'navigator.webdriver detectado (Selenium/Playwright)');
                state.suspiciousScore += 10;
            }
        }

        function _checkHeadless() {

            const plugins = navigator.plugins.length;
            const languages = navigator.languages && navigator.languages.length;
            const noChrome = !window.chrome && navigator.userAgent.includes('Chrome');

            if (plugins === 0) {
                Logger.warn('AntiBot', 'Nenhum plugin detectado — possível headless');
                state.suspiciousScore += 3;
            }
            if (!languages) {
                Logger.warn('AntiBot', 'Nenhum idioma detectado — possível headless');
                state.suspiciousScore += 3;
            }
            if (noChrome) {
                Logger.warn('AntiBot', 'Chrome sem objeto window.chrome — possível headless');
                state.suspiciousScore += 3;
            }
        }

        function _checkTiming() {

            if (!state.firstInteraction) return;
            const elapsed = Date.now() - state.firstInteraction;
            const total = state.mouseEvents + state.keyEvents + state.touchEvents;

            if (total > 20 && elapsed < 500) {
                Logger.warn('AntiBot', 'Interações muito rápidas — possível bot', { total, elapsed });
                state.suspiciousScore += 5;
            }
        }

        function _checkLinearMovement() {

            const path = state.movementPath;
            if (path.length < 10) return;

            let linearCount = 0;
            for (let i = 2; i < path.length; i++) {
                const dx1 = path[i - 1].x - path[i - 2].x;
                const dy1 = path[i - 1].y - path[i - 2].y;
                const dx2 = path[i].x - path[i - 1].x;
                const dy2 = path[i].y - path[i - 1].y;
                if (dx1 === dx2 && dy1 === dy2) linearCount++;
            }

            if (linearCount / path.length > 0.8) {
                Logger.warn('AntiBot', 'Movimento do mouse perfeitamente linear', { linearCount });
                state.suspiciousScore += 4;
            }
        }

        function _injectHoneypot() {
            const form = document.querySelector('form');
            if (!form) return;

            const trap = document.createElement('input');
            trap.type = 'text';
            trap.name = 'website';
            trap.tabIndex = -1;
            trap.autocomplete = 'off';
            trap.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;pointer-events:none';
            trap.setAttribute('aria-hidden', 'true');

            form.appendChild(trap);

            form.addEventListener('submit', function() {
                if (trap.value !== '') {
                    state.honeypotTriggered = true;
                    state.suspiciousScore += 15;
                    Logger.critical('AntiBot', 'Honeypot ativado — bot preencheu campo oculto');
                }
            });

            Logger.info('AntiBot', 'Honeypot injetado no formulário');
        }

        function _evaluateThreat() {
            if (state.suspiciousScore >= threshold) {
                Logger.critical('AntiBot', `Score de suspeita atingiu limiar (${state.suspiciousScore}/${threshold})`, state);

                if (cfg.onThreat) cfg.onThreat({ module: 'AntiBot', score: state.suspiciousScore, state });

                if (cfg.botAction === 'redirect') {
                    window.location.href = cfg.devtoolsRedirectUrl || '/blocked';
                } else if (cfg.botAction === 'block') {
                    document.documentElement.innerHTML =
                        '<body style="background:#000;color:#f00;font-family:monospace;padding:2rem">' +
                        '<h1>⚠ Acesso Negado</h1><p>Comportamento automatizado detectado.</p>' +
                        '</body>';
                } else {
                    Logger.warn('AntiBot', 'Bot detectado — nenhuma ação bloqueadora configurada');
                }
            }
        }

        function init(config = {}) {
            cfg = config;
            threshold = config.botThreshold || 5;

            _checkUserAgent();
            _checkWebDriver();
            _checkHeadless();

            document.addEventListener('mousemove', function(e) {
                state.mouseEvents++;
                state.lastInteraction = Date.now();
                if (!state.firstInteraction) state.firstInteraction = Date.now();
                state.movementPath.push({ x: e.clientX, y: e.clientY });
                if (state.movementPath.length > 50) state.movementPath.shift();
                if (state.mouseEvents % 20 === 0) _checkLinearMovement();
            }, { passive: true });

            document.addEventListener('keydown', function() {
                state.keyEvents++;
                state.lastInteraction = Date.now();
                if (!state.firstInteraction) state.firstInteraction = Date.now();
                _checkTiming();
            }, { passive: true });

            document.addEventListener('touchstart', function() {
                state.touchEvents++;
                state.lastInteraction = Date.now();
            }, { passive: true });

            document.addEventListener('scroll', function() {
                state.scrollEvents++;
            }, { passive: true });

            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', _injectHoneypot);
            } else {
                _injectHoneypot();
            }

            setInterval(_evaluateThreat, 5000);

            Logger.info('AntiBot', 'Detecção de bots ativa', { threshold });
        }

        function getState() { return {...state }; }

        return { init, getState };
    })();


    const CSPRuntime = (() => {
        function init() {

            const cspContent = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline'", // ajuste conforme necessário
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
                "font-src 'self' https://fonts.gstatic.com",
                "img-src 'self' data: https:",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "form-action 'self'",
                "base-uri 'self'",
                "object-src 'none'",
            ].join('; ');

            const existing = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            if (!existing) {
                const meta = document.createElement('meta');
                meta.setAttribute('http-equiv', 'Content-Security-Policy');
                meta.setAttribute('content', cspContent);
                document.head.insertBefore(meta, document.head.firstChild);
                Logger.info('CSPRuntime', 'Meta CSP injetada no <head>');
            } else {
                Logger.info('CSPRuntime', 'Meta CSP já presente — não sobrescrita');
            }

            const observer = new MutationObserver(mutations => {
                mutations.forEach(mutation => {
                    mutation.addedNodes.forEach(node => {
                        if (node.tagName === 'SCRIPT') {
                            const src = node.src || '';
                            const inline = node.textContent || '';


                            if (src && !src.startsWith(location.origin) && !src.startsWith('https://fonts.googleapis.com')) {
                                Logger.critical('CSPRuntime', `Script externo bloqueado: ${src}`);
                                node.remove();
                                return;
                            }

                            const xssPatterns = [/eval\s*\(/, /document\.write/, /\.cookie/, /atob\s*\(/];
                            if (xssPatterns.some(p => p.test(inline))) {
                                Logger.critical('CSPRuntime', 'Script inline suspeito removido', { snippet: inline.slice(0, 80) });
                                node.remove();
                            }
                        }
                    });
                });
            });

            if (document.head) {
                observer.observe(document.documentElement, { childList: true, subtree: true });
            }
        }

        return { init };
    })();

    function init(userConfig = {}) {
        const config = Object.assign({}, DEFAULT_CONFIG, userConfig);

        Logger.info('Core', '⬡ CyberShield iniciando...', { version: '1.0.0', config });

        if (config.clickjacking) AntiClickjacking.init(config.allowedOrigins);
        if (config.xss) AntiXSS.init();
        if (config.csp) CSPRuntime.init();
        if (config.bot) AntiBot.init(config);
        if (config.devtools) AntiDevTools.init(config);

        Logger.info('Core', '✔ CyberShield ativo — todos os módulos carregados');

        return {
            getLogs: Logger.getEvents,
            clearLogs: Logger.clear,
            getBotState: AntiBot.getState,
            sanitize: AntiXSS.sanitize,
            escapeHTML: AntiXSS.escapeHTML,
        };
    }

    return { init, version: '1.0.0' };
});

(function autoInit() {
    const scripts = document.querySelectorAll('script[src*="cybershield"]');
    scripts.forEach(s => {
        if (s.hasAttribute('data-autoinit')) {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => CyberShield.init());
            } else {
                CyberShield.init();
            }
        }
    });
})();
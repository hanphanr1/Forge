/*
 * FORGE trust bypass for a locally repackaged, debuggable build.
 *
 * The app trusts system CAs only, so the user-installed capture CA is refused and PCAPdroid cannot
 * decrypt anything. This script hooks the Java TLS decision points to accept the chain as-is while a
 * capture runs. It proves nothing about the official build: it runs inside the re-signed repackage
 * that FORGE's apk-gadget produced, and it applies in-process only. Every hook sends a marker so the
 * run can show which ones actually attached.
 *
 * checkTrustedRecursive is deliberately not overridden: its callers use the return value as a typed
 * chain and replacing it breaks Conscrypt's own verification path.
 */
Java.perform(function () {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var Permissive = Java.registerClass({
        name: 'forge.PermissiveTrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function () { },
            checkServerTrusted: function () { },
            getAcceptedIssuers: function () { return []; }
        }
    });
    var managers = [Permissive.$new()];

    var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
                                        '[Ljavax.net.ssl.TrustManager;',
                                        'java.security.SecureRandom');
    init.implementation = function (keyManagers, trustManagers, secureRandom) {
        send('ssl-context-init-replaced');
        return init.call(this, keyManagers, managers, secureRandom);
    };

    function noop(name) {
        try {
            var pinner = Java.use('okhttp3.CertificatePinner');
            pinner[name].overloads.forEach(function (overload) {
                overload.implementation = function () { send('certificate-pinner-' + name); };
            });
        } catch (error) { }
    }
    noop('check$okhttp');
    noop('check');

    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.overloads.forEach(function (overload) {
            overload.implementation = function () {
                send('conscrypt-verify-chain');
                return arguments[0];
            };
        });
    } catch (error) { }
    try {
        var ConscryptEngine = Java.use('com.android.org.conscrypt.ConscryptEngineSocket');
        ConscryptEngine.verifyCertificateChain.overloads.forEach(function (overload) {
            overload.implementation = function () {
                send('conscrypt-engine-verify');
                return arguments[0];
            };
        });
    } catch (error) { }

    send('forge-trust-bypass-loaded');
});

// Universal Android TLS pinning bypass for the GreyNOC droid workbench.
// Loaded by `droid.py run` through the frida CLI (frida 17: the CLI bundles the Java bridge).
// Every hook is independent and wrapped in try/catch: a class absent from the app is skipped, never fatal.
// Covers the Java layer only. Native pinning (Flutter/Dart BoringSSL, Unreal/libcurl, Cronet built-in pins)
// needs a native hook or reFlutter; the run log says which hooks attached so a silent miss is visible.

'use strict';

function log(m) { console.log('[ssl-bypass] ' + m); }

Java.perform(function () {
  var hooked = [];
  function ok(name) { hooked.push(name); }

  // 1. A permissive TrustManager injected into every SSLContext.init
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustAll = Java.registerClass({
      name: 'gnoc.wb.TrustAll',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    init.implementation = function (km, tm, sr) {
      return init.call(this, km, Java.array('javax.net.ssl.TrustManager', [TrustAll.$new()]), sr);
    };
    ok('SSLContext.init');
  } catch (e) {}

  // 2. Conscrypt platform TrustManagerImpl (Android 7+): the pin check and the chain verification
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    try {
      TMI.checkTrustedRecursive.implementation = function () { return Java.use('java.util.ArrayList').$new(); };
      ok('TrustManagerImpl.checkTrustedRecursive');
    } catch (e) {}
    try {
      TMI.verifyChain.implementation = function (untrustedChain) { return untrustedChain; };
      ok('TrustManagerImpl.verifyChain');
    } catch (e) {}
  } catch (e) {}

  // 3. network_security_config <pin-set>
  try {
    var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
    NSTM.checkPins.implementation = function () {};
    ok('NetworkSecurityTrustManager.checkPins');
  } catch (e) {}

  // 4. OkHttp 3/4 CertificatePinner (every overload, plus the Kotlin internal name)
  ['okhttp3.CertificatePinner', 'com.android.okhttp.CertificatePinner', 'com.squareup.okhttp.CertificatePinner'].forEach(function (cn) {
    try {
      var CP = Java.use(cn);
      ['check', 'check$okhttp'].forEach(function (m) {
        try {
          CP[m].overloads.forEach(function (ov) { ov.implementation = function () {}; });
          ok(cn + '.' + m);
        } catch (e) {}
      });
    } catch (e) {}
  });

  // 5. Hostname verifiers
  try {
    var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
    HUC.setDefaultHostnameVerifier.implementation = function (v) {};
    HUC.setHostnameVerifier.implementation = function (v) {};
    HUC.setSSLSocketFactory.implementation = function (f) {};
    ok('HttpsURLConnection setters');
  } catch (e) {}
  try {
    var OkHV = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    OkHV.verify.overloads.forEach(function (ov) { ov.implementation = function () { return true; }; });
    ok('OkHostnameVerifier.verify');
  } catch (e) {}

  // 6. WebView: proceed on any TLS error
  try {
    var WVC = Java.use('android.webkit.WebViewClient');
    WVC.onReceivedSslError.implementation = function (view, handler, error) { handler.proceed(); };
    ok('WebViewClient.onReceivedSslError');
  } catch (e) {}

  // 7. TrustKit
  try {
    var TK = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
    TK.verify.overloads.forEach(function (ov) { ov.implementation = function () { return true; }; });
    ok('TrustKit.OkHostnameVerifier');
  } catch (e) {}
  try {
    var TKPTM = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
    TKPTM.checkServerTrusted.overloads.forEach(function (ov) { ov.implementation = function () {}; });
    ok('TrustKit.PinningTrustManager');
  } catch (e) {}

  // 8. Conscrypt socket-level chain verification
  ['com.android.org.conscrypt.OpenSSLSocketImpl', 'org.conscrypt.OpenSSLSocketImpl', 'org.conscrypt.ConscryptFileDescriptorSocket'].forEach(function (cn) {
    try {
      var S = Java.use(cn);
      S.verifyCertificateChain.overloads.forEach(function (ov) { ov.implementation = function () {}; });
      ok(cn + '.verifyCertificateChain');
    } catch (e) {}
  });

  // 9. Apache / legacy and common SDK pinners
  try {
    var AbsV = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
    AbsV.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function () {};
    ok('apache AbstractVerifier');
  } catch (e) {}
  try {
    var PTM = Java.use('appcelerator.https.PinningTrustManager');
    PTM.checkServerTrusted.implementation = function () {};
    ok('appcelerator PinningTrustManager');
  } catch (e) {}
  try {
    var CWV = Java.use('org.apache.cordova.CordovaWebViewClient');
    CWV.onReceivedSslError.implementation = function (v, h, e) { h.proceed(); };
    ok('CordovaWebViewClient');
  } catch (e) {}

  log('attached hooks (' + hooked.length + '): ' + hooked.join(', '));
});

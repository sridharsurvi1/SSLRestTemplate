package com.ivrus.ssl;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class DelegatingX509KeyManager implements X509KeyManager {

    private String alias;
    private X509KeyManager x509KeyManager;

    public DelegatingX509KeyManager(String alias, X509KeyManager mgr) {
        this.alias = alias;
        this.x509KeyManager = mgr;
    }

    @Override
    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
        return alias;
    }

    @Override
    public String[] getClientAliases(String s, Principal[] principals) {
        return x509KeyManager.getClientAliases(s, principals);
    }

    @Override
    public String[] getServerAliases(String s, Principal[] principals) {
        return x509KeyManager.getServerAliases(s, principals);
    }

    @Override
    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        return x509KeyManager.chooseServerAlias(s, principals, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String s) {
        return x509KeyManager.getCertificateChain(s);
    }

    @Override
    public PrivateKey getPrivateKey(String s) {
        return x509KeyManager.getPrivateKey(s);
    }
}

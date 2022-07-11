package com.ivrus.ssl;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.stream;

@Slf4j
public class SSLContextConfig {

    private static final String SECURE_SOCKET_PROTOCOL = "TLSv1.2";
    private static final String SUNX509 = "SunX509";
    private static final String KEYSTORE_TYPE = "jks";

    private String keystoreInternalCertAlias;
    private String keystoreString;
    private String keystorePassword;
    private String truststorePath;
    private boolean keystoreAsTruststore = false;

    public SSLContextConfig(String keystoreInternalCertAlias, String keystoreString, String keystorePassword, String truststorePath, boolean keystoreAsTruststore) {
        this.keystoreInternalCertAlias = keystoreInternalCertAlias;
        this.keystoreString = keystoreString;
        this.keystorePassword = keystorePassword;
        this.truststorePath = truststorePath;
        this.keystoreAsTruststore = keystoreAsTruststore;
    }

    /**
     * Creates SSLContext with Keystore containing client certs and truststore This
     * method uses Base64 encoded jks file which is stored in KEYSTORE Environment
     * variable and decodes it with KEYSTORE_PASSWORD Client cert is filtered with
     * SYNAPSE_SSL_KEYSTORE_CLIENT_ALIAS
     *
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws KeyManagementException
     */
    public SSLContext sslContext() throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
            IOException, UnrecoverableKeyException, KeyManagementException {
        log.info("Initializing SSLContext.");
        log.debug("SSLContextConfig KEYSTORE {}", keystoreString);
        log.debug("SSLContextConfig TRUSTSTORE {}", truststorePath);
        log.debug("SSLContextConfig SERVER_SSL_CLIENTALIAS {}", keystoreInternalCertAlias);

        KeyStore keyStore = getKeystore(keystoreString, keystorePassword);
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(SUNX509);
        keyManagerFactory.init(keyStore,
                new String(Base64.getDecoder().decode(keystorePassword.getBytes(UTF_8)), UTF_8).toCharArray());

        log.info("Keystore is initialized.");
        KeyManager[] keyManagers = chooseClientCert(keyManagerFactory.getKeyManagers(), this.keystoreInternalCertAlias);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(SUNX509);
        trustManagerFactory.init(this.keystoreAsTruststore ? keyStore : truststore());

        log.info("Initializing SSL Context");
        SSLContext sslContext = SSLContext.getInstance(SECURE_SOCKET_PROTOCOL);
        sslContext.init(keyManagers, trustManagerFactory.getTrustManagers(), null);
        log.info("SSL Context Initialized.");
        return sslContext;
    }

    private KeyStore truststore() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        log.info("Trying to retrieve truststore passphrase...");
        KeyStore truststore = null;
        if (truststorePath != null && !truststorePath.trim().isEmpty()) {
            truststore = createTrustStoreFromCerts(truststorePath);
        }
        KeyManagerFactory trustManagerFactory = KeyManagerFactory.getInstance(SUNX509);
        trustManagerFactory.init(truststore, null);
        log.info("Truststore is initialized.");
        return truststore;
    }

    private KeyManager[] chooseClientCert(KeyManager[] keyManagers, String certAlias) {
        log.info("Selecting client certificate for provided cert alias - [{}]", certAlias);
        return stream(keyManagers).filter(keyManager -> keyManager instanceof X509KeyManager)
                .map(aManager -> new DelegatingX509KeyManager(certAlias, (X509KeyManager) aManager))
                .toArray(DelegatingX509KeyManager[]::new);
    }

    private KeyStore getKeystore(@NonNull String keystoreString, @NonNull String keystorePassword)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        InputStream keystoreStream = new ByteArrayInputStream(Base64.getDecoder().decode(keystoreString));
        KeyStore jks = KeyStore.getInstance(KEYSTORE_TYPE);
        char[] password = new String(Base64.getDecoder().decode(keystorePassword.getBytes(UTF_8)), UTF_8).toCharArray();
        jks.load(keystoreStream, password);
        return jks;
    }

    public KeyStore createTrustStoreFromCerts(String locationOfCerts) {
        try {
            log.info("Initializing trustStore from path {}", locationOfCerts);
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(null, (char[]) null);
            try (FileInputStream fis = new FileInputStream(locationOfCerts)) {
                try (BufferedInputStream bis = new BufferedInputStream(fis)) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    Certificate cert = null;
                    while (bis.available() > 0) {
                        cert = cf.generateCertificate(bis);
                        ks.setCertificateEntry(String.valueOf(bis.available()), cert);
                    }
                    ks.setCertificateEntry(String.valueOf(bis.available()), cert);
                }
            }
            log.info("TrustStore initialized from path {}", locationOfCerts);
            return ks;
        } catch (Exception e) {
            log.error("Failed to initialize trustStore.", e);
            throw new IllegalStateException("Failed to initializing trustStore from path " + locationOfCerts);
        }
    }

}

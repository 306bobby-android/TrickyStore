package io.github.a13e300.tricky_store.keystore;

import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

public class Utils {
    private final static String TAG = "Utils";
    static X509Certificate toCertificate(byte[] bytes) {
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            Log.w(TAG, "Couldn't parse certificate in keystore", e);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Collection<X509Certificate> toCertificates(byte[] bytes) {
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (Collection<X509Certificate>) certFactory.generateCertificates(
                    new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            Log.w(TAG, "Couldn't parse certificates in keystore", e);
            return new ArrayList<>();
        }
    }

    public static Certificate[] getModifiedCertificateChain(KeyEntryResponse response) {
        if (response == null || response.metadata.certificate == null) return null;
        Certificate[] originalChain = getCertificateChain(response);
        return CertHack.hackCertificateChain(originalChain);
    }

    public static void putCertificateChain(KeyEntryResponse response, Certificate[] chain) throws Throwable {
        putCertificateChain(response.metadata, chain);
    }

    public static void putCertificateChain(KeyMetadata metadata, Certificate[] chain) throws Throwable {
        if (chain == null || chain.length == 0) return;
        metadata.certificate = chain[0].getEncoded();
        var output = new ByteArrayOutputStream();
        for (int i = 1; i < chain.length; i++) {
            output.write(chain[i].getEncoded());
        }
        metadata.certificateChain = output.toByteArray();
    }
}

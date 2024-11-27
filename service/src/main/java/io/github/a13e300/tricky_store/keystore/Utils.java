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
    private static final String CERT_TYPE = "X.509";

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

    public static Certificate[] getCertificateChain(KeyEntryResponse response) {
        if (response == null || response.metadata.certificate == null) return null;

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance(CERT_TYPE);
            ArrayList<Certificate> certs = new ArrayList<>();

            // Parse the primary certificate
            Certificate leaf = certFactory.generateCertificate(
                    new ByteArrayInputStream(response.metadata.certificate));
            certs.add(leaf);

            // Parse the remaining chain if available
            if (response.metadata.certificateChain != null) {
                certs.addAll(certFactory.generateCertificates(
                        new ByteArrayInputStream(response.metadata.certificateChain)));
            }

            return certs.toArray(new Certificate[0]);
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse certificate chain", e);
            return null;
        }
    }    

    public static Certificate[] getModifiedCertificateChain(KeyEntryResponse response) {
        if (response == null || response.metadata.certificate == null) return null;
        Certificate[] originalChain = getCertificateChain(response);
        return CertHack.hackCertificateChain(originalChain);
    }

    public static Certificate[] modifyVerifiedBootFields(Certificate[] caList) {
        if (caList == null || caList.length == 0) return caList;

        try {
            X509Certificate leaf = (X509Certificate) caList[0];
            X509CertificateHolder certHolder = new X509CertificateHolder(leaf.getEncoded());

            // Get the attestation extension OID
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
            Extension attestationExtension = certHolder.getExtension(oid);

            if (attestationExtension == null) {
                // No attestation extension, return unmodified chain
                return caList;
            }

            // Parse the attestation extension
            ASN1Sequence attestationData = ASN1Sequence.getInstance(attestationExtension.getParsedValue());
            ASN1Encodable[] fields = attestationData.toArray();

            // Modify only the TEE-enforced fields
            ASN1Sequence teeEnforced = ASN1Sequence.getInstance(fields[7]);
            ASN1EncodableVector modifiedTeeEnforced = new ASN1EncodableVector();

            for (ASN1Encodable item : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) item;

                if (taggedObject.getTagNo() == 704) {
                    // Replace verified boot fields
                    ASN1Sequence hackedRootOfTrust = new DERSequence(new ASN1Encodable[]{
                            new DEROctetString(UtilKt.getBootKey()), // Custom boot key
                            ASN1Boolean.TRUE,                       // Verified
                            new ASN1Enumerated(0),                  // Verified boot state
                            new DEROctetString(UtilKt.getBootHash()) // Custom boot hash
                    });
                    modifiedTeeEnforced.add(new DERTaggedObject(704, hackedRootOfTrust));
                } else {
                    // Retain all other fields
                    modifiedTeeEnforced.add(taggedObject);
                }
            }

            // Replace the TEE-enforced fields
            fields[7] = new DERSequence(modifiedTeeEnforced);
            ASN1Sequence modifiedAttestationData = new DERSequence(fields);

            // Build the modified extension
            Extension modifiedExtension = new Extension(
                    oid,
                    attestationExtension.isCritical(),
                    new DEROctetString(modifiedAttestationData)
            );

            // Replace the modified extension in the certificate
            X509CertificateHolder modifiedCertHolder = certHolder.replaceExtension(modifiedExtension);

            // Convert the modified holder back to X509Certificate
            X509Certificate modifiedLeaf = new JcaX509CertificateConverter().getCertificate(modifiedCertHolder);

            // Return the modified chain
            ArrayList<Certificate> modifiedChain = new ArrayList<>();
            modifiedChain.add(modifiedLeaf);
            modifiedChain.addAll(Arrays.asList(caList).subList(1, caList.length));

            return modifiedChain.toArray(new Certificate[0]);
        } catch (Exception e) {
            Logger.e("Error modifying verified boot fields", e);
            return caList;
        }
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

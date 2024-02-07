package id.idtrust.signing.model.signer;

import id.idtrust.signing.util.Description;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class KeySigner {

    PrivateKey pv;
    PublicKey pb;
    Certificate[] cert;
    Long pv_ID=null;
    Date expiredCert;
    static Description ds = new Description();

    private static final Logger logger = LogManager.getLogger("idtrust");

    public Date getExpiredCert() {
        return expiredCert;
    }

    public PrivateKey getPv() {
        return pv;
    }

    public PublicKey getPb() {
        return pb;
    }

    public Certificate[] getCert() {
        return cert;
    }

    public PrivateKey getPrivateKey(String base64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey hasil=null;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(base64));
//	    KeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.gdecode(base64));
        hasil = keyFactory.generatePrivate(privateKeySpec);
        return hasil;
    }

    public PublicKey getPublicKey(String base64) throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {

        PublicKey publicKey =
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(java.util.Base64.getDecoder().decode(base64)));

        return publicKey;
    }

    public Certificate[] getCert(String cert) throws CertificateException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bis=new ByteArrayInputStream(java.util.Base64.getDecoder().decode(cert));
        Certificate c = fact.generateCertificate(bis);
        Certificate[] lCert=new Certificate[1];
        lCert[0]=c;

        return lCert;
    }


    public Certificate[] getCert2(String[] cert) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");

        List<Certificate> certs = new ArrayList<Certificate>();

        //add user cacerts
        for(int i=0 ; i < cert.length ; i++)
        {
            ByteArrayInputStream bis = new ByteArrayInputStream(Base64.getDecoder().decode(cert[i]));
            Certificate c = fact.generateCertificate(bis);

            certs.add(c);
        }

//        //add rootca
//        InputStream inStream = new FileInputStream("cacerts");
//
//        KeyStore ks = KeyStore.getInstance("JKS");
//        ks.load(inStream, null);
//
//        Enumeration<String> e = ks.aliases();
//
//        while (e.hasMoreElements()) {
//            String alias = e.nextElement();
//            logger.debug("[" + ds.VERSION + "]-[SIGNING/INFO] : Add Root : " + alias);
//            Certificate certificate = ks.getCertificate(alias);
//
//            certs.add(certificate);
//        }

//        //add
//        InputStream inStreamB2 = new FileInputStream("test1.b2.crt");
//
//        KeyStore ksB2 = KeyStore.getInstance("JKS");
//        ksB2.load(inStreamB2, null);
//
//        Enumeration<String> eB2 = ks.aliases();
//
//        while (e.hasMoreElements()) {
//            String aliasB2 = eB2.nextElement();
//            logger.debug("[" + ds.VERSION + "]-[SIGNING/INFO] : Add Root : " + aliasB2);
//            Certificate certificateB2 = ks.getCertificate(aliasB2);
//
//            certs.add(certificateB2);
//        }

        return certs.toArray(new Certificate[0]);
    }
}

package id.idtrust.signing.core.certificate;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

public final class PKCS7Signer {

    private static final String PATH_TO_KEYSTORE = "idtrustdev.pfx";
    private static final String KEYSTORE_PASSWORD = "Trust@123";
    private static final String SIGNATUREALGO = "SHA256withECDSA";

    public PKCS7Signer() {
    }

    public KeyStore loadKeyStore() throws Exception {

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        InputStream is = PKCS7Signer.class.getClassLoader().getResourceAsStream(PATH_TO_KEYSTORE);
        keystore.load(is, KEYSTORE_PASSWORD.toCharArray());
        return keystore;
    }

    public CMSSignedDataGenerator setUpProvider(final KeyStore keystore) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        Enumeration aliases = keystore.aliases();
        String keyAlias = "";
        while (aliases.hasMoreElements()) {
            keyAlias = (String) aliases.nextElement();
        }

        System.out.println("key alias:"+keyAlias);

        Certificate[] certchain = (Certificate[]) keystore.getCertificateChain(keyAlias);

        final List<Certificate> certlist = new ArrayList<Certificate>();

        for (int i = 0, length = certchain == null ? 0 : certchain.length; i < length; i++) {
            certlist.add(certchain[i]);
        }

        Store certstore = new JcaCertStore(certlist);

        Certificate cert = keystore.getCertificate(keyAlias);

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATUREALGO).setProvider("BC").
                build((PrivateKey) (keystore.getKey(keyAlias, KEYSTORE_PASSWORD.toCharArray())));

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
                build()).build(signer, (X509Certificate) cert));

        generator.addCertificates(certstore);

        return generator;
    }

    public byte[] signPkcs7(final byte[] content, final CMSSignedDataGenerator generator) throws Exception {

        CMSTypedData cmsdata = new CMSProcessableByteArray(content);
        CMSSignedData signeddata = generator.generate(cmsdata, true);
        return signeddata.getEncoded();
    }

//    public static void main(String[] args) throws Exception {
//
//        PKCS7Signer signer = new PKCS7Signer();
//        KeyStore keyStore = signer.loadKeyStore();
//        CMSSignedDataGenerator signatureGenerator = signer.setUpProvider(keyStore);
//        String content = "{\"keyAlias\":\"RSA-USERDUMMY-0004\", \"data\":\"EJ84VaqJF7eQbVLcGYEBxqLgQvGaH7CtwDAfaxIGOFg=\"}";
//        byte[] signedBytes = signer.signPkcs7(content.getBytes("UTF-8"), signatureGenerator);
//        String datatosend=new String(Base64.encode(signedBytes));
//        JSONObject json =new JSONObject();
//        json.put("data",datatosend);
//        System.out.println(json.toString());
//    }
}
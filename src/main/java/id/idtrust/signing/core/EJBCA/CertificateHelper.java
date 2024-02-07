//package com.digisign.kms.core.EJBCA;
//
//import java.security.cert.Certificate;
//import java.security.cert.CertificateException;
//import java.util.Arrays;
//
//import com.digisign.kms.core.certificate.CertificateRequest;
//import com.digisign.kms.util.LogSystem;
//import org.cesecore.util.Base64;
//import org.springframework.beans.factory.annotation.Autowired;
//
//public class CertificateHelper {
//    @Autowired
//    static CertTools certTools;
//    public static final String RESPONSETYPE_CERTIFICATE = "CERTIFICATE";
//    public static final String RESPONSETYPE_PKCS7 = "PKCS7";
//    public static final String RESPONSETYPE_PKCS7WITHCHAIN = "PKCS7WITHCHAIN";
//    public static final int CERT_REQ_TYPE_PKCS10 = 0;
//    public static final int CERT_REQ_TYPE_CRMF = 1;
//    public static final int CERT_REQ_TYPE_SPKAC = 2;
//    public static final int CERT_REQ_TYPE_PUBLICKEY = 3;
//
//    public CertificateHelper() {
//    }
//
//    public static Certificate getCertificate(byte[] certificateData) throws CertificateException {
//        LogSystem.info("MASUK AWAL");
//        LogSystem.info("MASUK"+ Arrays.toString(Base64.decode(certificateData)));
//        Certificate retval = certTools.getCertfromByteArray(Base64.decode(certificateData), Certificate.class);
//        LogSystem.info("SELETAH MASUK AWAL");
//        return retval;
//    }
//
//    public static byte[] getPKCS7(byte[] pkcs7Data) {
//        return Base64.decode(pkcs7Data);
//    }
//}

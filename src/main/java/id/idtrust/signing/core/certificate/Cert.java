//package id.idtrust.signing.core.certificate;
//
//import id.idtrust.signing.util.Description;
//import org.springframework.beans.factory.annotation.Autowired;
//
//import java.security.KeyPairGenerator;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.cert.Certificate;
//import java.util.Date;
////import sun.security.x509.X500Name;
//
//public class Cert extends Description {
//
//    private boolean newCert=false;
//
//    private PublicKey publicKey = null;
//    private PrivateKey privateKey = null;
//    private KeyPairGenerator keyGen = null;
//    private java.security.cert.Certificate[] certChain = null;
//
//    private static String  dirCert="/opt/data-DS/ds-cert/";
//    private static String  dirUserCert="/opt/data-DS/ds-cert/user/";
//    private String dirUser=null;
//    private String keyName=null;
//    private String csrName=null;
//    private String crtName=null;
//    private String p12File=null;
//    private Long mitraID=null;
//    private String subjCSR="";
//    private String password="";
//    private String levelUser="";
//    private Long userid=null;
//    private String email;
//    private Date tsp;
//    private String org;
//    private boolean certificateRenewal=false;
//    Long private_key_id=null;
//    Certificate[] cert;
//
//    @Autowired
//    KeyRepository keyRepo;
//
//    @Autowired
//    SealCertRepository sealCertRepository;
//
//    public void setCertificateRenewal(boolean certificateRenewal) {
//        this.certificateRenewal = certificateRenewal;
//    }
//
//    public Cert(UserCertificate uc, Date tsp){
//        this.tsp=tsp;
//        String name=uc.getEmail();
//        dirUser=dirUserCert+uc.getIdUser().toString()+"/";
//        keyName=dirUser+name+".key.pem";
//        csrName=dirUser+name+".csr.pem";
//        crtName=dirUser+name+".cert";
//        p12File=dirUser+name+".p12";
//        userid=uc.getIdUser();
//        mitraID=uc.getMitraID();
//        org=uc.getOrganization();
//        levelUser=uc.getLevelCert();
//        if(uc.getMitraID()!=null)mitraID=uc.getMitraID();
//        System.out.println(org);
//    }
//
////    public boolean loadCert() {
////        boolean res = false;
////
////        try {
////            Optional<List<Key>> keyData;
////            if (levelUser.equals("C5")) {
////                keyData = sealCertRepository.checkACTSealCertificate(mitraID, levelUser);
////            } else {
////                keyData = keyRepo.checkACTSignatureCertificate(userid, levelUser);
////            }
////
////            LogSystem.info("load certificate" + tsp);
////
////            for (int i = 0; i < keyData.get().size(); i++) {
////                String base64 = keyData.get().get(i).getKey();
////                KeySigner signer = new KeySigner();
////
////                if (devel.equals("")) {
////                    base64 = KeyEncryption.decrypt(base64);
////                } else {
////                    base64 = AESEncryption.decrypt(base64);
////                }
////
////                if (keyData.get().get(i).getJenisKey().equals("PV")) {
////                    privateKey = signer.getPrivateKey(base64);
////                } else if (keyData.get().get(i).getJenisKey().equals("PB")) {
////                    publicKey = signer.getPublicKey(base64);
////                } else if (keyData.get().get(i).getJenisKey().equals("PR")) {
////                    cert = signer.getCert(base64);
////                }
////            }
////
////            if (cert != null) {
////                X509Certificate cr = (X509Certificate) cert[0];
////                String o = X500Name.asX500Name(cr.getSubjectX500Principal()).getOrganization();
////                System.out.println(o + " | " + org);
////                if (!o.equals(org)) {
////                    privateKey = null;
////                    cert = null;
////                    publicKey = null;
////                }
////            }
////
////            private_key_id = keyData.get().get(0).getPairKeyId();
////
////
////            CertificateRequest cReq = new CertificateRequest();
////            int tryCnt = 0;
////            java.security.cert.Certificate[] dC = null;
////            while (tryCnt < 3 && dC == null) {
////                dC = cReq.RequestedCAChain((X509Certificate) certChain[0], tsp);
////                if (dC.length <= 1) dC = null;
////                tryCnt++;
////            }
////            if (dC == null) return false;
////            certChain = dC;
////
////
////            res = true;
////
////
////        }catch (Exception e)
////        {
////            e.printStackTrace();
////            LogSystem.error("Error " + e.getMessage());
////        }
////        return res;
////    }
//
//}

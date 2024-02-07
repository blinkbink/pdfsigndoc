//package id.idtrust.signing.core.certificate;
//
//import com.ejbca.client.RevokeStatus;
//import org.cesecore.certificates.crl.RevokedCertInfo;
//import org.cesecore.util.CertTools;
//
//import java.io.IOException;
//import java.math.BigInteger;
//import java.security.*;
//import java.security.cert.CertificateException;
//
//public class CertificateStatus extends CertificateRequest {
//
//
//    public CertificateStatus() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
//            KeyManagementException, UnrecoverableKeyException, NoSuchProviderException {
//        super();
//        // TODO Auto-generated constructor stub
//    }
//
//
//    protected static final String[] REASON_TEXTS ={"NOT REVOKED",
//            "REV_UNSPECIFIED",			"REV_KEYCOMPROMISE",	"REV_CACOMPROMISE",
//            "REV_AFFILIATIONCHANGED",	"REV_SUPERSEDED",		"REV_CESSATIONOFOPERATION",
//            "REV_CERTIFICATEHOLD",		"REV_REMOVEFROMCRL",	"REV_PRIVILEGEWITHDRAWN",
//            "REV_AACOMPROMISE"};
//
//
//    public static final int NOT_REVOKED = RevokedCertInfo.NOT_REVOKED;
//    public static final int REVOCATION_REASON_UNSPECIFIED = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
//    public static final int REVOCATION_REASON_KEYCOMPROMISE = RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE;
//    public static final int REVOCATION_REASON_CACOMPROMISE = RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE;
//    public static final int REVOCATION_REASON_AFFILIATIONCHANGED = RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED;
//    public static final int REVOCATION_REASON_SUPERSEDED = RevokedCertInfo.REVOCATION_REASON_SUPERSEDED;
//    public static final int REVOCATION_REASON_CESSATIONOFOPERATION = RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION;
//    public static final int REVOCATION_REASON_CERTIFICATEHOLD = RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
//    public static final int REVOCATION_REASON_REMOVEFROMCRL = RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL;
//    public static final int REVOCATION_REASON_PRIVILEGESWITHDRAWN = RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN;
//    public static final int REVOCATION_REASON_AACOMPROMISE = RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE;
//
//    protected static final int[] REASON_VALUES = {NOT_REVOKED,REVOCATION_REASON_UNSPECIFIED,
//            REVOCATION_REASON_KEYCOMPROMISE, REVOCATION_REASON_CACOMPROMISE,
//            REVOCATION_REASON_AFFILIATIONCHANGED, REVOCATION_REASON_SUPERSEDED,
//            REVOCATION_REASON_CESSATIONOFOPERATION, REVOCATION_REASON_CERTIFICATEHOLD,
//            REVOCATION_REASON_REMOVEFROMCRL, REVOCATION_REASON_PRIVILEGESWITHDRAWN,
//            REVOCATION_REASON_AACOMPROMISE};
//    protected int getRevokeReason(String reason) throws Exception{
//        for(int i=0;i<REASON_TEXTS.length;i++){
//            if(REASON_TEXTS[i].equalsIgnoreCase(reason)){
//                return REASON_VALUES[i];
//            }
//        }
//
//        System.exit(-1); // NOPMD, this is not a JEE app
//        return 0;
//    }
//
//    protected static String getRevokeReason(int reason) {
//        for(int i=0;i<REASON_VALUES.length;i++){
//            if(REASON_VALUES[i]==reason){
//                return REASON_TEXTS[i];
//            }
//        }
//
//        System.exit(-1); // NOPMD, this is not a JEE app
//        return null;
//    }
//    public boolean checkStatus(String DN, BigInteger SN) throws Exception {
//
//        int trCnt=0;
//        while(trCnt<3) {
//            trCnt++;
//            try {
//
////				EjbcaWS send = service.getEjbcaWSPort();
//                String dn=CertTools.stringToBCDNString(DN);
//                System.out.println("DN :"+ dn);
//                System.out.println("DN :"+ SN.toString(16));
//
////	    		synchronized (service) {
//                setService();
//
//                RevokeStatus status=send.checkRevokationStatus(dn,SN.toString(16));
//                if(status == null){
//                    System.out.println("Error, No certificate found in database.");
//
//                }else{
//                    System.out.println("Revocation status :");
//                    System.out.println("  IssuerDN      : " + status.getIssuerDN());
//                    System.out.println("  CertificateSN : " + status.getCertificateSN());
//                    if(status.getReason() == RevokedCertInfo.NOT_REVOKED){
//                        System.out.println("  Status        : NOT REVOKED");
//                        return true;
//                    }else{
//                        System.out.println("  Status        : REVOKED");
//                        System.out.println("  Reason        : " + getRevokeReason(status.getReason()));
//                        System.out.println("  Date          : " + status.getRevocationDate().toString());
//                    }
//                }
////	    		}
//
//            } catch (Exception e) {
//                // TODO Auto-generated catch block
//                if(trCnt<3) {
//                    continue;
//                }
//                e.printStackTrace();
//                throw e;
//            }
//            break;
//        }
//        return false;
//    }
//
//    private static String getCertSN(String certsn) {
//        try{
//            new BigInteger(certsn,16);
//        }catch(NumberFormatException e){
//
//            System.exit(-1); // NOPMD, this is not a JEE app
//        }
//        return certsn;
//    }
//}

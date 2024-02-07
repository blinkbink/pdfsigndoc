package id.idtrust.signing.util;

public class Description {

//    public final static String devel = "";
//    public final static String EJBCA_PORT = "8443";
//    public final static String EJBCA_HOST = "ejbca";
//    public final static String EJBCA_TSP_PORT = "8080";
//    public final static String SIGN_SERVER = "signserver";
//
//    public final static String LINK_DOC_STATUS = "https://app.digisign.id/information.html?info=";
//    public final static String TSA = "http://"+SIGN_SERVER+":"+EJBCA_TSP_PORT+"/signserver/process?workerName=TimeStampSigner";
//    public final static String LOG_SYS_API="http://actlog:3001";
//
//    /*NASSERVER*/
//    public final static String FILESYS_SERVER_ADDRESS_NAS = "NASSERVER";
//    public final static String FILESYS_SERVER_ADDRESS_NAS2 = "NASSERVER2";
//    public final static String FILESYS_USERNAME_NAS = "fs_user";
//    public final static String FILESYS_PASSWORD_NAS = "BanBanZip";
////    public final static String FILESYS_USERNAME_NAS = "snids";
////    public final static String FILESYS_PASSWORD_NAS = "$0luS!n3tD$";
////    public final static String HSK_URL="https://hsk.digisign.id:7010";
//    public final static String HSK_URL="https://hsk.tandatanganku.com:7010";
//    public final static String JKS="/opt/jks/";
//    public final static boolean simMandatory=false;

    //Environment Variables
    public final String devel = System.getenv("DEVEL");
    public final String EJBCA_PORT = System.getenv("EJBCA_PORT");
    public final String EJBCA_HOST = System.getenv("EJBCA_HOST");

    public final String LINK_DOC_STATUS = System.getenv("LINK_DOC_STATUS");
    public final String TSA = System.getenv("TSA");
    public final String LOG_SYS_API=System.getenv("LOG_SYS_API");

    /*NASSERVER*/
    public final String FILESYS_SERVER_ADDRESS_NAS = System.getenv("FILESYS_SERVER_ADDRESS_NAS");
    public final String FILESYS_SERVER_ADDRESS_NAS2 = System.getenv("FILESYS_SERVER_ADDRESS_NAS2");
    public final String FILESYS_USERNAME_NAS = System.getenv("FILESYS_USERNAME_NAS");
    public final String FILESYS_PASSWORD_NAS = System.getenv("FILESYS_PASSWORD_NAS");

    public final String DEBUG = System.getenv("DEBUG");
    public final String TSA_URL = System.getenv("TSA_URL");
    public final String EXTERNAL_SIGNING_URL = System.getenv("EXTERNAL_SIGNING_URL");
    public final String EXTERNAL_SIGNING_PORT = System.getenv("EXTERNAL_SIGNING_PORT");

    public final String HSK_URL=System.getenv("HSK_URL");
    public final String HSK_SIM_URL=System.getenv("HSK_SIM_URL");
    public final String JKS=System.getenv("JKS");
    public final boolean simMandatory=Boolean.parseBoolean(System.getenv("SIM_MANDATORY"));
//    public final boolean notification=Boolean.parseBoolean(System.getenv("ERROR_NOTIFICATION"));
    public final boolean notification=false;
    public final String VERSION="1.0.0";
}
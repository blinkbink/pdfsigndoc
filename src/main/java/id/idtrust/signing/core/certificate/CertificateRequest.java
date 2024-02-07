//package id.idtrust.signing.core.certificate;
//
//import id.idtrust.signing.util.Description;
//import com.ejbca.client.Certificate;
//import com.ejbca.client.*;
////import com.sun.xml.internal.ws.developer.JAXWSProperties;
//import id.idtrust.signing.util.LogSystem;
//import org.apache.commons.lang.exception.ExceptionUtils;
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.util.encoders.Base64;
//import org.cesecore.certificates.crl.RevokedCertInfo;
//import org.cesecore.certificates.util.AlgorithmConstants;
//import org.ejbca.core.protocol.ws.common.CertificateHelper;
//import org.springframework.stereotype.Component;
//import sun.security.x509.X500Name;
//
//import javax.net.ssl.*;
//import javax.xml.namespace.QName;
//import javax.xml.ws.BindingProvider;
//import javax.xml.ws.Service;
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.IOException;
//import java.net.URL;
//import java.security.KeyStore;
//import java.security.*;
//import java.security.cert.CertificateException;
//import java.security.cert.CertificateParsingException;
//import java.security.cert.X509Certificate;
//import java.util.Date;
//import java.util.List;
//import java.util.Objects;
//
//@Component
////public class CertificateRequest extends Description {
////
////    private final static Logger LOGGER = LogManager.getLogger(CertificateRequest.class);
////
////    protected String subjDN;
////    protected String email;
////    static String data1 = "OK";
////    protected static Service service;
////    protected static QName qname;
////    protected EjbcaWS send;
////
////    /**
////     * penamaan ca
////     **/
////    final int CertC3 = 0;
////    final int CertC4 = 1;
////    final int CertSeal = 2;
////    final String caNameProd[] = {"Digisign-CA", "Digisign-CA", "Digisign-CA"};
////    final String caNameDevel[] = {"DigisignID.Dev.CA.Level3", "DigisignID.Dev.CA.Level4", "DigisignID.Dev.CA.LevelSeal"};
////
////    final String caNameProdv1 = "Digisign-CA";
////    final String caNameDevelv1 = "Development Digisign";
////
////    static List<Certificate> resultCA_v1 = null;
////    static List<Certificate> resultCA = null;
////    static List<Certificate> resultCA_C3 = null;
////    static List<Certificate> resultCA_C5 = null;
////    /**
////     * end
////     **/
////
////
////    static List<Certificate> resultTransCA = null;
////
////    public void setService() throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException {
//////		final Provider tlsProvider = new TLSProvider();
//////        Security.addProvider(tlsProvider);
////
////        SSLSocketFactory sc;
////        Security.addProvider(new BouncyCastleProvider());
////
////        sc = setSSL();
////
////        synchronized (data1) {
////            if (service == null) {
////                qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
////
////                service = Service.create(new URL("https://" + EJBCA_HOST + ":" + EJBCA_PORT + "/ejbca/ejbcaws/ejbcaws?wsdl"), qname);
////            }
////
////        }
////
////
////        send = service.getPort(EjbcaWS.class);
////
////        ((BindingProvider) send).getRequestContext().put("com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory", sc);
////
////    }
////
////    public CertificateRequest(String DN, String email) throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
////        subjDN = DN;
////        this.email = email;
////
////
////    }
////
////    public CertificateRequest() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException, NoSuchProviderException {
////
////
////    }
////
////    protected SSLSocketFactory setSSL() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException, NoSuchProviderException {
////
//////		System.setProperty ("javax.net.ssl.trustStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jkstruststore.jks");
//////		System.setProperty ("javax.net.ssl.trustStorePassword", "spinku12345");
//////		System.setProperty ("javax.net.ssl.keyStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jksadmin.jks");
//////		System.setProperty ("javax.net.ssl.keyStorePassword", "spinku12345");
//////	      System.setProperty("javax.net.ssl.keyStoreType", "JKS");
////
//////	        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true"); // <-- I still have to set this to true, otherwise a ws call will result in 'SocketException: Unexpected end of file from server'. One should try to avoid setting it to true.
////        //I also had to restart JBoss each time I changed the setting. We accept the security risk although I am still looking for answers why the EOF exception occurs.
////
////        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
////            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
////                return null;
////            }
////
////            public void checkClientTrusted(X509Certificate[] certs, String authType) {
////            }
////
////            public void checkServerTrusted(X509Certificate[] certs, String authType) {
////            }
////
////        }};
////
////        KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
////        FileInputStream instream = new FileInputStream(new File(Description.JKS+"admin.jks"));
//////	        FileInputStream instream = new FileInputStream(new File("F:\\DigisignFile\\admin.jks"));
////
////        if (Objects.equals(devel, "devel")) {
////                LogSystem.info("serverKMS.jks load jks");
////                instream = new FileInputStream(new File(Description.JKS+"serverKMS.jks"));
////                LogSystem.info("SUKSES serverKMS.jks load jks");
////        }
////
////        try {
////            keyStore.load(instream, "spinku12345".toCharArray());
////        } finally {
////            instream.close();
////        }
////        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
////        kmf.init(keyStore, "spinku12345".toCharArray());
////
//////			FileInputStream myKeys = new FileInputStream("F:\\\\DigisignFile\\truststore.jks");
////        LogSystem.info("trusstore.jks load jks");
////        FileInputStream myKeys = new FileInputStream(Description.JKS+"truststore.jks");
////        LogSystem.info("finish trusstore.jks load jks");
////
////        if (Objects.equals(devel, "devel")) {
////            LogSystem.info("trusstore.jks load jks devel");
////            myKeys = new FileInputStream(new File(Description.JKS+"truststore-devel.jks"));
////            LogSystem.info("finish trusstore.jks load jks devel");
////        }
////
////        // Do the same with your trust store this time
////        // Adapt how you load the keystore to your needs
////        KeyStore myTrustStore = KeyStore.getInstance("JKS", "SUN");
////        myTrustStore.load(myKeys, "spinku12345".toCharArray());
////
////        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
////
////        tmf.init(myTrustStore);
////
////        // Trust own CA and all self-signed certs
//////	        SSLContext sslcontext = SSLContexts.custom()
//////	            .loadKeyMaterial(keyStore, "spinku12345".toCharArray())
//////	            //.loadTrustMaterial(trustStore, new TrustSelfSignedStrategy()) //custom trust store
//////	            .build();
////        SSLContext sslcontext = SSLContext.getInstance("TLS");
////        sslcontext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
////
////        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
////                new javax.net.ssl.HostnameVerifier() {
////
////                    public boolean verify(String hostname,
////                                          javax.net.ssl.SSLSession sslSession) {
////                        return true;
////                    }
////                });
////        HttpsURLConnection.setDefaultSSLSocketFactory(sslcontext.getSocketFactory());
////        return sslcontext.getSocketFactory();
////    }
////
////    public X509Certificate RequestedCertificate33(String pkcs10, String levelCert, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
////
////
////        setService();
////
////        try {
////
////            UserDataVOWS userdata = new UserDataVOWS();
////            userdata.setCaName("Digisign-CA");
////            if (Objects.equals(devel, "devel")) {
////               userdata.setCaName("Development Digisign");
////
////            }
////            userdata.setUsername(email);
////            userdata.setEndEntityProfileName("UserApp");
////            if (levelCert.equals("C4")) {
////                userdata.setPassword("ejb" + email.substring(0, 5));
////                userdata.setCertificateProfileName("UserApp");
////                userdata.setEmail(email);
////            } else if (levelCert.equals("C3") || levelCert.equals("C2")) {
////                userdata.setPassword("ejb" + email.substring(0, 5));
////                userdata.setCertificateProfileName("UserApp" + levelCert);
////                userdata.setEmail(email);
////            } else if (levelCert.equals("C5")) {
////                if (email.length() < 8) userdata.setPassword("ejb" + email);
////                else userdata.setPassword("ejb" + email.substring(email.length() - 5));
////                userdata.setCertificateProfileName("UserApp" + levelCert);
////                userdata.setEndEntityProfileName("SealProfile");
////
////            }
////            userdata.setSubjectDN(subjDN);
////
////            LOGGER.info(LogSystem.getLog("profile cert : " + userdata.getCertificateProfileName(), tsp, "LOG"));
////
////            CertificateResponse cr = send.certificateRequest(userdata, pkcs10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
////
////            X509Certificate cert1 = (X509Certificate) CertificateHelper.getCertificate(cr.getData());
////
////            return cert1;
////
////        } catch (AuthorizationDeniedException_Exception e) {
////            // TODO Auto-generated catch block
//////				 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////            e.printStackTrace();
////        } catch (EjbcaException_Exception e) {
////            // TODO Auto-generated catch block
//////				 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (ApprovalException_Exception e) {
////            // TODO Auto-generated catch block
//////				 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (NotFoundException_Exception e) {
////            // TODO Auto-generated catch block
//////				 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
////            // TODO Auto-generated catch block
//////				 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (WaitingForApprovalException_Exception e) {
////            // TODO Auto-generated catch block
//////				 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }
////
////        return null;
////
////    }
////
////    public X509Certificate RequestedCertificate(String pkcs10, String levelCert, String sim, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CADoesntExistsException_Exception {
////
////
////        setService();
////
////        try {
////
////            UserDataVOWS userdata = new UserDataVOWS();
////            String ca[] = caNameProd;
////
////            if (devel.equals("devel")) ca = caNameDevel;
////
////
////            userdata.setUsername(email);
////            userdata.setEndEntityProfileName("UserApp");
////            userdata.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
////            if (levelCert.equals("C4")) {
////                userdata.setPassword("ejb" + email.substring(0, 5));
////                userdata.setCertificateProfileName("UserAppC4V.2");
////                userdata.setEmail(email);
////                userdata.setCaName(ca[CertC4]);
////
////                if (simMandatory) {
////                    userdata.setSubjectAltName("subjectIdentificationMethod=" + sim);
////                }
////            } else if (levelCert.equals("C3")) {
////                userdata.setPassword("ejb" + email.substring(0, 5));
////                userdata.setCertificateProfileName("UserAppC3V.2");
////                userdata.setEmail(email);
////                userdata.setCaName(ca[CertC3]);
////                if (simMandatory) {
////                    userdata.setSubjectAltName("subjectIdentificationMethod=" + sim);
////                }
////            } else if (levelCert.equals("C5")) {
////                if (email.length() < 8) userdata.setPassword("ejb" + email);
////                else userdata.setPassword("ejb" + email.substring(email.length() - 5));
////                userdata.setCertificateProfileName("UserAppSealV.2");
////                userdata.setEndEntityProfileName("SealProfile");
////                userdata.setCaName(ca[CertSeal]);
////
////            } else {
////                return null;
////            }
////            userdata.setSubjectDN(subjDN);
////            send.editUser(userdata);
//////	         LOGGER.info(LogSystem.getLog( "profile cert : "+userdata.getCertificateProfileName(), tsp, "LOG"));
////
////            CertificateResponse cr = send.certificateRequest(userdata, pkcs10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
////
////            X509Certificate cert1 = (X509Certificate) CertificateHelper.getCertificate(cr.getData());
////
////            return cert1;
////
////        } catch (AuthorizationDeniedException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////            e.printStackTrace();
////        } catch (EjbcaException_Exception | NotFoundException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (ApprovalException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (WaitingForApprovalException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }catch (Exception e)
////        {
////            e.printStackTrace();
////        }
////
////
////        return null;
////
////    }
////
////    public byte[] RequestedTransactionCertificate(String pkcs10, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
////
////
////        setService();
////
////        try {
////
////            UserDataVOWS userdata = new UserDataVOWS();
////            userdata.setCaName("Digisign-CA");
////
////            if (devel.equals("devel")) userdata.setCaName("Development Digisign - TR1");
////
////            userdata.setUsername(email);
////            userdata.setEndEntityProfileName("TRUserApp");
////            userdata.setPassword("ejb" + email.substring(0, 5));
////            userdata.setCertificateProfileName("TRUserApp");
////            userdata.setEmail(email);
////            userdata.setSubjectDN(subjDN);
////
////            LOGGER.info(LogSystem.getLog("profile cert : " + userdata.getCertificateProfileName(), tsp, "LOG"));
////
////            CertificateResponse cr = send.certificateRequest(userdata, pkcs10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
////
////
////            return cr.getData();
////
////        } catch (AuthorizationDeniedException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////            e.printStackTrace();
////        } catch (EjbcaException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (ApprovalException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (NotFoundException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (WaitingForApprovalException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }
////
////        return null;
////
////    }
////
////    public byte[] RequestP12(String levelCert, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
////
////
////        setService();
////
////        try {
////
//////			UserDataVOWS userdata = new UserDataVOWS();
//////			userdata.setCaName("Digisign-CA");
//////			if(devel!=null) {
//////				if(devel.equals("devel"))userdata.setCaName("Development Digisign");
//////
//////			}
////            UserDataVOWS userdata = new UserDataVOWS();
////            String ca[] = caNameProd;
////
////            if (devel.equals("devel")) ca = caNameDevel;
////
////            userdata.setUsername(email);
////            userdata.setEndEntityProfileName("UserApp");
////            if (levelCert.equals("C4")) {
////                userdata.setPassword("ejb" + email.substring(0, 5));
//////				userdata.setCertificateProfileName("UserApp");
////                userdata.setCertificateProfileName("UserAppC4V.2");
////                userdata.setEmail(email);
////                userdata.setCaName(ca[CertC4]);
////            } else if (levelCert.equals("C3")) {
////                userdata.setPassword("ejb" + email.substring(0, 5));
//////				userdata.setCertificateProfileName("UserApp"+levelCert);
////                userdata.setCertificateProfileName("UserAppC3V.2");
////                userdata.setEmail(email);
////                userdata.setCaName(ca[CertC3]);
////
////            } else if (levelCert.equals("C5")) {
////                if (email.length() < 8) userdata.setPassword("ejb" + email);
////                else userdata.setPassword("ejb" + email.substring(email.length() - 5));
//////				userdata.setCertificateProfileName("UserApp"+levelCert);
////                userdata.setCertificateProfileName("UserAppSealV.2");
////                userdata.setEndEntityProfileName("SealProfile");
////                userdata.setCaName(ca[CertSeal]);
////            }
////            userdata.setSubjectDN(subjDN);
////
////            send.editUser(userdata);
////            LOGGER.info(LogSystem.getLog("profile cert : " + userdata.getCertificateProfileName(), tsp, "LOG"));
////            com.ejbca.client.KeyStore kyStore = send.pkcs12Req(email, userdata.getPassword(), null, "2048", AlgorithmConstants.KEYALGORITHM_RSA);
//////			CertificateResponse cr = send.certificateRequest(userdata, pkcs10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
////
//////	        X509Certi?ficate cert1 = (X509Certificate) CertificateHelper.getCertificate(cr.getData());
////
////            return kyStore.getKeystoreData();
////
////        } catch (AuthorizationDeniedException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////            e.printStackTrace();
////        } catch (EjbcaException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (ApprovalException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (NotFoundException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (WaitingForApprovalException_Exception e) {
////            // TODO Auto-generated catch block
//////			 MyLogger.setError(this.getClass(), e);
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (CADoesntExistsException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }
////        catch(Exception e)
////        {
////            e.printStackTrace();
////
////        }
////        return null;
////
////    }
////
////    public boolean revoke(String emailToRevoke, Date tsp) throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException {
//////String issuerDN, String serialToRevoke, String revokeDN,
////        //EjbcaWSService es = new EjbcaWSService();
//////		  CryptoProviderTools.installBCProvider();
//////		Security.addProvider(new BouncyCastleProvider());
////
//////		System.setProperty ("javax.net.ssl.trustStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jkstruststore.jks");
//////        System.setProperty ("javax.net.ssl.trustStorePassword", "spinku12345");
//////        System.setProperty ("javax.net.ssl.keyStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jksadmin.jks");
//////        System.setProperty ("javax.net.ssl.keyStorePassword", "spinku12345");
//////        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
////
////        //System.setProperty("javax.net.ssl.trustStoreType","pkcs12");
////        setService();
////        boolean res = false;
////        try {
////
////            UserMatch usermatch = new UserMatch();
////            usermatch.setMatchwith(org.ejbca.core.protocol.ws.objects.UserMatch.MATCH_WITH_USERNAME);
////            usermatch.setMatchtype(org.ejbca.core.protocol.ws.objects.UserMatch.MATCH_TYPE_EQUALS);
////            usermatch.setMatchvalue(emailToRevoke);
////            List<UserDataVOWS> result = send.findUser(usermatch);
////            LOGGER.info(LogSystem.getLog("REQ REVOKE: " + emailToRevoke, tsp, "LOG"));
//////				send.revokeCert(issuerDN, serialToRevoke, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION);
////            if (result.size() > 0) {
////                send.revokeUser(emailToRevoke, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, true);
////                Date date = new Date();
//////					LogSystem.info(date+"Certificate "+serialToRevoke+" ["+revokeDN+"] has been revoked");
////                LOGGER.info(LogSystem.getLog("User " + emailToRevoke + " has been revoked", tsp, "LOG"));
////
////
////            }
////
////
////            return true;
////        } catch (AuthorizationDeniedException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////            e.printStackTrace();
////        } catch (EjbcaException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////            e.printStackTrace();
////
////        } catch (ApprovalException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////            e.printStackTrace();
////
////        } catch (NotFoundException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////            e.printStackTrace();
////
////        } catch (WaitingForApprovalException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////            e.printStackTrace();
////
////        } catch (AlreadyRevokedException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            e.printStackTrace();
////
////        } catch (CADoesntExistsException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (EndEntityProfileNotFoundException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (IllegalQueryException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }
////
////        return false;
////    }
////
////
////    public boolean revokeCert(String certPem, Date tsp) throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException {
//////String issuerDN, String serialToRevoke, String revokeDN,
////        //EjbcaWSService es = new EjbcaWSService();
//////		  CryptoProviderTools.installBCProvider();
//////		Security.addProvider(new BouncyCastleProvider());
////
//////		System.setProperty ("javax.net.ssl.trustStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jkstruststore.jks");
//////        System.setProperty ("javax.net.ssl.trustStorePassword", "spinku12345");
//////        System.setProperty ("javax.net.ssl.keyStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jksadmin.jks");
//////        System.setProperty ("javax.net.ssl.keyStorePassword", "spinku12345");
//////        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
////
////        //System.setProperty("javax.net.ssl.trustStoreType","pkcs12");
////
////        setService();
////        try {
////            X509Certificate cert1 = (X509Certificate) CertificateHelper.getCertificate(Base64.decode(certPem));
////            send.revokeCert(cert1.getIssuerDN().toString(), cert1.getSerialNumber().toString(), RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION);
////
////
////            return true;
////        } catch (AuthorizationDeniedException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////            e.printStackTrace();
////        } catch (EjbcaException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////            e.printStackTrace();
////
////        } catch (ApprovalException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////            e.printStackTrace();
////
////        } catch (NotFoundException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////            e.printStackTrace();
////
////        } catch (WaitingForApprovalException_Exception e) {
////            // TODO Auto-generated catch block
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////            e.printStackTrace();
////
////        } catch (AlreadyRevokedException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            e.printStackTrace();
////
////        } catch (CADoesntExistsException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }catch (Exception e)
////        {
////            e.printStackTrace();
////        }
////
////        return false;
////    }
////
////    public java.security.cert.Certificate[] RequestedCAChain(X509Certificate cr, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
////        java.security.cert.Certificate[] dataCerts = new java.security.cert.Certificate[1];
////
////        setService();
////
////        dataCerts[0] = cr;
////
////
////        try {
////
////            LogSystem.info("CN Name:" + X500Name.asX500Name(cr.getIssuerX500Principal()).getCommonName());
//////					  List<Certificate> result = send.getLastCAChain(X500Name.asX500Name(cr.getIssuerX500Principal()).getCommonName());
////
//////			  String ca="Digisign-CA";
//////			  if(devel!=null) {
//////					if(devel.equals("devel"))ca="Development Digisign";
//////
//////				}
////
//////			UserDataVOWS userdata = new UserDataVOWS();
//////			String ca[] = caNameProd;
//////			if (devel != null) {
//////				if (devel.equals("devel"))
//////					ca = caNameDevel;
//////
//////			}
////            int x = 0;
////            List<Certificate> certCAChain = null;
////            while (certCAChain == null && x < 4) {
////                LOGGER.info(LogSystem.getLog("REQUEST CA CHAIN", tsp, "LOG"));
////                certCAChain = getCA(cr, tsp);
////                x++;
////            }
////
////            LOGGER.info(LogSystem.getLog("CN size:" + certCAChain.size(), tsp, "LOG"));
////
////            if (certCAChain.size() > 0) {
////                dataCerts = new java.security.cert.Certificate[certCAChain.size() + 1];
////                dataCerts[0] = cr;
////
////                int i = 1;
////                for (Certificate certificate : certCAChain) {
////                    X509Certificate cert1 = (X509Certificate) CertificateHelper
////                            .getCertificate(certificate.getCertificateData());
////                    dataCerts[i] = cert1;
////                    i++;
////                }
////                return dataCerts;
////            }
////
////        } catch (IOException e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }
////        return dataCerts;
////
////    }
////
////    private List<Certificate> getCA(X509Certificate cert, Date tsp) {
////        Security.addProvider(new BouncyCastleProvider());
////        try {
////            String cnIssuer = X500Name.asX500Name(cert.getIssuerX500Principal()).getCommonName();
////            int xTry = 0;
////            while ((resultCA == null || resultCA_C5 == null || resultCA_C3 == null || resultCA_v1 == null) && xTry <= 3) {
////                LOGGER.info(LogSystem.getLog("TRY                :" + xTry, tsp, "LOG"));
////                try {
////                    loadCAinit();
////                } catch (KeyManagementException e) {
////                    // TODO Auto-generated catch block
////                    e.printStackTrace();
////                } catch (UnrecoverableKeyException e) {
////                    // TODO Auto-generated catch block
////                    e.printStackTrace();
////                } catch (CertificateException e) {
////                    // TODO Auto-generated catch block
////                    e.printStackTrace();
////                } catch (KeyStoreException e) {
////                    // TODO Auto-generated catch block
////                    e.printStackTrace();
////                } catch (NoSuchAlgorithmException e) {
////                    // TODO Auto-generated catch block
////                    e.printStackTrace();
////                } catch (NoSuchProviderException e) {
////                    // TODO Auto-generated catch block
////                    e.printStackTrace();
////                }
////                xTry++;
////            }
////
////            if (xTry > 3) {
////                return null;
////            }
////
////            for (int i = 0; i < 4; i++) {
////                List<Certificate> CACheck;
////                if (i == 0) {
////                    CACheck = resultCA;
////                } else if (i == 1) {
////                    CACheck = resultCA_C3;
////                } else if (i == 2) {
////                    CACheck = resultCA_C5;
////                } else {
////                    CACheck = resultCA_v1;
////                }
////
////                X509Certificate  certCA;
////                try {
////                    certCA = (X509Certificate) CertificateHelper.getCertificate(CACheck.get(0).getCertificateData());
////
////                    String cnIssuerCheck = X500Name.asX500Name(certCA.getSubjectX500Principal()).getCommonName();
////                    LogSystem.info("         CA CERT: " + certCA);
////                    LogSystem.info("         CA CN: " + cnIssuerCheck);
////                    LogSystem.info("User Issuer CN: " + cnIssuer);
////                    if (cnIssuer.equals(cnIssuerCheck)) {
////                        LOGGER.info(LogSystem.getLog("DN CA:" + certCA.getSubjectDN().toString() + ", SN: " + certCA.getSerialNumber().toString(16).toUpperCase(), tsp, "LOG"));
////                        LOGGER.info(LogSystem.getLog("DN User:" + cert.getSubjectDN().toString() + ", SN: " + cert.getSerialNumber().toString(16).toUpperCase(), tsp, "LOG"));
////                        return CACheck;
////                    }
////                } catch (CertificateParsingException e) {
////                    // TODO Auto-generated catch block
////                    LOGGER.info(LogSystem.getLog("      CATCH 1", tsp,"LOG"));
////                    e.getCause();
////                    e.printStackTrace();
////                } catch (CertificateException e) {
////                    e.printStackTrace();
////                }
////
////            }
////            LOGGER.info(LogSystem.getLog("Issuer " + cnIssuer + " not found : " + cert.getIssuerDN(), tsp, "LOG"));
////            LogSystem.info("asas");
////        } catch (IOException e) {
////            // TODO Auto-generated catch block
////            LOGGER.info(LogSystem.getLog("      CATCH 2", tsp,"LOG"));
////            e.printStackTrace();
////            LogSystem.info("asas");
////        }
////        LOGGER.info(LogSystem.getLog("      RETURN NULL", tsp,"LOG"));
////        LogSystem.info("asas");
////        return null;
////    }
////
////
////    public X509Certificate RequestedTransCAChain(Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
////
//////        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
////
////        setService();
////
////        try {
////
////
////            String ca = "Digisign-CA";
////            if (devel.equals("devel")) ca = "Development Digisign - TR1";
////
////
////            int x = 0;
////            synchronized (data1) {
////
////                while (resultTransCA == null && x < 4) {
////
////                    LOGGER.info(LogSystem.getLog("REQUEST CA CHAIN", tsp, "LOG"));
////
////                    setService();
////                    resultTransCA = send.getLastCAChain(ca);
////                    x++;
////
////                }
////            }
////            LOGGER.info(LogSystem.getLog("CN size:" + resultTransCA.size(), tsp, "LOG"));
////
////            if (resultTransCA.size() > 0) {
////                Certificate cr = resultTransCA.get(0);
////                return (X509Certificate) CertificateHelper.getCertificate(cr.getCertificateData());
////            }
////        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (CADoesntExistsException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (IOException e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }
////        return null;
////
////    }
////
////
////    public void loadCAinit() throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
////        setService();
////        Date tsp = new Date();
////        try {
////            LOGGER.info(LogSystem.getLog("--INIT CA--", tsp, "LOG"));
////
////            String ca[] = caNameProd;
////            String caV1 = caNameProdv1;
////            if (devel.equals("devel")) {
////                ca = caNameDevel;
////                caV1 = caNameDevelv1;
////            }
////
////            int x = 0;
////            synchronized (data1) {
////
////                while ((resultCA == null || resultCA_C5 == null || resultCA_C3 == null || resultCA_v1 == null) && x < 10) {
////
////                    LOGGER.info(LogSystem.getLog("REQUEST CA CHAIN", tsp, "LOG"));
////
////                    setService();
////                    if (resultCA_C3 == null) {
////                        resultCA_C3 = send.getLastCAChain(ca[CertC3]);
////                        LOGGER.info(LogSystem.getLog("load CA levelC3 :" + resultCA_C3.size(), tsp, "LOG"));
////                    }
////                    if (resultCA == null) {
////                        resultCA = send.getLastCAChain(ca[CertC4]);
////                        LOGGER.info(LogSystem.getLog("load CA levelC4 :" + resultCA.size(), tsp, "LOG"));
////
////                    }
////                    if (resultCA_C5 == null) {
////                        resultCA_C5 = send.getLastCAChain(ca[CertSeal]);
////                        LOGGER.info(LogSystem.getLog("load CA levelSeal :" + resultCA_C5.size(), tsp, "LOG"));
////
////                    }
////
////                    if (resultCA_v1 == null) {
////                        resultCA_v1 = send.getLastCAChain(caV1);
////                        LOGGER.info(LogSystem.getLog("load CA v1 :" + resultCA_v1.size(), tsp, "LOG"));
////
////                    }
////                    x++;
////
////                }
////                if (resultCA != null && resultCA_C5 != null && resultCA_C3 != null && resultCA_v1 != null) {
////                    LOGGER.info(LogSystem.getLog("load cert CA successfully", tsp, "LOG"));
////                    return;
////
////                }
////            }
////
////
////        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (CADoesntExistsException_Exception e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        } catch (IOException e) {
////            // TODO Auto-generated catch block
////            e.printStackTrace();
////            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
////
////        }catch (Exception e)
////        {
////            e.printStackTrace();
////        }
////
////    }
////}
//
//public class CertificateRequest extends Description {
//
//    private final static Logger LOGGER = LogManager.getLogger(CertificateRequest.class);
//
//    protected String subjDN;
//    protected String email;
//    static String data1 = "OK";
//    protected static Service service;
//    protected static QName qname;
//    protected EjbcaWS send;
//
//    /**
//     * penamaan ca
//     **/
//    final int CertC3 = 0;
//    final int CertC4 = 1;
//    final int CertSeal = 2;
////    final String caNameProd[] = {"Digisign-CA", "Digisign-CA", "Digisign-CA"};
//    final String caNameProd[] = {"DigisignID.CA.Level3-G3", "DigisignID.CA.Level4-G3", "DigisignID.CA.Seal-G3"};
//    //    final String caNameDevel[] = {"DigisignID.Dev.CA.Level3", "DigisignID.Dev.CA.Level4", "DigisignID.Dev.CA.LevelSeal"};
//    final String caNameDevel[] = {"DigisignID.Dev.CA.Level3-G3", "DigisignID.Dev.CA.Level4-G3", "DigisignID.Dev.CA.Seal-G3"};
//
//    final String caNameProdv1 = "DigisignID.CA.Level4-G3";
//    final String caNameDevelv1 = "Development Digisign";
//
//    static List<Certificate> resultCA_v1 = null;
//    static List<Certificate> resultCA = null;
//    static List<Certificate> resultCA_C3 = null;
//    static List<Certificate> resultCA_C5 = null;
//    /**
//     * end
//     **/
//
//
//    static List<Certificate> resultTransCA = null;
//
//    public void setService() throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException {
////		final Provider tlsProvider = new TLSProvider();
////        Security.addProvider(tlsProvider);
//
//        SSLSocketFactory sc;
//        Security.addProvider(new BouncyCastleProvider());
//
//        sc = setSSL();
//
//        synchronized (data1) {
//            if (service == null) {
//                qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
//
//                service = Service.create(new URL("https://" + EJBCA_HOST + ":" + EJBCA_PORT + "/ejbca/ejbcaws/ejbcaws?wsdl"), qname);
//            }
//
//        }
//
//
//        send = service.getPort(EjbcaWS.class);
//
//        ((BindingProvider) send).getRequestContext().put("com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory", sc);
//
//    }
//
//    public CertificateRequest(String DN, String email) throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
//        subjDN = DN;
//        this.email = email;
//
//
//    }
//
//    public CertificateRequest() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException, NoSuchProviderException {
//
//
//    }
//
//    protected SSLSocketFactory setSSL() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException, NoSuchProviderException {
//
////		System.setProperty ("javax.net.ssl.trustStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jkstruststore.jks");
////		System.setProperty ("javax.net.ssl.trustStorePassword", "spinku12345");
////		System.setProperty ("javax.net.ssl.keyStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jksadmin.jks");
////		System.setProperty ("javax.net.ssl.keyStorePassword", "spinku12345");
////	      System.setProperty("javax.net.ssl.keyStoreType", "JKS");
//
////	        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true"); // <-- I still have to set this to true, otherwise a ws call will result in 'SocketException: Unexpected end of file from server'. One should try to avoid setting it to true.
//        //I also had to restart JBoss each time I changed the setting. We accept the security risk although I am still looking for answers why the EOF exception occurs.
//
//        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
//            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
//                return null;
//            }
//
//            public void checkClientTrusted(X509Certificate[] certs, String authType) {
//            }
//
//            public void checkServerTrusted(X509Certificate[] certs, String authType) {
//            }
//
//        }};
//
//        KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
//        FileInputStream instream = new FileInputStream(new File(JKS + "admin.jks"));
////	        FileInputStream instream = new FileInputStream(new File("F:\\DigisignFile\\admin.jks"));
//
//        if (Objects.equals(devel, "devel")) {
//            LogSystem.info("serverKMS.jks load jks");
//            instream = new FileInputStream(new File(JKS + "serverKMS.jks"));
//            LogSystem.info("SUKSES serverKMS.jks load jks");
//        }
//
//        try {
//            keyStore.load(instream, "spinku12345".toCharArray());
//        } finally {
//            instream.close();
//        }
//        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
//        kmf.init(keyStore, "spinku12345".toCharArray());
//
////			FileInputStream myKeys = new FileInputStream("F:\\\\DigisignFile\\truststore.jks");
//        LogSystem.info("trusstore.jks load jks");
//        FileInputStream myKeys = new FileInputStream(JKS + "truststore.jks");
//        LogSystem.info("finish trusstore.jks load jks");
//
//        if (Objects.equals(devel, "devel")) {
//            LogSystem.info("trusstore.jks load jks devel");
//            myKeys = new FileInputStream(new File(JKS + "truststore-devel.jks"));
//            LogSystem.info("finish trusstore.jks load jks devel");
//        }
//
//        // Do the same with your trust store this time
//        // Adapt how you load the keystore to your needs
//        KeyStore myTrustStore = KeyStore.getInstance("JKS", "SUN");
//        myTrustStore.load(myKeys, "spinku12345".toCharArray());
//
//        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
//
//        tmf.init(myTrustStore);
//
//        // Trust own CA and all self-signed certs
////	        SSLContext sslcontext = SSLContexts.custom()
////	            .loadKeyMaterial(keyStore, "spinku12345".toCharArray())
////	            //.loadTrustMaterial(trustStore, new TrustSelfSignedStrategy()) //custom trust store
////	            .build();
//        SSLContext sslcontext = SSLContext.getInstance("TLS");
//        sslcontext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
//
//        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
//                new javax.net.ssl.HostnameVerifier() {
//
//                    public boolean verify(String hostname,
//                                          javax.net.ssl.SSLSession sslSession) {
//                        return true;
//                    }
//                });
//        HttpsURLConnection.setDefaultSSLSocketFactory(sslcontext.getSocketFactory());
//        return sslcontext.getSocketFactory();
//    }
//
//    public X509Certificate RequestedCertificate33(String pkcs10, String levelCert, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
//
//
//        setService();
//
//        try {
//
//            UserDataVOWS userdata = new UserDataVOWS();
//            userdata.setCaName("Digisign-CA");
//            if (Objects.equals(devel, "devel")) {
//                userdata.setCaName("Development Digisign");
//
//            }
//            userdata.setUsername(email);
//            userdata.setEndEntityProfileName("UserApp");
//            if (levelCert.equals("C4")) {
//                userdata.setPassword("ejb" + email.substring(0, 5));
//                userdata.setCertificateProfileName("UserApp");
//                userdata.setEmail(email);
//            } else if (levelCert.equals("C3") || levelCert.equals("C2")) {
//                userdata.setPassword("ejb" + email.substring(0, 5));
//                userdata.setCertificateProfileName("UserApp" + levelCert);
//                userdata.setEmail(email);
//            } else if (levelCert.equals("C5")) {
//                if (email.length() < 8) userdata.setPassword("ejb" + email);
//                else userdata.setPassword("ejb" + email.substring(email.length() - 5));
//                userdata.setCertificateProfileName("UserApp" + levelCert);
//                userdata.setEndEntityProfileName("SealProfile");
//
//            }
//            userdata.setSubjectDN(subjDN);
//
//            LOGGER.info(LogSystem.getLog("profile cert : " + userdata.getCertificateProfileName(), tsp, "LOG"));
//
//            CertificateResponse cr = send.certificateRequest(userdata, pkcs10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
//
//            X509Certificate cert1 = (X509Certificate) CertificateHelper.getCertificate(cr.getData());
//
//            return cert1;
//
//        } catch (AuthorizationDeniedException_Exception e) {
//            // TODO Auto-generated catch block
////				 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//            e.printStackTrace();
//        } catch (EjbcaException_Exception e) {
//            // TODO Auto-generated catch block
////				 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (ApprovalException_Exception e) {
//            // TODO Auto-generated catch block
////				 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (NotFoundException_Exception e) {
//            // TODO Auto-generated catch block
////				 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
//            // TODO Auto-generated catch block
////				 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (WaitingForApprovalException_Exception e) {
//            // TODO Auto-generated catch block
////				 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        }
//
//        return null;
//
//    }
//
//    public X509Certificate RequestedCertificate(String pkcs10, String levelCert, String sim, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CADoesntExistsException_Exception {
//
//
//        setService();
//
//        try {
//
//            UserDataVOWS userdata = new UserDataVOWS();
//            String ca[] = caNameProd;
//
//            if (devel.equals("devel")) ca = caNameDevel;
//
//
//            userdata.setUsername(email);
//            userdata.setEndEntityProfileName("UserApp");
//            userdata.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
//            if (levelCert.equals("C4")) {
//                userdata.setPassword("ejb" + email.substring(0, 5));
//                userdata.setCertificateProfileName("UserAppC4V.2");
//                userdata.setEmail(email);
//                userdata.setCaName(ca[CertC4]);
//
//                if (simMandatory) {
//                    userdata.setSubjectAltName("subjectIdentificationMethod=" + sim);
//                }
//            } else if (levelCert.equals("C3")) {
//                userdata.setPassword("ejb" + email.substring(0, 5));
//                userdata.setCertificateProfileName("UserAppC3V.2");
//                userdata.setEmail(email);
//                userdata.setCaName(ca[CertC3]);
//                if (simMandatory) {
//                    userdata.setSubjectAltName("subjectIdentificationMethod=" + sim);
//                }
//            } else if (levelCert.equals("C5")) {
//                if (email.length() < 8) userdata.setPassword("ejb" + email);
//                else userdata.setPassword("ejb" + email.substring(email.length() - 5));
//                userdata.setCertificateProfileName("UserAppSealV.2");
//                userdata.setEndEntityProfileName("SealProfile");
//                userdata.setCaName(ca[CertSeal]);
//
//            } else {
//                return null;
//            }
//            userdata.setSubjectDN(subjDN);
//            send.editUser(userdata);
////	         LOGGER.info(LogSystem.getLog( "profile cert : "+userdata.getCertificateProfileName(), tsp, "LOG"));
//
//            CertificateResponse cr = send.certificateRequest(userdata, pkcs10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
//
//            X509Certificate cert1 = (X509Certificate) CertificateHelper.getCertificate(cr.getData());
//
//            return cert1;
//
//        } catch (AuthorizationDeniedException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//            e.printStackTrace();
//        } catch (EjbcaException_Exception | NotFoundException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (ApprovalException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (WaitingForApprovalException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//
//        return null;
//
//    }
//
//    public byte[] RequestedTransactionCertificate(String pkcs10, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
//
//
//        setService();
//
//        try {
//
//            UserDataVOWS userdata = new UserDataVOWS();
//            userdata.setCaName("Digisign-CA");
//
//            if (devel.equals("devel")) userdata.setCaName("Development Digisign - TR1");
//
//            userdata.setUsername(email);
//            userdata.setEndEntityProfileName("TRUserApp");
//            userdata.setPassword("ejb" + email.substring(0, 5));
//            userdata.setCertificateProfileName("TRUserApp");
//            userdata.setEmail(email);
//            userdata.setSubjectDN(subjDN);
//
//            LOGGER.info(LogSystem.getLog("profile cert : " + userdata.getCertificateProfileName(), tsp, "LOG"));
//
//            CertificateResponse cr = send.certificateRequest(userdata, pkcs10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
//
//
//            return cr.getData();
//
//        } catch (AuthorizationDeniedException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//            e.printStackTrace();
//        } catch (EjbcaException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (ApprovalException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (NotFoundException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (WaitingForApprovalException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        }
//
//        return null;
//
//    }
//
//    public byte[] RequestP12(String levelCert, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
//
//
//        setService();
//
//        try {
//
////			UserDataVOWS userdata = new UserDataVOWS();
////			userdata.setCaName("Digisign-CA");
////			if(devel!=null) {
////				if(devel.equals("devel"))userdata.setCaName("Development Digisign");
////
////			}
//            UserDataVOWS userdata = new UserDataVOWS();
//            String ca[] = caNameProd;
//
//            if (devel.equals("devel")) ca = caNameDevel;
//
//            userdata.setUsername(email);
//            userdata.setEndEntityProfileName("UserApp");
//            if (levelCert.equals("C4")) {
//                userdata.setPassword("ejb" + email.substring(0, 5));
////				userdata.setCertificateProfileName("UserApp");
//                userdata.setCertificateProfileName("UserAppC4V.2");
//                userdata.setEmail(email);
//                userdata.setCaName(ca[CertC4]);
//            } else if (levelCert.equals("C3")) {
//                userdata.setPassword("ejb" + email.substring(0, 5));
////				userdata.setCertificateProfileName("UserApp"+levelCert);
//                userdata.setCertificateProfileName("UserAppC3V.2");
//                userdata.setEmail(email);
//                userdata.setCaName(ca[CertC3]);
//
//            } else if (levelCert.equals("C5")) {
//                if (email.length() < 8) userdata.setPassword("ejb" + email);
//                else userdata.setPassword("ejb" + email.substring(email.length() - 5));
////				userdata.setCertificateProfileName("UserApp"+levelCert);
//                userdata.setCertificateProfileName("UserAppSealV.2");
//                userdata.setEndEntityProfileName("SealProfile");
//                userdata.setCaName(ca[CertSeal]);
//            }
//            userdata.setSubjectDN(subjDN);
//
//            send.editUser(userdata);
//            LOGGER.info(LogSystem.getLog("profile cert : " + userdata.getCertificateProfileName(), tsp, "LOG"));
//            com.ejbca.client.KeyStore kyStore = send.pkcs12Req(email, userdata.getPassword(), null, "2048", AlgorithmConstants.KEYALGORITHM_RSA);
////			CertificateResponse cr = send.certificateRequest(userdata, pkcs10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
//
////	        X509Certi?ficate cert1 = (X509Certificate) CertificateHelper.getCertificate(cr.getData());
//
//            return kyStore.getKeystoreData();
//
//        } catch (AuthorizationDeniedException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//            e.printStackTrace();
//        } catch (EjbcaException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (ApprovalException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (NotFoundException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (WaitingForApprovalException_Exception e) {
//            // TODO Auto-generated catch block
////			 MyLogger.setError(this.getClass(), e);
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (CADoesntExistsException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (Exception e) {
//            e.printStackTrace();
//
//        }
//        return null;
//
//    }
//
//    public boolean revoke(String emailToRevoke, Date tsp) throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException {
////String issuerDN, String serialToRevoke, String revokeDN,
//        //EjbcaWSService es = new EjbcaWSService();
////		  CryptoProviderTools.installBCProvider();
////		Security.addProvider(new BouncyCastleProvider());
//
////		System.setProperty ("javax.net.ssl.trustStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jkstruststore.jks");
////        System.setProperty ("javax.net.ssl.trustStorePassword", "spinku12345");
////        System.setProperty ("javax.net.ssl.keyStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jksadmin.jks");
////        System.setProperty ("javax.net.ssl.keyStorePassword", "spinku12345");
////        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
//
//        //System.setProperty("javax.net.ssl.trustStoreType","pkcs12");
//        setService();
//        boolean res = false;
//        try {
//
//            UserMatch usermatch = new UserMatch();
//            usermatch.setMatchwith(org.ejbca.core.protocol.ws.objects.UserMatch.MATCH_WITH_USERNAME);
//            usermatch.setMatchtype(org.ejbca.core.protocol.ws.objects.UserMatch.MATCH_TYPE_EQUALS);
//            usermatch.setMatchvalue(emailToRevoke);
//            List<UserDataVOWS> result = send.findUser(usermatch);
//            LOGGER.info(LogSystem.getLog("REQ REVOKE: " + emailToRevoke, tsp, "LOG"));
////				send.revokeCert(issuerDN, serialToRevoke, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION);
//            if (result.size() > 0) {
//                send.revokeUser(emailToRevoke, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, true);
//                Date date = new Date();
////					LogSystem.info(date+"Certificate "+serialToRevoke+" ["+revokeDN+"] has been revoked");
//                LOGGER.info(LogSystem.getLog("User " + emailToRevoke + " has been revoked", tsp, "LOG"));
//
//
//            }
//
//
//            return true;
//        } catch (AuthorizationDeniedException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//            e.printStackTrace();
//        } catch (EjbcaException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//            e.printStackTrace();
//
//        } catch (ApprovalException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//            e.printStackTrace();
//
//        } catch (NotFoundException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//            e.printStackTrace();
//
//        } catch (WaitingForApprovalException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//            e.printStackTrace();
//
//        } catch (AlreadyRevokedException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            e.printStackTrace();
//
//        } catch (CADoesntExistsException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (EndEntityProfileNotFoundException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (IllegalQueryException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        }
//
//        return false;
//    }
//
//
//    public boolean revokeCert(String certPem, Date tsp) throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException {
////String issuerDN, String serialToRevoke, String revokeDN,
//        //EjbcaWSService es = new EjbcaWSService();
////		  CryptoProviderTools.installBCProvider();
////		Security.addProvider(new BouncyCastleProvider());
//
////		System.setProperty ("javax.net.ssl.trustStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jkstruststore.jks");
////        System.setProperty ("javax.net.ssl.trustStorePassword", "spinku12345");
////        System.setProperty ("javax.net.ssl.keyStore", "C:\\SNI\\Digisign\\mitraapi\\kms\\jksadmin.jks");
////        System.setProperty ("javax.net.ssl.keyStorePassword", "spinku12345");
////        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
//
//        //System.setProperty("javax.net.ssl.trustStoreType","pkcs12");
//
//        setService();
//        try {
//            X509Certificate cert1 = (X509Certificate) CertificateHelper.getCertificate(Base64.decode(certPem));
//            send.revokeCert(cert1.getIssuerDN().toString(), cert1.getSerialNumber().toString(), RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION);
//
//
//            return true;
//        } catch (AuthorizationDeniedException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//            e.printStackTrace();
//        } catch (EjbcaException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//            e.printStackTrace();
//
//        } catch (ApprovalException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//            e.printStackTrace();
//
//        } catch (NotFoundException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//            e.printStackTrace();
//
//        } catch (WaitingForApprovalException_Exception e) {
//            // TODO Auto-generated catch block
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//            e.printStackTrace();
//
//        } catch (AlreadyRevokedException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            e.printStackTrace();
//
//        } catch (CADoesntExistsException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        return false;
//    }
//
//    public java.security.cert.Certificate[] RequestedCAChain(X509Certificate cr, Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
//        java.security.cert.Certificate[] dataCerts = new java.security.cert.Certificate[1];
//
//        setService();
//
//        dataCerts[0] = cr;
//
//        try {
//
//            LogSystem.info("CN Name:" + X500Name.asX500Name(cr.getIssuerX500Principal()).getCommonName());
////					  List<Certificate> result = send.getLastCAChain(X500Name.asX500Name(cr.getIssuerX500Principal()).getCommonName());
//
////			  String ca="Digisign-CA";
////			  if(devel!=null) {
////					if(devel.equals("devel"))ca="Development Digisign";
////
////				}
//
////			UserDataVOWS userdata = new UserDataVOWS();
////			String ca[] = caNameProd;
////			if (devel != null) {
////				if (devel.equals("devel"))
////					ca = caNameDevel;
////
////			}
//            int x = 0;
//            List<Certificate> certCAChain = null;
//            while (certCAChain == null && x < 4) {
//                LOGGER.info(LogSystem.getLog("REQUEST CA CHAIN", tsp, "LOG"));
//                certCAChain = getCA(cr, tsp);
//                x++;
//            }
//
//            LOGGER.info(LogSystem.getLog("CN size:" + certCAChain.size(), tsp, "LOG"));
//
//            if (certCAChain.size() > 0) {
//                dataCerts = new java.security.cert.Certificate[certCAChain.size() + 1];
//                dataCerts[0] = cr;
//
//                int i = 1;
//                for (Certificate certificate : certCAChain) {
//                    X509Certificate cert1 = (X509Certificate) CertificateHelper
//                            .getCertificate(certificate.getCertificateData());
//                    dataCerts[i] = cert1;
//                    i++;
//                }
//                return dataCerts;
//            }
//
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        }
//        return dataCerts;
//
//    }
//
//    private List<Certificate> getCA(X509Certificate cert, Date tsp) {
//        Security.addProvider(new BouncyCastleProvider());
//        try {
//            String cnIssuer = X500Name.asX500Name(cert.getIssuerX500Principal()).getCommonName();
//            int xTry = 0;
//            while ((resultCA == null || resultCA_C5 == null || resultCA_C3 == null || resultCA_v1 == null) && xTry <= 3) {
//                LOGGER.info(LogSystem.getLog("TRY                :" + xTry, tsp, "LOG"));
//                try {
//                    loadCAinit();
//                } catch (KeyManagementException e) {
//                    // TODO Auto-generated catch block
//                    e.printStackTrace();
//                } catch (UnrecoverableKeyException e) {
//                    // TODO Auto-generated catch block
//                    e.printStackTrace();
//                } catch (CertificateException e) {
//                    // TODO Auto-generated catch block
//                    e.printStackTrace();
//                } catch (KeyStoreException e) {
//                    // TODO Auto-generated catch block
//                    e.printStackTrace();
//                } catch (NoSuchAlgorithmException e) {
//                    // TODO Auto-generated catch block
//                    e.printStackTrace();
//                } catch (NoSuchProviderException e) {
//                    // TODO Auto-generated catch block
//                    e.printStackTrace();
//                }
//                xTry++;
//            }
//
//            if (xTry > 3) {
//                return null;
//            }
//
//            for (int i = 0; i < 4; i++) {
//                List<Certificate> CACheck;
//                if (i == 0) {
//                    CACheck = resultCA;
//                } else if (i == 1) {
//                    CACheck = resultCA_C3;
//                } else if (i == 2) {
//                    CACheck = resultCA_C5;
//                } else {
//                    CACheck = resultCA_v1;
//                }
//
//                X509Certificate certCA;
//                try {
//                    certCA = (X509Certificate) CertificateHelper.getCertificate(CACheck.get(0).getCertificateData());
//
//                    String cnIssuerCheck = X500Name.asX500Name(certCA.getSubjectX500Principal()).getCommonName();
////                    LogSystem.info("         CA CERT: " + certCA);
//                    if (cnIssuer.equals(cnIssuerCheck)) {
//                        LogSystem.info("DN CA:" + certCA.getSubjectDN().toString() + ", SN: " + certCA.getSerialNumber().toString(16).toUpperCase());
//                        LogSystem.info("DN User:" + cert.getSubjectDN().toString() + ", SN: " + cert.getSerialNumber().toString(16).toUpperCase());
//                        return CACheck;
//                    }
//                } catch (CertificateParsingException e) {
//                    // TODO Auto-generated catch block
//                    LOGGER.info(LogSystem.getLog("      CATCH 1", tsp, "LOG"));
//                    e.getCause();
//                    e.printStackTrace();
//                } catch (CertificateException e) {
//                    e.printStackTrace();
//                }
//
//            }
//            LOGGER.info(LogSystem.getLog("Issuer " + cnIssuer + " not found : " + cert.getIssuerDN(), tsp, "LOG"));
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            LOGGER.info(LogSystem.getLog("      CATCH 2", tsp, "LOG"));
//            e.printStackTrace();
//        }
//        LOGGER.info(LogSystem.getLog("      RETURN NULL", tsp, "LOG"));
//        return null;
//    }
//
//
//    public X509Certificate RequestedTransCAChain(Date tsp) throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
//
////        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
//
//        setService();
//
//        try {
//
//
//            String ca = "Digisign-CA";
//            if (devel.equals("devel")) ca = "Development Digisign - TR1";
//
//
//            int x = 0;
//            synchronized (data1) {
//
//                while (resultTransCA == null && x < 4) {
//
//                    LOGGER.info(LogSystem.getLog("REQUEST CA CHAIN", tsp, "LOG"));
//
//                    setService();
//                    resultTransCA = send.getLastCAChain(ca);
//                    x++;
//
//                }
//            }
//            LOGGER.info(LogSystem.getLog("CN size:" + resultTransCA.size(), tsp, "LOG"));
//
//            if (resultTransCA.size() > 0) {
//                Certificate cr = resultTransCA.get(0);
//                return (X509Certificate) CertificateHelper.getCertificate(cr.getCertificateData());
//            }
//        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (CADoesntExistsException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        }
//        return null;
//
//    }
//
//
//    public void loadCAinit() throws CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
//        setService();
//        Date tsp = new Date();
//        try {
//            LOGGER.info(LogSystem.getLog("--INIT CA--", tsp, "LOG"));
//
//            String ca[] = caNameProd;
//            String caV1 = caNameProdv1;
//            if (devel.equals("devel")) {
//                ca = caNameDevel;
//                caV1 = caNameDevelv1;
//            }
//
//            int x = 0;
//            synchronized (data1) {
//
//                while ((resultCA == null || resultCA_C5 == null || resultCA_C3 == null || resultCA_v1 == null) && x < 10) {
//
//                    LOGGER.info(LogSystem.getLog("REQUEST CA CHAIN", tsp, "LOG"));
//
//                    setService();
//                    if (resultCA_C3 == null) {
//                        resultCA_C3 = send.getLastCAChain(ca[CertC3]);
//                        LOGGER.info(LogSystem.getLog("load CA levelC3 :" + resultCA_C3.size(), tsp, "LOG"));
//                    }
//                    if (resultCA == null) {
//                        resultCA = send.getLastCAChain(ca[CertC4]);
//                        LOGGER.info(LogSystem.getLog("load CA levelC4 :" + resultCA.size(), tsp, "LOG"));
//
//                    }
//                    if (resultCA_C5 == null) {
//                        resultCA_C5 = send.getLastCAChain(ca[CertSeal]);
//                        LOGGER.info(LogSystem.getLog("load CA levelSeal :" + resultCA_C5.size(), tsp, "LOG"));
//
//                    }
//
//                    if (resultCA_v1 == null) {
//                        resultCA_v1 = send.getLastCAChain(caV1);
//                        LOGGER.info(LogSystem.getLog("load CA v1 :" + resultCA_v1.size(), tsp, "LOG"));
//
//                    }
//                    x++;
//
//                }
//                if (resultCA != null && resultCA_C5 != null && resultCA_C3 != null && resultCA_v1 != null) {
//                    LOGGER.info(LogSystem.getLog("load cert CA successfully", tsp, "LOG"));
//                    return;
//
//                }
//            }
//
//
//        } catch (AuthorizationDeniedException_Exception | EjbcaException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (CADoesntExistsException_Exception e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            LOGGER.error(LogSystem.getLog(ExceptionUtils.getStackTrace(e), tsp, "ERROR"));
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//    }
//
//}
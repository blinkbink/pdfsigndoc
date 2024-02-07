//package id.idtrust.signing.core.pdf;
//
//import id.idtrust.signing.core.certificate.CertificateRequest;
//import id.idtrust.signing.model.signer.KeySigner;
//import id.idtrust.signing.util.Description;
//
//import org.apache.pdfbox.examples.signature.cert.CRLVerifier;
//import org.apache.pdfbox.examples.signature.cert.OcspHelper;
//import org.apache.pdfbox.examples.signature.cert.RevokedCertificateException;
//import org.apache.pdfbox.examples.signature.validation.AddValidationInformation;
//
//import org.bouncycastle.asn1.ASN1Encodable;
//import org.bouncycastle.asn1.ASN1OctetString;
//import org.bouncycastle.asn1.ASN1Sequence;
//import org.bouncycastle.asn1.ASN1TaggedObject;
//import org.bouncycastle.asn1.x509.Extension;
//import org.bouncycastle.asn1.x509.GeneralName;
//import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
//import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
//import org.bouncycastle.cert.ocsp.OCSPException;
//import org.bouncycastle.cert.ocsp.OCSPResp;
//
//import org.json.JSONArray;
//import org.json.JSONException;
//import org.json.JSONObject;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.stereotype.Component;
//
//import java.awt.geom.Rectangle2D;
//import java.io.*;
//import java.security.*;
//import java.security.cert.Certificate;
//import java.security.cert.X509Certificate;
//import java.text.MessageFormat;
//import java.util.*;
//
//import static org.aspectj.util.FileUtil.copyFile;
//
//@Component
//public class SignDoc extends Description {
//    JSONArray arrayTimeStamp=new JSONArray();
//    private PrivateKey privateKey = null;
//    private String keyAlias = null;
//    private KeyPairGenerator keyGen = null;
//    Certificate[] cert=null;
//
//    Logger logger = LoggerFactory.getLogger(SignDoc.class);
//
//    public Date signingDoc(Date timestamp, UserSignature userS, List<UserSignature> userSignBulk, String tmpdir, List<KeyV3> key, List<KeyV3> sealCert, String org, JSONObject jsonFile) throws Exception {
//        //Decrypt private key
//        Calendar calendar = dateToCalendar(timestamp);
//
//        UserSignature userSign=userS;
//        LogSystem.info("Decrypt private key");
//        try {
//            List<KeyV3> keyData = key;
//            List<KeyV3> sealCertData =  sealCert;
//            LogSystem.info("User sign level " + userS.getLevel());
//            LogSystem.info("User certificate " + userS.getCertificate().getIdUser());
//
//            if (userS.getLevel().equals("C5"))
//            {
//                if(sealCertData.size()<=0)
//                {
//                    LogSystem.info("SEAL DATA SIZE " + sealCertData.size());
//                    return null;
//                }
//
//                for (int i = 0; i < sealCertData.size(); i++)
//                {
//                    String base64 = sealCertData.get(i).getKey();
//                    KeySigner signer = new KeySigner();
//                    LogSystem.info("JENIS KEY : "+sealCertData.get(i).getJenisKey());
//
//                    if (sealCertData.get(i).getJenisKey().equals("CR"))
//                    {
//                        keyAlias =  sealCertData.get(i).getKeyAlias();
//                        cert = signer.getCert(base64);
//                        LogSystem.info("KEY ALIAS "+keyAlias);
//                    }
//
//                    if(cert!=null)break;
//                }
//
//                LogSystem.info("load certificate " + timestamp);
//
//                CertificateRequest cReq = new CertificateRequest();
//                int tryCnt = 0;
//                Certificate[] dC = null;
//                while (tryCnt < 3 && dC == null) {
//                    try {
//                        dC = cReq.RequestedCAChain((X509Certificate) cert[0], timestamp);
//                    }catch(Exception e)
//                    {
//                        LogSystem.error(e.toString());
//                        e.printStackTrace();
//                        jsonFile.put("error", e.toString());
//                        return null;
//                    }
//                    if (dC.length <= 1) dC = null;
//                    tryCnt++;
//                }
//                if (dC == null) return null;
//                cert = dC;
//            }
//            else
//            {
//                if(!Optional.ofNullable(keyData).isPresent())
//                {
//                    return null;
//                }
//
//                LogSystem.info("DATA SIZE "+keyData.size());
//                for (int i = 0; i < keyData.size(); i++)
//                {
//                    String base64 = keyData.get(i).getKey();
//                    KeySigner signer = new KeySigner();
//                    LogSystem.info("JENIS KEY : "+keyData.get(i).getJenisKey());
//
//                    if (keyData.get(i).getJenisKey().equals("CR"))
//                    {
//                        keyAlias =  keyData.get(i).getKeyAlias();
//
//                        cert = signer.getCert(base64);
//                        LogSystem.info("KEY ALIAS "+keyAlias);
//                    }
//
//                    if(cert!=null)break;
//                }
//
//                LogSystem.info("load certificate " + timestamp);
//
//                CertificateRequest cReq = new CertificateRequest();
//                int tryCnt = 0;
//                Certificate[] dC = null;
//                while (tryCnt < 3 && dC == null) {
//                    LogSystem.info("Request CA Chain");
//                    try {
//                        dC = cReq.RequestedCAChain((X509Certificate) cert[0], timestamp);
//                    }catch(Exception e)
//                    {
//                        LogSystem.error(e.toString());
//                        e.printStackTrace();
//                        jsonFile.put("error", e.toString());
//                        return null;
//                    }
//                    if (dC.length <= 1) dC = null;
//                    tryCnt++;
//                }
////                LogSystem.info("ISI DC " +dC.toString());
//                if (dC == null) return null;
//                cert = dC;
//
//                LogSystem.info("CERT:"+cert.toString());
//
//            }
//        }catch (Exception e)
//        {
//            e.printStackTrace();
//            LogSystem.error(e.toString());
//            if(!jsonFile.has("error")) {
//                jsonFile.put("error", e.toString());
//            }
//            return null;
//        }
//
//        File inPath = new File(userS.getInFile());
//        LogSystem.info("IN Path : " + inPath);
//        File destFile;
//
//        Signing signing = null;
//        if (userS.getLevel().equals("C5")) {
//            signing = new Signing(cert, keyAlias);
//        }
//        else {
//            signing = new Signing(cert, keyAlias);
//        }
//
//        signing.setDate(calendar);
//        //SignDoc
//        if(userS.isWithQR())
//        {
//            LogSystem.info("User is with QR");
//            QRCode qr=new QRCode();
//            if(userS.getLevel().equals("C5"))
//            {
//                LogSystem.info("Level C5");
//                qr.generateQRCode(userS.getDoc_id(), userS.getPathLogo(), userS.getCertificate().getName(), signing.getDate().getTime(), userS.getImgFile(), userS.getqRPathTemp(), userS.getQrText(), QRCode.QR_FOR_SEAL, userS.isWithSignature(), userS.isQrOnly());
//                signing.setImageFile(new File(userS.getqRPathTemp()));
//                signing.setExternalSigning(true);
//
//                LogSystem.info("USER IMAGE PATH"+userS.getqRPathTemp());
//            }
//            else
//            {
//                if(userS.getType().equals("initials"))
//                {
//                    signing.setImageFile(new File(userS.getImgFile()));
//                }
//                else
//                {
//                    LogSystem.info("Level selain C5");
//                    if(userS.getPosition() != 2)
//                    {
//                        qr.generateQRCode(userS.getDoc_id(), userS.getPathLogo(), userS.getCertificate().getName(), signing.getDate().getTime(), userS.getImgFile(), userS.getqRPathTemp(), userS.getQrText(), QRCode.QR_FOR_SIGN, userS.isWithSignature(), userS.isQrOnly());
//                    }
//                    else
//                    {
//                        LogSystem.info("Position " + userS.getPosition());
//                        qr.generateQRCodeImage2(userS.getDoc_id(), userS.getQrText(), userS.getPathLogo(), userS.getCertificate().getName(), new Date(), userS.getImgFile(), userS.getqRPathTemp(), QRCode.QR_FOR_SIGN, false, false);
//                    }
//                    signing.setImageFile(new File(userS.getqRPathTemp()));
//                    LogSystem.info("USER IMAGE PATH"+userS.getqRPathTemp());
//                }
//            }
//        }
//        else
//        {
//            LogSystem.info("User no QR");
//            if (userS.getType().equals("initials")) {
//                LogSystem.info("Type initials");
//                signing.setImageFile(new File(userS.getImgFile()));
//            } else {
//                if(!userS.getLevel().equals("C5")) {
//                    QRCode qr = new QRCode();
//                    LogSystem.info("Type sign");
//                    qr.generateImageSignNoQr(userS.getCertificate().getName(), userS.getImgFile(), userS.getqRPathTemp(), signing.getDate().getTime());
//                    signing.setImageFile(new File(userS.getqRPathTemp()));
//                    LogSystem.info("USER IMAGE PATH " + userS.getqRPathTemp());
//                }
//                else {
//                    LogSystem.info("only Logo C5");
//                    signing.setImageFile(new File(userS.getImgFile()));
//                    LogSystem.info("USER IMAGE PATH " + userS.getImgFile());
//                }
//            }
//        }
//
//        // sign PDF
//        destFile = new File(userS.getOutFile());
//        String nameField;
//
//        for(int i = 0 ; i < userSignBulk.size() ; i++)
//        {
//            float lx = 0;
//            float ly = 0;
//            float rx = 0;
//            float ry = 0;
//
//            int page = 0;
//
//            if(userSignBulk.get(i).isVisible())
//            {
//                lx = Float.parseFloat(userSignBulk.get(i).getSigPosLLX());
//                ly = Float.parseFloat(userSignBulk.get(i).getSigPosLLY());
//                rx = Float.parseFloat(userSignBulk.get(i).getSigPosURX());
//                ry = Float.parseFloat(userSignBulk.get(i).getSigPosURY());
//                page = userSignBulk.get(i).getSigpage()-1;
//            }
//
//            //Signing with PDFBox
//            //OCSP and CRL
//            // Try checking the certificate through OCSP (faster than CRL)
//            String ocspURL = extractOCSPURL((X509Certificate) cert[0]);
//            if (ocspURL != null)
//            {
//                LogSystem.info("Checking OCSP");
//                LogSystem.info("OCSP URL : " + ocspURL);
//
//                try
//                {
//                    OcspHelper ocspHelper = new OcspHelper((X509Certificate) cert[0], new Date(), (X509Certificate) cert[1], null, ocspURL);
//
//                    OCSPResp ocspResp = ocspHelper.getResponseOcsp();
//
//                    LogSystem.info("OCSP Status : " + ocspResp.getStatus());
//
////                    CRLVerifier.verifyCertificateCRLs((X509Certificate) cert[0], new Date(), null);
//                }
//                catch (IOException | OCSPException | RevokedCertificateException ex)
//                {
//                    jsonFile.put("error", ex.toString());
//                    logger.error(String.valueOf(ex));
//                    ex.printStackTrace();
//                    // IOException happens with 021496.pdf because OCSP responder no longer exists
//                    // OCSPException happens with QV_RCA1_RCA3_CPCPS_V4_11.pdf
//                    LogSystem.error("Exception trying OCSP, will try CRL ");
//                    LogSystem.error("Certificate# to check: " + ((X509Certificate) cert[0]).getSerialNumber().toString(16));
//                    CRLVerifier.verifyCertificateCRLs((X509Certificate) cert[0], new Date(), null);
//
//                    return null;
//                }
//            }
//            else
//            {
//                LogSystem.info("OCSP not available, will try CRL");
//                // Check whether the certificate is revoked by the CRL
//                // given in its CRL distribution point extension
//                try {
//                    CRLVerifier.verifyCertificateCRLs((X509Certificate) cert[0], new Date(), null);
//                }catch(Exception e)
//                {
//                    e.printStackTrace();
//                    LogSystem.error(e.toString());
//                    jsonFile.put("error", e.toString());
//                    return null;
//                }
//            }
//
//            try
//            {
//                if (Float.compare(ry, ly) < 0)
//                {
//                    ly = Float.parseFloat(userSignBulk.get(i).getSigPosURY());
//                    ry = Float.parseFloat(userSignBulk.get(i).getSigPosLLY());
//                }
//
//                LogSystem.info("Signing " + i + "/" + userSignBulk.size());
//                LogSystem.info("Process signing page "+userSignBulk.get(i).getSigpage());
//                float width = rx - lx;
//                float height = ry - ly;
//
//                LogSystem.info("Width "+ width);
//                LogSystem.info("Height "+ height);
//
//                if(userSignBulk.get(i).getType().equals("initials"))
//                {
//                    nameField = userSign.getCertificate().getName().replace(".", " ").trim() + " Initial : [INTID" + userSignBulk.get(i).getSignID()+"]";
//                    LogSystem.info("Field Name " + nameField);
//                }
//                else
//                {
//                    nameField = userSignBulk.get(i).getCertificate().getName().replace(".", " ").trim() + " Signature : [DSID" + userSignBulk.get(i).getSignID()+"]";
//                    LogSystem.info("Field Name " + nameField);
//                    if(!userSignBulk.get(i).getType().equals("seal"))
//                    {
//                        if (width < 130) {
//                            width = 130;
//                            height = 73;
//
//                            LogSystem.info("Resize to default width " + width);
//                            LogSystem.info("Resize to default height " + height);
//                        }
//                    }
//                }
//
//                Rectangle2D humanRect = new Rectangle2D.Float(lx, ry, width, height);
//
//                boolean signingProcess = signing.signPDF(inPath, destFile, humanRect, TSA, page, nameField, userSignBulk.get(i).isWithQR(), userS.getCertificate().getName().toUpperCase(), userSignBulk.get(i), jsonFile);
//
//                if (!signingProcess)
//                {
//                    return null;
//                }
//
////                inPath = new File(userSignBulk.get(i).getSignID()+".pdf");
////                LogSystem.info("Signed iteration " + inPath);
//                copyFile(destFile, inPath);
//
////                if(userSignBulk.get(i).getType().equals("seal") && !signing.getValidation())
////                {
////                    LogSystem.info("Seal process, final process to lock");
////                    signing.lockPDF(inPath, destFile,userSignBulk.get(i).getSigpage() - 1, humanRect, userSignBulk.get(i), nameField);
////                    copyFile(destFile,inPath);
////                }
//
//                LogSystem.info("Finish signing page "+userSignBulk.get(i).getSigpage());
//            }catch(Exception e)
//            {
//                LogSystem.error("Error while signing document");
//                LogSystem.error(e.toString());
//                e.printStackTrace();
//                jsonFile.put("error", e.toString());
//                return null;
//            }
//
//            LogSystem.info(userSignBulk.get(i).getSignID());
//            addTimeStamp(Long.valueOf(userSignBulk.get(i).getSignID()), signing.getDate().getTime());
//        }
//
//        if(!signing.getValidation())
//        {
//            try {
//                LogSystem.info("Process LTV");
//                LogSystem.info("dest file : " + destFile);
//                File outFile = new File(String.valueOf(destFile));
//                AddValidationInformation addValidationInformation = new AddValidationInformation();
//                LogSystem.info("Validate signature");
//                addValidationInformation.validateSignature(inPath, outFile);
//
////                            LTV check = new LTV();
//                LogSystem.info("out file : " + outFile);
//                            LogSystem.info("Check LTV");
////                            check.checkLTV(outFile);
//                            LogSystem.info("Finish LTV");
//
//            } catch (Exception e) {
//                LogSystem.error("Error Process LTV");
//                LogSystem.error(e.toString());
//                e.printStackTrace();
//                jsonFile.put("error", e.toString());
//                return null;
//            }
//        }
//        return timestamp;
//    }
//
//    private String getOutputFileName(String filePattern, boolean externallySign)
//    {
//        return MessageFormat.format(filePattern, (externallySign ? "_ext" : ""));
//    }
//
//    private static String extractOCSPURL(X509Certificate cert) throws IOException
//    {
//        byte[] authorityExtensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
//        if (authorityExtensionValue != null)
//        {
//            // copied from CertInformationHelper.getAuthorityInfoExtensionValue()
//            // DRY refactor should be done some day
//            ASN1Sequence asn1Seq = (ASN1Sequence) JcaX509ExtensionUtils.parseExtensionValue(authorityExtensionValue);
//            Enumeration<?> objects = asn1Seq.getObjects();
//            while (objects.hasMoreElements())
//            {
//                // AccessDescription
//                ASN1Sequence obj = (ASN1Sequence) objects.nextElement();
//                ASN1Encodable oid = obj.getObjectAt(0);
//                // accessLocation
//                ASN1TaggedObject location = (ASN1TaggedObject) obj.getObjectAt(1);
//                if (X509ObjectIdentifiers.id_ad_ocsp.equals(oid)
//                        && location.getTagNo() == GeneralName.uniformResourceIdentifier)
//                {
//                    ASN1OctetString url = (ASN1OctetString) location.getObject();
//                    String ocspURL = new String(url.getOctets());
////                    LogSystem.info("OCSP URL: " + ocspURL);
//                    return ocspURL;
//                }
//            }
//        }
//        return null;
//    }
//
//    private void addTimeStamp(Long id, Date tsDate) {
//        JSONObject ts=new JSONObject();
//        try {
//            ts.put("timestamp", tsDate.getTime());
//            ts.put("doc_access", id);
//            arrayTimeStamp.put(ts);
//        } catch (JSONException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//    }
//
//    public JSONArray getArrayTimeStamp() {
//        return arrayTimeStamp;
//    }
//
//    //Convert Date to Calendar
//    private Calendar dateToCalendar(Date date) {
//
//        Calendar calendar = Calendar.getInstance();
//        calendar.setTime(date);
//        return calendar;
//
//    }
//
//}

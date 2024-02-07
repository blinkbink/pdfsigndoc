package id.idtrust.signing.core.LTV;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.examples.signature.SigUtils;
import org.apache.pdfbox.examples.signature.cert.CRLVerifier;
import org.apache.pdfbox.examples.signature.cert.CertificateVerificationException;
import org.apache.pdfbox.examples.signature.cert.OcspHelper;
import org.apache.pdfbox.examples.signature.cert.RevokedCertificateException;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.util.Hex;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

public class SealValidationInformation {
    private static final Log LOG = LogFactory.getLog(SealValidationInformation.class);
    private CertInformationCollector certInformationHelper;
    private COSArray correspondingOCSPs;
    private COSArray correspondingCRLs;
    private COSDictionary vriBase;
    private COSArray ocsps;
    private COSArray crls;
    private COSArray certs;
    private final Map<X509Certificate, COSStream> certMap = new HashMap();
    private PDDocument document;
    private final Set<X509Certificate> foundRevocationInformation = new HashSet();
    private Calendar signDate;
    private final Set<X509Certificate> ocspChecked = new HashSet();

    private String errorOCSPMessage=null;

    public SealValidationInformation() {

    }

//    public void validateSignature(File inFile, File outFile) throws IOException {
//        if (inFile != null && inFile.exists()) {
//            PDDocument doc = PDDocument.load(inFile);
//            FileOutputStream fos = new FileOutputStream(outFile);
//            int accessPermissions = SigUtils.getMDPPermission(doc);
//            if (accessPermissions == 1) {
//                System.out.println("PDF is certified to forbid changes, some readers may report the document as invalid despite that the PDF specification allows DSS additions");
//            }
//
//            this.document = doc;
//            this.doValidation(inFile.getAbsolutePath(), fos);
//            fos.close();
//            doc.close();
//        } else {
//            String err = "Document for signing ";
//            if (null == inFile) {
//                err = err + "is null";
//            } else {
//                err = err + "does not exist: " + inFile.getAbsolutePath();
//            }
//
//            throw new FileNotFoundException(err);
//        }
//    }

    public void doValidation(PDSignature signature, PDDocument doc) throws IOException {
        this.certInformationHelper = new CertInformationCollector();
        CertInformationCollector.CertSignatureInformation certInfo = null;
//        this.document=doc;
        try {
//            PDSignature signature = SigUtils.getLastRelevantSignature(this.document);
            if (signature != null) {
//                certInfo = this.certInformationHelper.getCertInfoPub(cms);
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                doc.save(byteArrayOutputStream);

                InputStream inputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());

                certInfo = this.certInformationHelper.getLastCertInfoSeal(signature, inputStream);
                this.signDate = signature.getSignDate();
                if ("ETSI.RFC3161".equals(signature.getSubFilter())) {
                    byte[] contents = signature.getContents();
                    TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(contents));
                    TimeStampTokenInfo timeStampInfo = timeStampToken.getTimeStampInfo();
                    this.signDate = Calendar.getInstance();
                    this.signDate.setTime(timeStampInfo.getGenTime());
                }
            }
        } catch (CertificateProccessingException var8) {
            throw new IOException("An Error occurred processing the Signature", var8);
        } catch (CMSException var9) {
            throw new IOException("An Error occurred processing the Signature", var9);
        } catch (TSPException var10) {
            throw new IOException("An Error occurred processing the Signature", var10);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

//        if (certInfo == null) {
//            throw new IOException("No Certificate information or signature found in the given document");
//        } else {
            PDDocumentCatalog docCatalog = doc.getDocumentCatalog();
            COSDictionary catalog = docCatalog.getCOSObject();
            catalog.setNeedToBeUpdated(true);
            COSDictionary dss = (COSDictionary)getOrCreateDictionaryEntry(COSDictionary.class, catalog, "DSS");
            this.addExtensions(docCatalog);
            this.vriBase = (COSDictionary)getOrCreateDictionaryEntry(COSDictionary.class, dss, "VRI");
            this.ocsps = (COSArray)getOrCreateDictionaryEntry(COSArray.class, dss, "OCSPs");
            this.crls = (COSArray)getOrCreateDictionaryEntry(COSArray.class, dss, "CRLs");
            this.certs = (COSArray)getOrCreateDictionaryEntry(COSArray.class, dss, "Certs");
            //set ocsp url not from certificate
            certInfo.setOcspUrl(certInfo.getOcspUrl());

            this.addRevocationData(certInfo, doc);
            this.addAllCertsToCertArray(doc);
//        }
    }

    private static <T extends COSBase & COSUpdateInfo> T getOrCreateDictionaryEntry(Class<T> clazz, COSDictionary parent, String name) throws IOException {
        COSBase element = parent.getDictionaryObject(name);
        COSBase result;
        if (element != null && clazz.isInstance(element)) {
            result = (COSBase)clazz.cast(element);
            ((COSUpdateInfo)result).setNeedToBeUpdated(true);
        } else {
            if (element != null) {
                throw new IOException("Element " + name + " from dictionary is not of type " + clazz.getCanonicalName());
            }

            try {
                result = (COSBase)clazz.getDeclaredConstructor().newInstance();
            } catch (InstantiationException var6) {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), var6);
            } catch (IllegalAccessException var7) {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), var7);
            } catch (NoSuchMethodException var8) {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), var8);
            } catch (SecurityException var9) {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), var9);
            } catch (IllegalArgumentException var10) {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), var10);
            } catch (InvocationTargetException var11) {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), var11);
            }

            result.setDirect(false);
            parent.setItem(COSName.getPDFName(name), result);
        }

        return (T) result;
    }

    private void addRevocationData(CertInformationCollector.CertSignatureInformation certInfo, PDDocument doc) throws IOException {
        COSDictionary vri = new COSDictionary();
        this.vriBase.setItem(certInfo.getSignatureHash(), vri);
        this.updateVRI(certInfo, vri, doc);
        if (certInfo.getTsaCerts() != null) {
            this.correspondingOCSPs = null;
            this.correspondingCRLs = null;
            this.addRevocationDataRecursive(certInfo.getTsaCerts(), doc);
        }

    }

    private void addRevocationDataRecursive(CertInformationCollector.CertSignatureInformation certInfo, PDDocument doc) throws IOException {
        if (!certInfo.isSelfSigned()) {
            boolean isRevocationInfoFound = this.foundRevocationInformation.contains(certInfo.getCertificate());
            if (!isRevocationInfoFound) {
                if (certInfo.getOcspUrl() != null && certInfo.getIssuerCertificate() != null) {
                    isRevocationInfoFound = this.fetchOcspData(certInfo, doc);
                }

                if (!isRevocationInfoFound && certInfo.getCrlUrl() != null) {
                    this.fetchCrlData(certInfo, doc);
                    isRevocationInfoFound = true;
                }

                if (certInfo.getOcspUrl() == null && certInfo.getCrlUrl() == null) {
                    LOG.info("No revocation information for cert " + certInfo.getCertificate().getSubjectX500Principal());
                } else if (!isRevocationInfoFound) {
                    throw new IOException("Could not fetch Revocation Info for Cert: " + certInfo.getCertificate().getSubjectX500Principal());
                }
            }

            if (certInfo.getAlternativeCertChain() != null) {
                this.addRevocationDataRecursive(certInfo.getAlternativeCertChain(), doc);
            }

            if (certInfo.getCertChain() != null && certInfo.getCertChain().getCertificate() != null) {
                this.addRevocationDataRecursive(certInfo.getCertChain(), doc);
            }

        }
    }

    private boolean fetchOcspData(CertInformationCollector.CertSignatureInformation certInfo, PDDocument doc) throws IOException {
        try {
            this.addOcspData(certInfo, doc);
            return true;
        } catch (OCSPException var3) {
            LOG.error("Failed fetching OCSP at " + certInfo.getOcspUrl(), var3);
            this.setErrorOCSPMessage("Failed fetching OCSP at " + certInfo.getOcspUrl() + " " + var3);
            return false;
        } catch (CertificateProccessingException var4) {
            LOG.error("Failed fetching OCSP at " + certInfo.getOcspUrl(), var4);
            this.setErrorOCSPMessage("Failed fetching OCSP at " + certInfo.getOcspUrl() + " " + var4);
            return false;
        } catch (IOException var5) {
            LOG.error("Failed fetching OCSP at " + certInfo.getOcspUrl(), var5);
            this.setErrorOCSPMessage("Failed fetching OCSP at " + certInfo.getOcspUrl() + " " + var5);
            return false;
        } catch (RevokedCertificateException var6) {
            throw new IOException(var6);
        }
    }

    private void fetchCrlData(CertInformationCollector.CertSignatureInformation certInfo, PDDocument doc) throws IOException {
        try {
            this.addCrlRevocationInfo(certInfo, doc);
        } catch (GeneralSecurityException var3) {
            LOG.warn("Failed fetching CRL", var3);
            throw new IOException(var3 + " OCSP : " + this.getErrorOCSPMessage());
        } catch (RevokedCertificateException var4) {
            LOG.warn("Failed fetching CRL", var4);
            throw new IOException(var4 + " OCSP : " + this.getErrorOCSPMessage());
        } catch (IOException var5) {
            LOG.warn("Failed fetching CRL", var5);
            throw new IOException(var5 + " OCSP : " + this.getErrorOCSPMessage());
        } catch (CertificateVerificationException var6) {
            LOG.warn("Failed fetching CRL", var6);
            throw new IOException(var6 + " OCSP : " + this.getErrorOCSPMessage());
        }
    }

    private void addOcspData(CertInformationCollector.CertSignatureInformation certInfo, PDDocument doc) throws IOException, OCSPException, CertificateProccessingException, RevokedCertificateException {
        if (!this.ocspChecked.contains(certInfo.getCertificate())) {
            OcspHelper ocspHelper = new OcspHelper(certInfo.getCertificate(), this.signDate.getTime(), certInfo.getIssuerCertificate(), new HashSet(this.certInformationHelper.getCertificateSet()), certInfo.getOcspUrl());
            OCSPResp ocspResp = ocspHelper.getResponseOcsp();
            this.ocspChecked.add(certInfo.getCertificate());
            BasicOCSPResp basicResponse = (BasicOCSPResp)ocspResp.getResponseObject();
            X509Certificate ocspResponderCertificate = ocspHelper.getOcspResponderCertificate();
            this.certInformationHelper.addAllCertsFromHolders(basicResponse.getCerts());

            byte[] signatureHash;
            try {
                BEROctetString encodedSignature = new BEROctetString(basicResponse.getSignature());
                signatureHash = MessageDigest.getInstance("SHA-1").digest(encodedSignature.getEncoded());
            } catch (NoSuchAlgorithmException var12) {
                throw new CertificateProccessingException(var12);
            }

            String signatureHashHex = Hex.getString(signatureHash);
            if (!this.vriBase.containsKey(signatureHashHex)) {
                COSArray savedCorrespondingOCSPs = this.correspondingOCSPs;
                COSArray savedCorrespondingCRLs = this.correspondingCRLs;
                COSDictionary vri = new COSDictionary();
                this.vriBase.setItem(signatureHashHex, vri);
                CertInformationCollector.CertSignatureInformation ocspCertInfo = this.certInformationHelper.getCertInfo(ocspResponderCertificate);
                this.updateVRI(ocspCertInfo, vri, doc);
                this.correspondingOCSPs = savedCorrespondingOCSPs;
                this.correspondingCRLs = savedCorrespondingCRLs;
            }

            byte[] ocspData = ocspResp.getEncoded();
            COSStream ocspStream = this.writeDataToStream(ocspData, doc);
            this.ocsps.add(ocspStream);
            if (this.correspondingOCSPs != null) {
                this.correspondingOCSPs.add(ocspStream);
            }

            this.foundRevocationInformation.add(certInfo.getCertificate());
        }
    }

    private void addCrlRevocationInfo(CertInformationCollector.CertSignatureInformation certInfo, PDDocument doc) throws IOException, RevokedCertificateException, GeneralSecurityException, CertificateVerificationException {
        X509CRL crl = CRLVerifier.downloadCRLFromWeb(certInfo.getCrlUrl());
        X509Certificate issuerCertificate = certInfo.getIssuerCertificate();
        Iterator var4 = this.certInformationHelper.getCertificateSet().iterator();

        while(var4.hasNext()) {
            X509Certificate certificate = (X509Certificate)var4.next();
            if (certificate.getSubjectX500Principal().equals(crl.getIssuerX500Principal())) {
                issuerCertificate = certificate;
                break;
            }
        }

        crl.verify(issuerCertificate.getPublicKey(), SecurityProvider.getProvider().getName());
        CRLVerifier.checkRevocation(crl, certInfo.getCertificate(), this.signDate.getTime(), certInfo.getCrlUrl());
        COSStream crlStream = this.writeDataToStream(crl.getEncoded(), doc);
        this.crls.add(crlStream);
        if (this.correspondingCRLs != null) {
            this.correspondingCRLs.add(crlStream);

            byte[] signatureHash;
            try {
                BEROctetString berEncodedSignature = new BEROctetString(crl.getSignature());
                signatureHash = MessageDigest.getInstance("SHA-1").digest(berEncodedSignature.getEncoded());
            } catch (NoSuchAlgorithmException var13) {
                throw new CertificateVerificationException(var13.getMessage(), var13);
            }

            String signatureHashHex = Hex.getString(signatureHash);
            if (!this.vriBase.containsKey(signatureHashHex)) {
                COSArray savedCorrespondingOCSPs = this.correspondingOCSPs;
                COSArray savedCorrespondingCRLs = this.correspondingCRLs;
                COSDictionary vri = new COSDictionary();
                this.vriBase.setItem(signatureHashHex, vri);

                CertInformationCollector.CertSignatureInformation crlCertInfo;
                try {
                    crlCertInfo = this.certInformationHelper.getCertInfo(issuerCertificate);
                } catch (CertificateProccessingException var12) {
                    throw new CertificateVerificationException(var12.getMessage(), var12);
                }

                this.updateVRI(crlCertInfo, vri, doc);
                this.correspondingOCSPs = savedCorrespondingOCSPs;
                this.correspondingCRLs = savedCorrespondingCRLs;
            }
        }

        this.foundRevocationInformation.add(certInfo.getCertificate());
    }

    private void updateVRI(CertInformationCollector.CertSignatureInformation certInfo, COSDictionary vri, PDDocument doc) throws IOException {
        if (certInfo.getCertificate().getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) == null) {
            this.correspondingOCSPs = new COSArray();
            this.correspondingCRLs = new COSArray();
            this.addRevocationDataRecursive(certInfo, doc);
            if (this.correspondingOCSPs.size() > 0) {
                vri.setItem("OCSP", this.correspondingOCSPs);
            }

            if (this.correspondingCRLs.size() > 0) {
                vri.setItem("CRL", this.correspondingCRLs);
            }
        }

        COSArray correspondingCerts = new COSArray();
        CertInformationCollector.CertSignatureInformation ci = certInfo;

        do {
            X509Certificate cert = ci.getCertificate();

            try {
                COSStream certStream = this.writeDataToStream(cert.getEncoded(), doc);
                correspondingCerts.add(certStream);
                this.certMap.put(cert, certStream);
            } catch (CertificateEncodingException var7) {
                LOG.error(var7, var7);
            }

            if (cert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) != null) {
                break;
            }

            ci = ci.getCertChain();
        } while(ci != null);

        vri.setItem(COSName.CERT, correspondingCerts);
        vri.setDate(COSName.TU, Calendar.getInstance());
    }

    private void addAllCertsToCertArray(PDDocument doc) throws IOException {
        Iterator var1 = this.certInformationHelper.getCertificateSet().iterator();

        while(var1.hasNext()) {
            X509Certificate cert = (X509Certificate)var1.next();
            if (!this.certMap.containsKey(cert)) {
                try {
                    COSStream certStream = this.writeDataToStream(cert.getEncoded(), doc);
                    this.certMap.put(cert, certStream);
                } catch (CertificateEncodingException var4) {
                    throw new IOException(var4);
                }
            }
        }

        var1 = this.certMap.values().iterator();

        while(var1.hasNext()) {
            COSStream certStream = (COSStream)var1.next();
            this.certs.add(certStream);
        }

    }

    private COSStream writeDataToStream(byte[] data, PDDocument doc) throws IOException {
        COSStream stream = doc.getDocument().createCOSStream();
        OutputStream os = null;

        try {
            os = stream.createOutputStream(COSName.FLATE_DECODE);
            os.write(data);
        } finally {
            IOUtils.closeQuietly(os);
        }

        return stream;
    }

    private void addExtensions(PDDocumentCatalog catalog) {
        COSDictionary dssExtensions = new COSDictionary();
        dssExtensions.setDirect(true);
        catalog.getCOSObject().setItem("Extensions", dssExtensions);
        COSDictionary adbeExtension = new COSDictionary();
        adbeExtension.setDirect(true);
        dssExtensions.setItem("ADBE", adbeExtension);
        adbeExtension.setName("BaseVersion", "1.7");
        adbeExtension.setInt("ExtensionLevel", 5);
        catalog.setVersion("1.7");
    }

    public String getErrorOCSPMessage() {
        return errorOCSPMessage;
    }

    public void setErrorOCSPMessage(String errorOCSPMessage) {
        this.errorOCSPMessage = errorOCSPMessage;
    }

    private static void usage() {
        System.err.println("usage: java " + org.apache.pdfbox.examples.signature.validation.AddValidationInformation.class.getName() + " <pdf_to_add_ocsp>\n");
    }
}

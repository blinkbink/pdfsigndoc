package id.idtrust.signing.core.LTV;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.examples.signature.SigUtils;
import org.apache.pdfbox.examples.signature.cert.CertificateVerifier;
import id.idtrust.signing.core.LTV.CertInformationHelper;
import id.idtrust.signing.core.LTV.CertificateProccessingException;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

public class CertInformationCollector {
    private static final Log LOG = LogFactory.getLog(CertInformationCollector.class);
    private static final int MAX_CERTIFICATE_CHAIN_DEPTH = 5;
    private final Set<X509Certificate> certificateSet = new HashSet();
    private final Set<String> urlSet = new HashSet();
    private final JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
    private CertInformationCollector.CertSignatureInformation rootCertInfo;
    private String rootErrorMessage=null;


    public String getRootErrorMessage() {
        return rootErrorMessage;
    }

    public void setRootErrorMessage(String rootErrorMessage) {
        this.rootErrorMessage = rootErrorMessage;
    }

    public CertInformationCollector() {
    }

    public CertInformationCollector.CertSignatureInformation getLastCertInfo(PDSignature signature, String fileName) throws CertificateProccessingException, IOException {
        FileInputStream documentInput = null;

        CertInformationCollector.CertSignatureInformation var5;
        try {
            documentInput = new FileInputStream(fileName);
            System.out.println(documentInput);
            byte[] signatureContent = signature.getContents(documentInput);
            var5 = this.getCertInfo(signatureContent);
        } finally {
            IOUtils.closeQuietly(documentInput);
        }

        return var5;
    }

    public CertInformationCollector.CertSignatureInformation getLastCertInfoSeal(PDSignature signature, InputStream fileIn) throws CertificateProccessingException, Exception {
        CertInformationCollector.CertSignatureInformation var5;
        try {
            byte[] signatureContent = signature.getContents(fileIn);
            var5 = this.getCertInfo(signatureContent);
        }catch(Exception e)
        {
            e.printStackTrace();
            throw new Exception("Failed get certificate info");
        }

        return var5;
    }

    public CertInformationCollector.CertSignatureInformation getCertInfoPub(byte[] signatureContent) throws CertificateProccessingException, IOException {
        this.rootCertInfo = new CertInformationCollector.CertSignatureInformation();
        this.rootCertInfo.signatureHash = CertInformationHelper.getSha1Hash(signatureContent);

        try {
            CMSSignedData signedData = new CMSSignedData(signatureContent);
            SignerInformation signerInformation = this.processSignerStore(signedData, this.rootCertInfo);
            this.addTimestampCerts(signerInformation);
        } catch (CMSException var4) {
            LOG.error("Error occurred getting Certificate Information from Signature", var4);
            throw new CertificateProccessingException(var4);
        }

        return this.rootCertInfo;
    }

    private CertInformationCollector.CertSignatureInformation getCertInfo(byte[] signatureContent) throws CertificateProccessingException, IOException {
        this.rootCertInfo = new CertInformationCollector.CertSignatureInformation();
        this.rootCertInfo.signatureHash = CertInformationHelper.getSha1Hash(signatureContent);

        try {
            CMSSignedData signedData = new CMSSignedData(signatureContent);
            SignerInformation signerInformation = this.processSignerStore(signedData, this.rootCertInfo);
            this.addTimestampCerts(signerInformation);
        } catch (CMSException var4) {
            LOG.error("Error occurred getting Certificate Information from Signature", var4);
            throw new CertificateProccessingException(var4);
        }

        return this.rootCertInfo;
    }

    private void addTimestampCerts(SignerInformation signerInformation) throws IOException, CertificateProccessingException {
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes != null) {
            Attribute tsAttribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            if (tsAttribute != null) {
                ASN1Encodable obj0 = tsAttribute.getAttrValues().getObjectAt(0);
                if (obj0 instanceof ASN1Object) {
                    ASN1Object tsSeq = (ASN1Object)obj0;

                    try {
                        CMSSignedData signedData = new CMSSignedData(tsSeq.getEncoded("DER"));
                        this.rootCertInfo.tsaCerts = new CertInformationCollector.CertSignatureInformation();
                        this.processSignerStore(signedData, this.rootCertInfo.tsaCerts);
                    } catch (CMSException var7) {
                        throw new IOException("Error parsing timestamp token", var7);
                    }
                }
            }
        }
    }

    private SignerInformation processSignerStore(CMSSignedData signedData, CertInformationCollector.CertSignatureInformation certInfo) throws IOException, CertificateProccessingException {
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        SignerInformation signerInformation = (SignerInformation)signers.iterator().next();
        Store<X509CertificateHolder> certificatesStore = signedData.getCertificates();
        Collection<X509CertificateHolder> matches = certificatesStore.getMatches(signerInformation.getSID());
        X509Certificate certificate = this.getCertFromHolder((X509CertificateHolder)matches.iterator().next());
        this.certificateSet.add(certificate);
        Collection<X509CertificateHolder> allCerts = certificatesStore.getMatches((Selector)null);
        this.addAllCerts(allCerts);
        this.traverseChain(certificate, certInfo, 5);
        return signerInformation;
    }

    private void traverseChain(X509Certificate certificate, CertInformationCollector.CertSignatureInformation certInfo, int maxDepth) throws IOException, CertificateProccessingException {
        certInfo.certificate = certificate;
        byte[] authorityExtensionValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (authorityExtensionValue != null) {
            CertInformationHelper.getAuthorityInfoExtensionValue(authorityExtensionValue, certInfo);
        }

        if (certInfo.issuerUrl != null) {
            this.getAlternativeIssuerCertificate(certInfo, maxDepth);
        }

        byte[] crlExtensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlExtensionValue != null) {
            certInfo.crlUrl = CertInformationHelper.getCrlUrlFromExtensionValue(crlExtensionValue);
        }

        try {
            certInfo.isSelfSigned = CertificateVerifier.isSelfSigned(certificate);
        } catch (GeneralSecurityException var9) {
            throw new CertificateProccessingException(var9);
        }

        if (maxDepth > 0 && !certInfo.isSelfSigned) {
            Iterator var6 = this.certificateSet.iterator();

            while(var6.hasNext()) {
                X509Certificate issuer = (X509Certificate)var6.next();

                try {
                    certificate.verify(issuer.getPublicKey(), SecurityProvider.getProvider().getName());
                    LOG.info("Found the right Issuer Cert! for Cert: " + certificate.getSubjectX500Principal() + "\n" + issuer.getSubjectX500Principal());
                    certInfo.issuerCertificate = issuer;
                    certInfo.certChain = new CertInformationCollector.CertSignatureInformation();
                    this.traverseChain(issuer, certInfo.certChain, maxDepth - 1);
                    break;
                } catch (GeneralSecurityException var10) {
                }
            }

            if (certInfo.issuerCertificate == null) {
                throw new IOException("No Issuer Certificate found for Cert: '" + certificate.getSubjectX500Principal() + "', i.e. Cert '" + certificate.getIssuerX500Principal() + "' is missing in the chain");
            }
        }
    }

    private void getAlternativeIssuerCertificate(CertInformationCollector.CertSignatureInformation certInfo, int maxDepth) throws CertificateProccessingException {
        if (!this.urlSet.contains(certInfo.issuerUrl)) {
            this.urlSet.add(certInfo.issuerUrl);
            LOG.info("Get alternative issuer certificate from: " + certInfo.issuerUrl);

            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream in = SigUtils.openURL(certInfo.issuerUrl);
                X509Certificate altIssuerCert = (X509Certificate)certFactory.generateCertificate(in);
                this.certificateSet.add(altIssuerCert);
                certInfo.alternativeCertChain = new CertInformationCollector.CertSignatureInformation();
                this.traverseChain(altIssuerCert, certInfo.alternativeCertChain, maxDepth - 1);
                in.close();
            } catch (IOException var6) {
                LOG.error("Error getting alternative issuer certificate from " + certInfo.issuerUrl, var6);
            } catch (CertificateException var7) {
                LOG.error("Error getting alternative issuer certificate from " + certInfo.issuerUrl, var7);
            }

        }
    }

    private X509Certificate getCertFromHolder(X509CertificateHolder certificateHolder) throws CertificateProccessingException {
        try {
            return this.certConverter.getCertificate(certificateHolder);
        } catch (CertificateException var3) {
            LOG.error("Certificate Exception getting Certificate from certHolder.", var3);
            throw new CertificateProccessingException(var3);
        }
    }

    private void addAllCerts(Collection<X509CertificateHolder> certHolders) {
        Iterator var2 = certHolders.iterator();

        while(var2.hasNext()) {
            X509CertificateHolder certificateHolder = (X509CertificateHolder)var2.next();

            try {
                X509Certificate certificate = this.getCertFromHolder(certificateHolder);
                this.certificateSet.add(certificate);
            } catch (CertificateProccessingException var5) {
                LOG.warn("Certificate Exception getting Certificate from certHolder.", var5);
            }
        }

    }

    public void addAllCertsFromHolders(X509CertificateHolder[] certHolders) throws CertificateProccessingException {
        this.addAllCerts(Arrays.asList(certHolders));
    }

    CertInformationCollector.CertSignatureInformation getCertInfo(X509Certificate certificate) throws CertificateProccessingException {
        try {
            CertInformationCollector.CertSignatureInformation certSignatureInformation = new CertInformationCollector.CertSignatureInformation();
            this.traverseChain(certificate, certSignatureInformation, 5);
            return certSignatureInformation;
        } catch (IOException var3) {
            throw new CertificateProccessingException(var3);
        }
    }

    public Set<X509Certificate> getCertificateSet() {
        return this.certificateSet;
    }

    public static class CertSignatureInformation {
        private X509Certificate certificate;
        private String signatureHash;
        private boolean isSelfSigned = false;
        private String ocspUrl;
        private String crlUrl;
        private String issuerUrl;
        private X509Certificate issuerCertificate;
        private CertInformationCollector.CertSignatureInformation certChain;
        private CertInformationCollector.CertSignatureInformation tsaCerts;
        private CertInformationCollector.CertSignatureInformation alternativeCertChain;

        public CertSignatureInformation() {
        }

        public String getOcspUrl() {
            return this.ocspUrl;
        }

        public void setOcspUrl(String ocspUrl) {
            this.ocspUrl = ocspUrl;
        }

        public void setIssuerUrl(String issuerUrl) {
            this.issuerUrl = issuerUrl;
        }

        public String getCrlUrl() {
            return this.crlUrl;
        }

        public X509Certificate getCertificate() {
            return this.certificate;
        }

        public boolean isSelfSigned() {
            return this.isSelfSigned;
        }

        public X509Certificate getIssuerCertificate() {
            return this.issuerCertificate;
        }

        public String getSignatureHash() {
            return this.signatureHash;
        }

        public CertInformationCollector.CertSignatureInformation getCertChain() {
            return this.certChain;
        }

        public CertInformationCollector.CertSignatureInformation getTsaCerts() {
            return this.tsaCerts;
        }

        public CertInformationCollector.CertSignatureInformation getAlternativeCertChain() {
            return this.alternativeCertChain;
        }
    }
}

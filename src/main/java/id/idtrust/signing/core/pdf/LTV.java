package id.idtrust.signing.core.pdf;

import id.idtrust.signing.util.LogSystem;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.util.Hex;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;
import org.junit.Assert;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;


public class LTV {

    private static CertificateFactory certificateFactory = null;

    public void checkLTV(File outFile)
            throws IOException, GeneralSecurityException, OCSPException, OperatorCreationException,
            CMSException
    {
        Security.addProvider(SecurityProvider.getProvider());
        certificateFactory = CertificateFactory.getInstance("X.509");

        PDDocument doc = PDDocument.load(outFile);

        PDSignature signature = doc.getLastSignatureDictionary();
        byte[] contents = signature.getContents();

        PDDocumentCatalog docCatalog = doc.getDocumentCatalog();
        COSDictionary dssDict = docCatalog.getCOSObject().getCOSDictionary(COSName.getPDFName("DSS"));
        COSArray dssCertArray = dssDict.getCOSArray(COSName.getPDFName("Certs"));
        COSDictionary vriDict = dssDict.getCOSDictionary(COSName.getPDFName("VRI"));

        // Check that all known signature certificates are in the VRI/signaturehash/Cert array
        byte[] signatureHash = MessageDigest.getInstance("SHA-1").digest(contents);
        String hexSignatureHash = Hex.getString(signatureHash);
        LogSystem.info("hexSignatureHash: " + hexSignatureHash);
        CMSSignedData signedData = new CMSSignedData(contents);
        Store<X509CertificateHolder> certificatesStore = signedData.getCertificates();
        HashSet<X509CertificateHolder> certificateHolderSet =
                new HashSet<X509CertificateHolder>(certificatesStore.getMatches(null));
        COSDictionary sigDict = vriDict.getCOSDictionary(COSName.getPDFName(hexSignatureHash));
        COSArray sigCertArray = sigDict.getCOSArray(COSName.getPDFName("Cert"));
        Set<X509CertificateHolder> sigCertHolderSetFromVRIArray = new HashSet<X509CertificateHolder>();
        for (int i = 0; i < sigCertArray.size(); ++i)
        {
            COSStream certStream = (COSStream) sigCertArray.getObject(i);
            InputStream is = certStream.createInputStream();
            sigCertHolderSetFromVRIArray.add(new X509CertificateHolder(IOUtils.toByteArray(is)));
            is.close();
        }
        for (X509CertificateHolder holder : certificateHolderSet)
        {
            if (holder.getSubject().toString().contains("QuoVadis OCSP Authority Signature"))
            {
                continue; // not relevant here
            }
            // disabled until PDFBOX-5203 is fixed
//            Assert.assertTrue("File '" + outFile + "' Root/DSS/VRI/" + hexSignatureHash +
//                    "/Cert array doesn't contain a certificate with subject '" +
//                    holder.getSubject() + "' and serial " + holder.getSerialNumber(),
//                    sigCertHolderSetFromVRIArray.contains(holder));
        }

        // Get all certificates. Each one should either be issued (= signed) by a certificate of the set
        Set<X509Certificate> certSet = new HashSet<X509Certificate>();
        for (int i = 0; i < dssCertArray.size(); ++i)
        {

            COSStream certStream = (COSStream) dssCertArray.getObject(i);
            InputStream is = certStream.createInputStream();
            X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(is);
            is.close();
            certSet.add(cert);
        }
        for (X509Certificate cert : certSet)
        {
            boolean verified = false;
            for (X509Certificate cert2 : certSet)
            {
                try
                {
                    cert.verify(cert2.getPublicKey(), SecurityProvider.getProvider().getName());
                    verified = true;
                }
                catch (GeneralSecurityException ex)
                {
                    // not the issuer
                }
            }
            // disabled until PDFBOX-5203 is fixed
//            Assert.assertTrue("Certificate " + cert.getSubjectX500Principal() +
//                    " not issued by any certificate in the Certs array", verified);
        }

        // Each CRL should be signed by one of the certificates in Certs
        Set<X509CRL> crlSet = new HashSet<X509CRL>();
        COSArray crlArray = dssDict.getCOSArray(COSName.getPDFName("CRLs"));
        for (int i = 0; i < crlArray.size(); ++i)
        {
            COSStream crlStream = (COSStream) crlArray.getObject(i);
            InputStream is = crlStream.createInputStream();
            X509CRL cert = (X509CRL) certificateFactory.generateCRL(is);
            is.close();
            crlSet.add(cert);
        }
        for (X509CRL crl : crlSet)
        {
            boolean crlVerified = false;
            X509Certificate crlIssuerCert = null;
            for (X509Certificate cert : certSet)
            {
                try
                {
                    crl.verify(cert.getPublicKey(), SecurityProvider.getProvider().getName());
                    crlVerified = true;
                    crlIssuerCert = cert;
                }
                catch (GeneralSecurityException ex)
                {
                    // not the issuer
                }
            }
            Assert.assertTrue("issuer of CRL not found in Certs array", crlVerified);

            byte[] crlSignatureHash = MessageDigest.getInstance("SHA-1").digest(crl.getSignature());
            String hexCrlSignatureHash = Hex.getString(crlSignatureHash);
            LogSystem.info("hexCrlSignatureHash: " + hexCrlSignatureHash);

            // Check that the issueing certificate is in the VRI array
            COSDictionary crlSigDict = vriDict.getCOSDictionary(COSName.getPDFName(hexCrlSignatureHash));
            COSArray certArray2 = crlSigDict.getCOSArray(COSName.getPDFName("Cert"));
            COSStream certStream = (COSStream) certArray2.getObject(0);
            InputStream is2 = certStream.createInputStream();
            X509CertificateHolder certHolder2 = new X509CertificateHolder(IOUtils.toByteArray(is2));
            is2.close();

            Assert.assertEquals("CRL issuer certificate missing in VRI " + hexCrlSignatureHash,
                    certHolder2, new X509CertificateHolder(crlIssuerCert.getEncoded()));
        }

        Set<OCSPResp> oscpSet = new HashSet<OCSPResp>();
        COSArray ocspArray = dssDict.getCOSArray(COSName.getPDFName("OCSPs"));
        for (int i = 0; i < ocspArray.size(); ++i)
        {
            COSStream ocspStream = (COSStream) ocspArray.getObject(i);
            InputStream is = ocspStream.createInputStream();
            OCSPResp ocspResp = new OCSPResp(is);
            is.close();
            oscpSet.add(ocspResp);
        }
        for (OCSPResp ocspResp : oscpSet)
        {
            BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
            Assert.assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspResp.getStatus());
            Assert.assertTrue("OCSP should have at least 1 certificate", basicResponse.getCerts().length >= 1);
            byte[] ocspSignatureHash = MessageDigest.getInstance("SHA-1").digest(basicResponse.getSignature());
            String hexOcspSignatureHash = Hex.getString(ocspSignatureHash);
            LogSystem.info("ocspSignatureHash: " + hexOcspSignatureHash);
            long secondsOld = (System.currentTimeMillis() - basicResponse.getProducedAt().getTime()) / 1000;
            Assert.assertTrue("OCSP answer is too old, is from " + secondsOld + " seconds ago",
                    secondsOld < 10);

            X509CertificateHolder ocspCertHolder = basicResponse.getCerts()[0];
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().setProvider(SecurityProvider.getProvider()).build(ocspCertHolder);
            Assert.assertTrue(basicResponse.isSignatureValid(verifier));

            COSDictionary ocspSigDict = vriDict.getCOSDictionary(COSName.getPDFName(hexOcspSignatureHash));

            // Check that the Cert is in the VRI array
            COSArray certArray2 = ocspSigDict.getCOSArray(COSName.getPDFName("Cert"));
            COSStream certStream = (COSStream) certArray2.getObject(0);
            InputStream is2 = certStream.createInputStream();
            X509CertificateHolder certHolder2 = new X509CertificateHolder(IOUtils.toByteArray(is2));
            is2.close();

            Assert.assertEquals("OCSP certificate is not in the VRI array", certHolder2, ocspCertHolder);
        }

        doc.close();
    }
}
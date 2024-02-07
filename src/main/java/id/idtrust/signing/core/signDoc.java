package id.idtrust.signing.core;

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import id.idtrust.signing.core.LTV.AddValidationInformation;
import id.idtrust.signing.core.LTV.CertInformationCollector;
import id.idtrust.signing.core.LTV.SealValidationInformation;
import id.idtrust.signing.core.certificate.PKCS7Signer;
import id.idtrust.signing.core.pdf.CMSProcessableInputStream;
import id.idtrust.signing.core.pdf.DssHelper;
import id.idtrust.signing.core.pdf.GetOcspResp;
import id.idtrust.signing.util.Description;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.examples.signature.CreateSignatureBase;
import org.apache.pdfbox.examples.signature.SigUtils;
import org.apache.pdfbox.examples.signature.ValidationTimeStamp;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.*;
import org.apache.pdfbox.util.Matrix;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONException;
import org.json.JSONObject;

import javax.net.ssl.*;
import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import id.idtrust.signing.core.ValidationTimeStampWithAuth;

/**
 * This is a second example for visual signing a pdf. It doesn't use the "design pattern" influenced
 * PDVisibleSignDesigner, and doesn't create its complex multilevel forms described in the Adobe
 * document
 * <a href="https://www.adobe.com/content/dam/acom/en/devnet/acrobat/pdfs/PPKAppearances.pdf">Digital
 * Signature Appearances</a>, because this isn't required by the PDF specification. See the
 * discussion in December 2017 in PDFBOX-3198.
 *
 * @author Vakhtang Koroghlishvili
 * @author Tilman Hausherr
 */

public class signDoc extends CreateSignatureBase
{
    private SignatureOptions signatureOptions;
    private Calendar signDate;
    private boolean lateExternalSigning = false;
    private File imageFile = null;
    private String keyAlias = null;
    private String reason;
    private String location;
    private String name;
    private String externalsigning=null;
    private int accessPermissions;
    private int status_code=0;

    private COSDictionary vriBase;
    private COSArray ocsps;
    private COSArray crls;
    private COSArray certs;

    private static final Logger logger = LogManager.getLogger();
    static Description ds = new Description();

    Certificate[] certificateChain = null;
    String tsaURL=null;

    boolean error=false;
    String throwMessage = null;
    PDDocument doc = null;

    Boolean doValidation=false;

    public static final COSName COS_NAME_LOCK = COSName.getPDFName("Lock");
    public static final COSName COS_NAME_ACTION = COSName.getPDFName("Action");
    public static final COSName COS_NAME_ALL = COSName.getPDFName("All");
    public static final COSName COS_NAME_SIG_FIELD_LOCK = COSName.getPDFName("SigFieldLock");

    public Boolean getDoValidation() {
        return doValidation;
    }

    public void setDoValidation(Boolean doValidation) {
        this.doValidation = doValidation;
    }

    public String getExternalsigning() {
        return externalsigning;
    }

    public void setExternalsigning(String externalsigning) {
        this.externalsigning = externalsigning;
    }

    public int getAccessPermissions() {
        return accessPermissions;
    }

    public void setAccessPermissions(int accessPermissions) {
        this.accessPermissions = accessPermissions;
    }

    public boolean isError() {
        return error;
    }

    public void setError(boolean error) {
        this.error = error;
    }

    public String getThrowMessage() {
        return throwMessage;
    }

    public void setThrowMessage(String throwMessage) {
        if(this.throwMessage == null)
        {
            this.throwMessage = throwMessage;
        }
    }

    public int getStatus_code() {
        return status_code;
    }

    public void setStatus_code(int status_code) {
        this.status_code = status_code;
    }

    /**
     * Initialize the signature creator with a keystore (pkcs12) and pin that
     * should be used for the signature.
     *
//     * @param keystore is a pkcs12 keystore.
//     * @param pin is the pin for the keystore / private key
     * @throws KeyStoreException if the keystore has not been initialized (loaded)
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     * @throws CertificateException if the certificate is not valid as signing time
     * @throws IOException if no certificate could be found
     */

//    public signDoc(KeyStore keystore, char[] pin)
//            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException
//    {
//        super(keystore, pin);
//    }


    public void setReason(String reason) {
        this.reason = reason;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public void setName(String name) {
        this.name = name;
    }

    public signDoc(Certificate[] certificates, PrivateKey privateKey)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException
    {
        super(certificates, null);
        this.keyAlias = keyAlias;
        this.certificateChain = certificates;
    }

    public signDoc(Certificate[] certificates, String keyAlias)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException
    {
        super(certificates, null);
        this.keyAlias = keyAlias;
        this.certificateChain = certificates;
    }

    public File getImageFile()
    {
        return imageFile;
    }

    public void setImageFile(File imageFile)
    {
        this.imageFile = imageFile;
    }

    public boolean isLateExternalSigning()
    {
        return lateExternalSigning;
    }


    public void setTsaURL(String tsaURL)
    {
        this.tsaURL = tsaURL;
    }
    /**
     * Set late external signing. Enable this if you want to activate the demo code where the
     * signature is kept and added in an extra step without using PDFBox methods. This is disabled
     * by default.
     *
     * @param lateExternalSigning
     */
    public void setLateExternalSigning(boolean lateExternalSigning)
    {
        this.lateExternalSigning = lateExternalSigning;
    }

    /**
     * Sign pdf file and create new file that ends with "_signed.pdf".
     *
     * @param inputFile The source pdf document file.
     * @param signedFile The file to be signed.
     * @param humanRect rectangle from a human viewpoint (coordinates start at top left)
     * @param tsaUrl optional TSA url
     * @throws IOException
     */
    public void signPDF(File inputFile,File signedFile, Rectangle2D humanRect, String tsaUrl, Rectangle2D humanRect2) throws Exception {
        this.signPDF(inputFile, signedFile, humanRect, tsaUrl, null, 0);
    }


    private File checkDocForSeal(File inputFile, File signedFile, Rectangle2D humanRect, String tsaUrl, String signatureFieldName, int page) throws IOException {
        String tmpFile=signedFile.getAbsolutePath().replace(".pdf", "-tmp.pdf");
        FileOutputStream fos = new FileOutputStream(tmpFile);

        // creating output document and prepare the IO streams.
        doc = PDDocument.load(inputFile);
        PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm(null);
        int accessPermissions = SigUtils.getMDPPermission(doc);
        if (accessPermissions == 1) {
            setStatus_code(403);
            throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }

        if (acroForm==null){
            return inputFile;
        }
        int sizeSignature = acroForm.getFields().size();
        if(sizeSignature==0){
            doc.close();
            return inputFile;
        }else{

            COSObject fields = acroForm.getCOSObject().getCOSObject(COSName.FIELDS);
            if (fields != null)
                fields.setNeedToBeUpdated(true);

            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            OutputStream result = new FileOutputStream(new File(tmpFile));
            PDPage pdPage = doc.getPage(page);
            // Create empty signature field, it will get the name "Signature1"
            PDSignatureField signatureField = new PDSignatureField(acroForm);

            //check doc seal 2 but having lock dict
            System.out.println("ACCESS : " + accessPermissions);
            COSBase lock = signatureField.getCOSObject().getItem(signDoc.COS_NAME_LOCK);
            System.out.println("Lock : " + lock);
            if(accessPermissions == 2)
            {
                throw new IllegalStateException("Document has Locked");
            }

            COSDictionary lockDict = new COSDictionary();
            lockDict.setItem(signDoc.COS_NAME_ACTION, signDoc.COS_NAME_ALL);
            lockDict.setItem(COSName.TYPE, signDoc.COS_NAME_SIG_FIELD_LOCK);
            signatureField.getCOSObject().setItem(signDoc.COS_NAME_LOCK, lockDict);
            signatureField.setPartialName(signatureFieldName);
            signatureField.getCOSObject().setNeedToBeUpdated(true);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            widget.setRectangle(this.createSignatureRectangle(doc,humanRect,page));
            widget.getCOSObject().setNeedToBeUpdated(true);
            widget.setPage(pdPage);
            pdPage.getAnnotations().add(widget);
            pdPage.getCOSObject().setNeedToBeUpdated(true);
            acroForm.getFields().add(signatureField);
            doc.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
            doc.saveIncremental(result);
            result.close();
            doc.close();

            return new File(tmpFile);
        }

    }
    /**
     * Sign pdf file and create new file that ends with "_signed.pdf".
     *
     * @param inputFile The source pdf document file.
     * @param signedFile The file to be signed.
     * @param humanRect rectangle from a human viewpoint (coordinates start at top left)
     * @param tsaUrl optional TSA url
     * @param signatureFieldName optional name of an existing (unsigned) signature field
     * @throws IOException
     */
    public void signPDF(File inputFile, File signedFile, Rectangle2D humanRect, String tsaUrl, String signatureFieldName, int page) throws Exception {
        try {
            if (inputFile == null) {
                throw new IOException("Document for signing does not exist");
            }

            setTsaUrl(tsaUrl);

            FileOutputStream fos = new FileOutputStream(signedFile);
            if(this.accessPermissions==1){
                inputFile=checkDocForSeal(inputFile,signedFile,humanRect,tsaUrl,signatureFieldName,page);
            }
            // creating output document and prepare the IO streams.
            doc = PDDocument.load(inputFile);

            // call SigUtils.checkCrossReferenceTable(doc) if Adobe complains
            // and read https://stackoverflow.com/a/71293901/535646
            // and https://issues.apache.org/jira/browse/PDFBOX-5382

            int accessPermissions = SigUtils.getMDPPermission(doc);
            if (accessPermissions == 1) {
                setStatus_code(403);
                throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
            }
            // Note that PDFBox has a bug that visual signing on certified files with permission 2
            // doesn't work properly, see PDFBOX-3699. As long as this issue is open, you may want to
            // be careful with such files.

            PDSignature signature = null;
            PDSignatureField signatureField = null;
            PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm(null);
            PDRectangle rect = null;

            // sign a PDF with an existing empty signature, as created by the CreateEmptySignatureForm example.
            int sizeSignature = 0;
            if (acroForm != null) {
                sizeSignature = acroForm.getFields().size();
//                String defaultSignatureField = "Signature1";
                signatureField = findExistingSignature(acroForm, signatureFieldName);
                if (signatureField != null) {
                    signature=signatureField.getSignature();
                    rect = acroForm.getField(signatureFieldName).getWidgets().get(0).getRectangle();
                }
            }

            if (signature == null) {
                // create signature dictionary
                signature = new PDSignature();
            }

            if (rect == null) {
                rect = createSignatureRectangle(doc, humanRect, page);
            }

            // Optional: certify
            // can be done only if version is at least 1.5 and if not already set
            // doing this on a PDF/A-1b file fails validation by Adobe preflight (PDFBOX-3821)
            // PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such files.
            boolean isLock = false;
            if (doc.getVersion() >= 1.5f && accessPermissions == 0) {
                //signature not exist on document
                if(sizeSignature < 1)
                {
                    if(this.accessPermissions == 1)
                    {
                        SigUtils.setMDPPermission(doc, signature, this.accessPermissions);
                    }
                }
                else
                {
                    //signature exist on document
                    if(this.accessPermissions == 1 && signatureField != null)
                    {
                        this.accessPermissions =2;
                        setDoValidation(true);
                        isLock = true;
                        COSBase lock = signatureField.getCOSObject().getDictionaryObject(COS_NAME_LOCK);
                        if (lock instanceof COSDictionary)
                        {
                            COSDictionary lockDict = new COSDictionary();
                            lockDict.setItem(COS_NAME_ACTION, COS_NAME_ALL);
                            lockDict.setItem(COSName.TYPE, COS_NAME_SIG_FIELD_LOCK);

                            COSDictionary transformParams = new COSDictionary(lockDict);
                            transformParams.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
                            transformParams.setItem(COSName.V, COSName.getPDFName("1.2"));
                            transformParams.setInt(COSName.P, 1);

                            transformParams.setDirect(true);
                            transformParams.setNeedToBeUpdated(true);

                            COSDictionary sigRef = new COSDictionary();
                            sigRef.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
                            sigRef.setItem(COSName.getPDFName("TransformParams"), transformParams);
                            sigRef.setItem(COSName.getPDFName("TransformMethod"), COSName.getPDFName("FieldMDP"));
                            sigRef.setItem(COSName.getPDFName("Data"), doc.getDocumentCatalog());
                            sigRef.setDirect(true);
                            COSArray referenceArray = new COSArray();
                            referenceArray.add(sigRef);
                            signature.getCOSObject().setItem(COSName.getPDFName("Reference"), referenceArray);
                            System.out.println("LOCK DICTIONARY");

                            final Predicate<PDField> shallBeLocked;
                            final COSArray fields = lockDict.getCOSArray(COSName.FIELDS);
                            final List<String> fieldNames = fields == null ? Collections.emptyList() :
                                    fields.toList().stream().filter(c -> (c instanceof COSString)).map(s -> ((COSString)s).getString()).collect(Collectors.toList());
                            final COSName action = lockDict.getCOSName(COSName.getPDFName("Action"));
                            if (action.equals(COSName.getPDFName("Include"))) {
                                shallBeLocked = f -> fieldNames.contains(f.getFullyQualifiedName());
                            } else if (action.equals(COSName.getPDFName("Exclude"))) {
                                shallBeLocked = f -> !fieldNames.contains(f.getFullyQualifiedName());
                            } else if (action.equals(COSName.getPDFName("All"))) {
                                shallBeLocked = f -> true;
                            } else { // unknown action, lock nothing
                                shallBeLocked = f -> false;
                            }
                            lockFields(doc.getDocumentCatalog().getAcroForm().getFields(), shallBeLocked);
                            setMDPPermission(doc, signature,2);
                        }
                    }
                }
            }

            if(this.accessPermissions == 1 && doc.getVersion() < 1.5f)
            {
                setStatus_code(403);
                throw new Exception("Not supported seal with document version < 1.5");
            }

            if (acroForm != null && acroForm.getNeedAppearances()) {
                // PDFBOX-3738 NeedAppearances true results in visible signature becoming invisible
                // with Adobe Reader
                if (acroForm.getFields().isEmpty()) {
                    // we can safely delete it if there are no fields
                    acroForm.getCOSObject().removeItem(COSName.NEED_APPEARANCES);
                    // note that if you've set MDP permissions, the removal of this item
                    // may result in Adobe Reader claiming that the document has been changed.
                    // and/or that field content won't be displayed properly.
                    // ==> decide what you prefer and adjust your code accordingly.
                } else {
                    System.out.println("/NeedAppearances is set, signature may be ignored by Adobe Reader");
                }
            }

            // default filter
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);

            // subfilter for basic and PAdES Part 2 signatures
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

            X509Certificate cert = (X509Certificate) getCertificateChain()[0];

            // https://stackoverflow.com/questions/2914521/
            X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());
            RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
            String name = IETFUtils.valueToString(cn.getFirst().getValue());

            signature.setName(name);
            signature.setLocation(this.location);
            signature.setReason(this.reason);

            // the signing date, needed for valid signature
            signature.setSignDate(Calendar.getInstance());

            // do not set SignatureInterface instance, if external signing used
            SignatureInterface signatureInterface = isExternalSigning() ? null : this;

            if(this.accessPermissions == 1 && !isLock)
            {
                try {
                    makeLTV();
                } catch (Exception e) {
                    throw new Exception(e.toString());
                }
            }

            // register signature dictionary and sign interface
            signatureOptions = new SignatureOptions();
            signatureOptions.setVisualSignature(createVisualSignatureTemplate(doc, page, rect, false, signature));

            signatureOptions.setPage(page);
            signatureOptions.setPreferredSignatureSize(200000);
            doc.addSignature(signature, signatureInterface, signatureOptions);

            doc.getDocumentCatalog().getAcroForm().getField(doc.getDocumentCatalog().getAcroForm().getFields().get(doc.getDocumentCatalog().getAcroForm().getFields().size() - 1).getPartialName()).setPartialName(signatureFieldName);

            if (isExternalSigning()) {
                ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(fos);
                // invoke external signature service
                byte[] cmsSignature = IOUtils.toByteArray(externalSigning.getContent());

//            byte[] cmsSignature = sign(externalSigning.getContent());

                // Explanation of late external signing (off by default):
                // If you want to add the signature in a separate step, then set an empty byte array
                // and call signature.getByteRange() and remember the offset signature.getByteRange()[1]+1.
                // you can write the ascii hex signature at a later time even if you don't have this
                // PDDocument object anymore, with classic java file random access methods.
                // If you can't remember the offset value from ByteRange because your context has changed,
                // then open the file with PDFBox, find the field with findExistingSignature() or
                // PDDocument.getLastSignatureDictionary() and get the ByteRange from there.
                // Close the file and then write the signature as explained earlier in this comment.
                String sgn = null;
                try {
                    try {
                        //hit to external signing just once
                        sgn = signingProcess(cmsSignature);

                    } catch (Exception e) {
                        e.printStackTrace();
                        setThrowMessage(e.toString());
                        throw new Exception(e.toString());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    doc.close();
                }

                // set signature bytes received from the service
                if (sgn != null) {
                    externalSigning.setSignature(attachSignature(sgn));

//                    if(this.accessPermissions == 1)
//                    {
//                        SealValidationInformation sealValidation = new SealValidationInformation();
//                        try {
//                            sealValidation.doValidation(signature, doc);
//                        } catch (Exception e) {
//                            e.printStackTrace();
//                            throw new Exception(e.toString());
//                        }
//                    }
                }
            } else {
                // write incremental (only for signing purpose)
                doc.saveIncremental(fos);
            }

        }catch(Exception e)
        {
            e.printStackTrace();
            throw new Exception(e.toString());
        }
        finally {
            doc.close();
            IOUtils.closeQuietly(signatureOptions);
        }

        // Do not close signatureOptions before saving, because some COSStream objects within
        // are transferred to the signed document.
        // Do not allow signatureOptions get out of scope before saving, because then the COSDocument
        // in signature options might by closed by gc, which would close COSStream objects prematurely.
        // See https://issues.apache.org/jira/browse/PDFBOX-3743
    }

    public byte[] attachSignature(String signature) throws OperatorCreationException, CMSException, IOException, NoSuchAlgorithmException, CertificateEncodingException, Exception {
        final byte[] signedHash = Base64.decode(signature);
        Certificate cert = getCertificateChain()[0];
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner nonSigner = new ContentSigner() {

            @Override
            public byte[] getSignature() {
                return signedHash;
            }

            @Override
            public OutputStream getOutputStream() {
                return new ByteArrayOutputStream();
            }

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHRSAANDMGF1");
            }
        };

        org.bouncycastle.asn1.x509.Certificate cert2 = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));
        JcaSignerInfoGeneratorBuilder sigb = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());


        sigb.setDirectSignature(true);
        gen.addSignerInfoGenerator(sigb.build(nonSigner, new X509CertificateHolder(cert2)));
        gen.addCertificates(new JcaCertStore(Arrays.asList(getCertificateChain())));

        CMSTypedData msg = new CMSProcessableInputStream(new ByteArrayInputStream("not used".getBytes()));

        CMSSignedData signedData = gen.generate((CMSTypedData) msg, false);

        if (this.tsaURL != null) {
            ValidationTimeStampWithAuth validation = new ValidationTimeStampWithAuth(this.tsaURL, null, null);

            signedData = validation.addSignedTimeStamp(signedData);
            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Added timestamp");

        }

        return signedData.getEncoded();

    }

    public PDRectangle createSignatureRectangle(PDDocument doc, Rectangle2D humanRect, int pageNum)
    {
        float x = (float) humanRect.getX();
//        float y = (float) humanRect.getY();

        float width = (float) humanRect.getWidth();
        float height = (float) humanRect.getHeight();
        PDPage page = doc.getPage(pageNum);
        PDRectangle pageRect = page.getCropBox();
        PDRectangle rect = new PDRectangle();

        float y = pageRect.getHeight() - (float) humanRect.getY();
        logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Page " + pageNum + " Rotation " + page.getRotation());


        // signing should be at the same position regardless of page rotation.
        switch (page.getRotation())
        {
            case 90:
                rect.setLowerLeftY(x);
                rect.setUpperRightY(x + width);
                rect.setLowerLeftX(y);
                rect.setUpperRightX(y + height);
                break;
            case 180:
                rect.setUpperRightX(pageRect.getWidth() - x);
                rect.setLowerLeftX(pageRect.getWidth() - x - width);
                rect.setLowerLeftY(y);
                rect.setUpperRightY(y + height);
                break;
            case 270:
                rect.setLowerLeftY(pageRect.getHeight() - x - width);
                rect.setUpperRightY(pageRect.getHeight() - x);
                rect.setLowerLeftX(pageRect.getWidth() - y - height);
                rect.setUpperRightX(pageRect.getWidth() - y);
                break;
            case 0:
            default:
                rect.setLowerLeftX(x);
                rect.setUpperRightX(x + width);
                rect.setLowerLeftY(pageRect.getHeight() - y - height);
                rect.setUpperRightY(pageRect.getHeight() - y);
                break;
        }
        return rect;
    }

    // create a template PDF document with empty signature and return it as a stream.
    private InputStream createVisualSignatureTemplate(PDDocument srcDoc, int pageNum,
                                                      PDRectangle rect, boolean isLock, PDSignature signature) throws IOException
    {
        PDDocument doc = new PDDocument();

        PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
        doc.addPage(page);
        PDAcroForm acroForm = new PDAcroForm(doc);
        doc.getDocumentCatalog().setAcroForm(acroForm);
        PDSignatureField signatureField = new PDSignatureField(acroForm);

        PDAnnotationWidget widget = signatureField.getWidgets().get(0);

        List<PDField> acroFormFields = acroForm.getFields();
        acroForm.setSignaturesExist(true);
        acroForm.setAppendOnly(true);
        acroForm.getCOSObject().setDirect(true);
        acroFormFields.add(signatureField);

        widget.setRectangle(rect);

        // from PDVisualSigBuilder.createHolderForm()
        PDStream stream = new PDStream(doc);
        PDFormXObject form = new PDFormXObject(stream);
        PDResources res = new PDResources();
        form.setResources(res);
        form.setFormType(1);
        PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
        float height = bbox.getHeight();
        Matrix initialScale = null;
        switch (srcDoc.getPage(pageNum).getRotation())
        {
            case 90:
                form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                height = bbox.getWidth();
                break;
            case 180:
                form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
                break;
            case 270:
                form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
                initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                height = bbox.getWidth();
                break;
            case 0:
            default:
                break;
        }

        form.setBBox(bbox);
        PDFont font = PDType1Font.HELVETICA_BOLD;

        // from PDVisualSigBuilder.createAppearanceDictionary()
        PDAppearanceDictionary appearance = new PDAppearanceDictionary();
        appearance.getCOSObject().setDirect(true);
        PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
        appearance.setNormalAppearance(appearanceStream);
        widget.setAppearance(appearance);

        PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream);

        // for 90° and 270° scale ratio of width / height
        // not really sure about this
        // why does scale have no effect when done in the form matrix???
        if (initialScale != null)
        {
            cs.transform(initialScale);
        }
//
//        // show background (just for debugging, to see the rect size + position)
//        cs.setNonStrokingColor(Color.yellow);
//        cs.addRect(-5000, -5000, 10000, 10000);
//        cs.fill();

        if (imageFile != null)
        {
            // show background image
            // save and restore graphics if the image is too large and needs to be scaled
            Dimension scaledDim = null;
            // save and restore graphics if the image is too large and needs to be scaled
            cs.saveGraphicsState();
            if (initialScale == null) {
                cs.transform(Matrix.getScaleInstance(1.0f, 1.0f));
            }
            PDImageXObject img = PDImageXObject.createFromFileByExtension(imageFile, doc);
            PDImageXObject img2 = PDImageXObject.createFromFileByExtension(imageFile, doc);

            int x = 0;
            int y = 0;
            int x2 = 0;
            int y2 = 0;

            scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getWidth(), (int) rect.getHeight()), 0);
            x = ((int) rect.getWidth() - scaledDim.width) / 2;
            y = ((int) rect.getHeight() - scaledDim.height) / 2;


            cs.drawImage(img, x, y, scaledDim.width, scaledDim.height);

            cs.restoreGraphicsState();
        }

        cs.close();

        // no need to set annotations and /P entry
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        doc.save(baos);
        doc.close();
        return new ByteArrayInputStream(baos.toByteArray());
    }

    // Find an existing signature (assumed to be empty). You will usually not need this.
    private PDSignatureField findExistingSignature(PDAcroForm acroForm, String sigFieldName)
    {
        PDSignature signature = null;
        PDSignatureField signatureField=null;
        if (acroForm != null)
        {
            signatureField = (PDSignatureField) acroForm.getField(sigFieldName);
            if (signatureField != null)
            {
                // retrieve signature dictionary
                signature = signatureField.getSignature();
                if (signature == null)
                {
                    signature = new PDSignature();
                    // after solving PDFBOX-3524
                    // signatureField.setValue(signature)
                    // until then:
                    signatureField.getCOSObject().setItem(COSName.V, signature);
                }
                else
                {
                    throw new IllegalStateException("The signature field " + sigFieldName + " is already signed.");
                }
            }
        }
        return signatureField;
    }

    TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1)
                throws CertificateException {
            // TODO Auto-generated method stub

        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1)
                throws CertificateException {
            // TODO Auto-generated method stub

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            // TODO Auto-generated method stub
            return null;
        }
    }
    };


    public String signingProcess(byte[] data) throws Exception {
        URL url = null;

        try {

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);

            SSLContext ctx = SSLContext.getInstance("TLS");
//            ctx.init(new KeyManager[0], new TrustManager[] {new DefaultTrustManager()}, new SecureRandom());
            ctx.init(new KeyManager[0], trustAllCerts, new java.security.SecureRandom());
//            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            Description ds = new Description();
            url = new URL("http://192.168.16.14:8091/api/sign/hash");
//            url = new URL("http://"+ds.EXTERNAL_SIGNING_URL+":"+ds.EXTERNAL_SIGNING_PORT+"/api/sign/hash");

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            conn.setChunkedStreamingMode(0);
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(240000);

            String base64Data = Base64.toBase64String(hash);
//            String input = "{\"keyAlias\":\"" + keyAlias + "\", \"data\":\"" + base64Data + "\"}";

            PKCS7Signer signer = new PKCS7Signer();
            KeyStore keyStore = signer.loadKeyStore();
            CMSSignedDataGenerator signatureGenerator = signer.setUpProvider(keyStore);
            String content = "{\"keyAlias\":\""+keyAlias+"\", \"data\":\""+base64Data+"\"}";
            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Content " + content.toString());
            byte[] signedBytes = signer.signPkcs7(content.getBytes("UTF-8"), signatureGenerator);
            String datatosend=new String(Base64.encode(signedBytes));
            JSONObject json =new JSONObject();
            json.put("data",datatosend);

            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Input to signing hash " + json.toString());

            OutputStream os = conn.getOutputStream();
            os.write(json.toString().getBytes());
            os.flush();
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            String output;
            String response = "";

            while ((output = br.readLine()) != null) {
                response += output;
            }
            conn.disconnect();

            JSONObject rspJSON = new JSONObject(response);

            setExternalsigning(rspJSON.getString("signature"));

            return rspJSON.getString("signature");

        } catch (IOException | NoSuchAlgorithmException | JSONException | KeyManagementException e) {

            e.printStackTrace();
            throw new Exception(e.toString() + " " + url);
        } catch (Exception e2) {
                    e2.printStackTrace();
            throw new Exception(e2.toString() + " " + url);
        }
    }


    private void makeLTV() throws Exception {
        try {
            COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
            catalogDict.setNeedToBeUpdated(true);
            byte[][] certs = new byte[certificateChain.length][];
            for (int i = 0; i < certificateChain.length; i++) {
                certs[i] = certificateChain[i].getEncoded();
            }
            // Assign byte array for storing certificate in DSS Store.
            List<CRL> crlList = new ArrayList<CRL>();
            List<OCSPResp> ocspList = new ArrayList<OCSPResp>();
            for (int i = 0; i < certificateChain.length; i++) {
                X509Certificate cert = (X509Certificate) certificateChain[i];
                if (!cert.getIssuerDN().equals(cert.getSubjectDN())) {
                    X509Certificate issuerCert = (X509Certificate) certificateChain[i + 1];
                    if (issuerCert != null) {
                        OCSPResp ocspResp;
                        ocspResp = new GetOcspResp().getOcspResp(cert, issuerCert);
                        if (ocspResp != null) {
                            ocspList.add(ocspResp);
                        }
                    }

                    crlList.addAll(new DssHelper().readCRLsFromCert(cert));
                }
            }
            byte[][] crls = new byte[crlList.size()][];
            for (int i = 0; i < crlList.size(); i++) {
                crls[i] = ((X509CRL) crlList.get(i)).getEncoded();
                logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : set CRL data");
            }
            byte[][] ocsps = new byte[ocspList.size()][];
            for (int i = 0; i < ocspList.size(); i++) {
                ocsps[i] = ocspList.get(i).getEncoded();
            }
            Iterable<byte[]> certifiates = Arrays.asList(certs);
            COSDictionary dss = new DssHelper().createDssDictionary(certifiates, Arrays.asList(crls),
                    Arrays.asList(ocsps));
            catalogDict.setItem(COSName.getPDFName("DSS"), dss);

        } catch (Exception e) {
            // TODO Auto-generated catch block

            e.printStackTrace();
            throw new Exception(e.toString());
        }
    }

    public static Dimension getScaledDimension(Dimension imgSize, Dimension boundary, int angle) {

        int original_width = imgSize.width;
        int original_height = imgSize.height;
        int bound_width = boundary.width;
        int bound_height = boundary.height;
        int new_width = original_width;
        int new_height = original_height;

        // first check if we need to scale width
        if (original_width > bound_width) {
            //scale width to fit
            new_width = bound_width;
            //scale height to maintain aspect ratio
            new_height = (new_width * original_height) / original_width;
        }

        // then check if we need to scale even with the new height
        if (new_height > bound_height) {
            //scale height to fit instead
            new_height = bound_height;
            //scale width to maintain aspect ratio
            new_width = (new_height * original_width) / original_height;
        }


        return new Dimension(new_width, new_height);
    }

    public static void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions)
            throws IOException {

        COSDictionary sigDict = signature.getCOSObject();

        // DocMDP specific stuff
        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem(COSName.TYPE, COSName.TRANSFORM_PARAMS);
        transformParameters.setInt(COSName.P, accessPermissions);
        transformParameters.setName(COSName.V, "1.2");
        transformParameters.setNeedToBeUpdated(true);

        COSDictionary referenceDict = new COSDictionary();
        referenceDict.setItem(COSName.TYPE, COSName.SIG_REF);
        referenceDict.setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP);
        referenceDict.setItem(COSName.DIGEST_METHOD, COSName.getPDFName("SHA1"));
        referenceDict.setItem(COSName.TRANSFORM_PARAMS, transformParameters);
        referenceDict.setNeedToBeUpdated(true);

        COSArray referenceArray = new COSArray();
        referenceArray.add(referenceDict);
        sigDict.setItem(COSName.REFERENCE, referenceArray);
        referenceArray.setNeedToBeUpdated(true);

        // Catalog
        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
        COSDictionary permsDict = new COSDictionary();
        catalogDict.setItem(COSName.PERMS, permsDict);
        permsDict.setItem(COSName.DOCMDP, signature);
        catalogDict.setNeedToBeUpdated(true);
        permsDict.setNeedToBeUpdated(true);
    }

    boolean lockFields(List<PDField> fields, Predicate<PDField> shallBeLocked) {
        boolean isUpdated = false;
        if (fields != null) {
            for (PDField field : fields) {
                boolean isUpdatedField = false;
                if (shallBeLocked.test(field)) {
                    field.setFieldFlags(field.getFieldFlags() | 1);
                    if (field instanceof PDTerminalField) {
                        for (PDAnnotationWidget widget : ((PDTerminalField)field).getWidgets())
                            widget.setLocked(true);
                    }
                    isUpdatedField = true;
                }
                if (field instanceof PDNonTerminalField) {
                    if (lockFields(((PDNonTerminalField)field).getChildren(), shallBeLocked))
                        isUpdatedField = true;
                }
                if (isUpdatedField) {
                    field.getCOSObject().setNeedToBeUpdated(true);
                    isUpdated = true;
                }
            }
        }
        return isUpdated;
    }
}

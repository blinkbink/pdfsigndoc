//package id.idtrust.signing.core.pdf;
//
//import java.awt.*;
//import java.awt.geom.AffineTransform;
//import java.awt.geom.Rectangle2D;
//import java.io.*;
//import java.net.HttpURLConnection;
//import java.net.MalformedURLException;
//import java.net.URL;
//import java.security.*;
//import java.security.cert.*;
//import java.security.cert.Certificate;
//import java.text.SimpleDateFormat;
//import java.util.*;
//import java.util.List;
//import java.util.function.Predicate;
//import java.util.stream.Collectors;
//
//import id.idtrust.signing.util.Description;
//import id.idtrust.signing.util.encryption.AESEncryption;
////import org.apache.pdfbox.Loader;
//import org.apache.pdfbox.cos.*;
////import org.apache.pdfbox.examples.signature.CreateSignatureBase;
//import org.apache.pdfbox.examples.signature.SigUtils;
//import org.apache.pdfbox.examples.signature.ValidationTimeStamp;
//import org.apache.pdfbox.examples.signature.CreateSignatureBase;
//import org.apache.pdfbox.io.IOUtils;
//import org.apache.pdfbox.pdmodel.*;
//import org.apache.pdfbox.pdmodel.common.PDRectangle;
//import org.apache.pdfbox.pdmodel.common.PDStream;
//import org.apache.pdfbox.pdmodel.font.PDFont;
//import org.apache.pdfbox.pdmodel.font.PDType1Font;
//import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
//import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
//import org.apache.pdfbox.pdmodel.interactive.annotation.*;
//import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
//import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
//import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
//import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
//import org.apache.pdfbox.pdmodel.interactive.form.*;
//import org.apache.pdfbox.util.Matrix;
//import org.bouncycastle.asn1.ASN1Primitive;
//import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
//import org.bouncycastle.cert.X509CertificateHolder;
//import org.bouncycastle.cert.jcajce.JcaCertStore;
//import org.bouncycastle.cert.ocsp.OCSPResp;
//import org.bouncycastle.cms.*;
//import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
//import org.bouncycastle.operator.ContentSigner;
//import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
//import org.bouncycastle.operator.OperatorCreationException;
//import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
//import org.bouncycastle.util.encoders.Base64;
//import org.json.JSONException;
//import org.json.JSONObject;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.net.ssl.*;
//
//
//
//import static org.aspectj.util.FileUtil.copyFile;
//
///**
// * This is a second example for visual signing a pdf. It doesn't use the "design pattern" influenced
// * PDVisibleSignDesigner, and doesn't create its complex multilevel forms described in the Adobe
// * document
// * <a href="https://www.adobe.com/content/dam/acom/en/devnet/acrobat/pdfs/PPKAppearances.pdf">Digital
// * Signature Appearances</a>, because this isn't required by the PDF specification. See the
// * discussion in December 2017 in PDFBOX-3198.
// *
// * @author Vakhtang Koroghlishvili
// * @author Tilman Hausherr
// */
//public class Signing extends CreateSignatureBase {
//    private SignatureOptions signatureOptions;
//    private boolean lateExternalSigning = false;
//    private File imageFile = null;
//    private Calendar signDate;
//    private File qrFile = null;
//    private File logoFile = null;
//    private String keyAlias = null;
//    private String tsaUrl = null;
//    private Boolean validation = false;
//
//    Certificate[] certificateChain = null;
//    PDDocument doc = null;
//    PDDocument newDocument = null;
//
//    public static final COSName COS_NAME_LOCK = COSName.getPDFName("Lock");
//    public static final COSName COS_NAME_ACTION = COSName.getPDFName("Action");
//    public static final COSName COS_NAME_ALL = COSName.getPDFName("All");
//    public static final COSName COS_NAME_SIG_FIELD_LOCK = COSName.getPDFName("SigFieldLock");
//
//
//    public static final COSName COS_NAME_INCLUDE = COSName.getPDFName("Include");
//    public static final COSName COS_NAME_EXCLUDE = COSName.getPDFName("Exclude");
//    public static final COSName COS_NAME_FIELDS = COSName.getPDFName("Fields");
//
//    Description ds = new Description();
//
//
//    //    /**
////     * Initialize the signature creator with a keystore (pkcs12) and pin that
////     * should be used for the signature.
////     *
////     * @param keystore is a pkcs12 keystore.
////     * @param pin is the pin for the keystore / private key
////     * @throws KeyStoreException if the keystore has not been initialized (loaded)
////     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
////     * @throws UnrecoverableKeyException if the given password is wrong
////     * @throws CertificateException if the certificate is not valid as signing time
////     * @throws IOException if no certificate could be found
////     */
//    public Signing(Certificate[] certChain, PrivateKey privateKey)
//            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException {
//
//        super(certChain, privateKey);
//    }
//
//    public Signing(Certificate[] certificateChain, String keyAlias) throws UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
//        super(certificateChain, null);
//        this.keyAlias = AESEncryption.decryptAlias(keyAlias);
//        this.certificateChain = certificateChain;
//    }
//
////    public CreateVisibleSignature2(KeyStore keystore, char[] pin)
////            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException
////    {
////        super(keystore, pin);
////    }
//
//    public File getImageFile() {
//        return imageFile;
//    }
//
//    public Boolean getValidation() {
//        return validation;
//    }
//
//    public void setValidation(Boolean setLTV) {
//        this.validation = setLTV;
//    }
//
//    public void setImageFile(File imageFile) {
//        this.imageFile = imageFile;
//    }
//
//    public void setDate(Calendar signDate) {
//        this.signDate = signDate;
//    }
//
//    public Calendar getDate() {
//        return signDate;
//    }
//
//    public void setQRFile(File qrFile) {
//        this.qrFile = qrFile;
//    }
//
//    public void setLogoFile(File logoFile) {
//        this.logoFile = logoFile;
//    }
//
//    public boolean isLateExternalSigning() {
//        return lateExternalSigning;
//    }
//
//    /**
//     * Set late external signing. Enable this if you want to activate the demo code where the
//     * signature is kept and added in an extra step without using PDFBox methods. This is disabled
//     * by default.
//     *
//     * @param lateExternalSigning
//     */
//    public void setLateExternalSigning(boolean lateExternalSigning) {
//        this.lateExternalSigning = lateExternalSigning;
//    }
//
//    /**
//     * Sign pdf file and create new file that ends with "_signed.pdf".
//     *
//     * @param inputFile The source pdf document file.
//     * @param signedFile The file to be signed.
//    //     * @param humanRect rectangle from a human viewpoint (coordinates start at top left)
//     * @param tsaUrl optional TSA url
//     * @throws IOException
//     */
////    public void signPDF(File inputFile, File signedFile, String tsaUrl, Optional<List<DocAccess>> userSignBulk) throws IOException
////    {
////        this.signPDF(inputFile, signedFile, tsaUrl, userSignBulk);
////    }
//
//    /**
//     * Sign pdf file and create new file that ends with "_signed.pdf".
//     *
//     * @param inputFile  The source pdf document file.
//     * @param signedFile The file to be signed.
//     *                   //     * @param humanRect rectangle from a human viewpoint (coordinates start at top left)
//     * @param tsaUrl     optional TSA url
//     *                   //     * @param signatureFieldName optional name of an existing (unsigned) signature field
//     * @throws IOException
//     */
//    public boolean signPDF(File inputFile, File signedFile, Rectangle2D humanRect, String tsaUrl, int page, String SignatureField, boolean isWithQR, String name, UserSignature userSignature, JSONObject jsonFile) throws Exception {
//        if (inputFile == null || !inputFile.exists()) {
//            throw new IOException("Document for signing does not exist");
//        }
//
//        if(!inputFile.canRead())
//        {
//            try {
//                jsonFile.put("error", "Can't open file is broken");
//            } catch (JSONException e) {
//                e.printStackTrace();
//                return false;
//            }
//            return false;
//        }
//
//        setTsaUrl(tsaUrl);
//        // creating output document and prepare the IO streams.
//
////        try (FileOutputStream fos = new FileOutputStream(signedFile);
////             PDDocument doc = Loader.loadPDF(inputFile)) {
//
//        // creating output document and prepare the IO streams.
//        FileOutputStream fos = new FileOutputStream(signedFile);
//
//        // load document
//        doc = PDDocument.load(inputFile);
//
//        PDDocumentInformation docInformation=doc.getDocumentInformation();
//        if(docInformation != null)
//        {
//            if(docInformation.getProducer() != null)
//            {
//                String producer = docInformation.getProducer().toLowerCase(Locale.ROOT);
//                LogSystem.info("Producer PDF " + producer);
//
//                if(producer.contains("aspose") && doc.getSignatureDictionaries().size() == 0)
//                {
//                    LogSystem.info("Process exception producer");
//                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
//                    doc.save(bos);
//                    doc.close();
//                    doc = PDDocument.load(bos.toByteArray());
//                    bos.reset();
//                    bos.close();
//                }
//            }
//        }
//
//        try {
//            int accessPermissions = SigUtils.getMDPPermission(doc);
//            LogSystem.info("Document permission " + accessPermissions);
//            if (accessPermissions == 1) {
//                jsonFile.put("info", "No changes to the document are permitted");
//                return false;
////                throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
//            }
//            // Note that PDFBox has a bug that visual signing on certified files with permission 2
//            // doesn't work properly, see PDFBOX-3699. As long as this issue is open, you may want to
//            // be careful with such files.
//
//            PDSignature signature = null;
//            PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm(null);
//            PDRectangle rect = null;
//
//            // sign a PDF with an existing empty signature, as created by the CreateEmptySignatureForm example.
////            String defaultSignatureField = "Signature1";
////            String defaultSignatureField = SignatureField;
////            if (acroForm != null) {
////                signature = findExistingSignature(acroForm, defaultSignatureField);
////                if (signature != null) {
////                    rect = acroForm.getField(defaultSignatureField).getWidgets().get(0).getRectangle();
////                }
////            }
//
//            if (signature == null) {
//                // create signature dictionary
//                signature = new PDSignature();
//            }
//
//
//            if (rect == null) {
//                rect = createSignatureRectangle(doc, humanRect, page);
////            rect = humanRect;
//            }
//
//            if (acroForm != null && acroForm.getNeedAppearances()) {
//                // PDFBOX-3738 NeedAppearances true results in visible signature becoming invisible
//                // with Adobe Reader
//                if (acroForm.getFields().isEmpty()) {
//                    // we can safely delete it if there are no fields
//                    acroForm.getCOSObject().removeItem(COSName.NEED_APPEARANCES);
//                    // note that if you've set MDP permissions, the removal of this item
//                    // may result in Adobe Reader claiming that the document has been changed.
//                    // and/or that field content won't be displayed properly.
//                    // ==> decide what you prefer and adjust your code accordingly.
//                } else {
//                    LogSystem.info("/NeedAppearances is set, signature may be ignored by Adobe Reader");
//                }
//            }
//
//            LogSystem.info("Visible signature : " + userSignature.isVisible());
//            // register signature dictionary and sign interface
//            signatureOptions = new SignatureOptions();
//            if (userSignature.isVisible())
//            {
//                signatureOptions.setVisualSignature(createVisualSignatureTemplate(doc, page, rect, signature, isWithQR, name, userSignature.getDescOnly(), userSignature.getType(), userSignature.isVisible(), userSignature.getLevel(), SignatureField));
//            }
//            signatureOptions.setPage(page);
//            signatureOptions.setPreferredSignatureSize(200000);
//
//            // Optional: certify
//            // can be done only if version is at least 1.5 and if not already set
//            // doing this on a PDF/A-1b file fails validation by Adobe preflight (PDFBOX-3821)
//            // PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such files.
//            if (userSignature.getType().equals("seal")) {
//                if (accessPermissions != 1) {
//                    try {
//                        SigUtils.setMDPPermission(doc, signature, 1);
//                        setValidation(true);
//                    } catch (Throwable throwable) {
//
////                        setMDPPermission(doc, signature, 2);
//
//                        LogSystem.info(throwable.getMessage());
//                        LogSystem.info("Approval exist");
//
//                        //Create empty signature field
//                        PDDocument docEx = PDDocument.load(inputFile);
//                        PDAcroForm acroFormField = docEx.getDocumentCatalog().getAcroForm();
//                        acroFormField.getCOSObject().setNeedToBeUpdated(true);
//                        COSObject fields = acroFormField.getCOSObject().getCOSObject(COSName.FIELDS);
//                        if (fields != null)
//                            fields.setNeedToBeUpdated(true);
//
//                        acroFormField.setSignaturesExist(true);
//                        acroFormField.setAppendOnly(true);
//                        acroFormField.getCOSObject().setDirect(true);
//
//                        PDPage pageField = docEx.getPage(page);
//                        // Create empty signature field, it will get the name "Signature1"
//                        PDSignatureField signatureField = new PDSignatureField(acroFormField);
//
//                        PDAnnotationWidget widget = signatureField.getWidgets().get(0);
////                        PDRectangle rectField = new PDRectangle((float) humanRect.getX(), (float) humanRect.getY(), (float) humanRect.getWidth(), (float) humanRect.getHeight());
//                        PDRectangle rectField = rect;
//
//                        widget.setRectangle(rectField);
//                        widget.getCOSObject().setNeedToBeUpdated(true);
//                        widget.setPage(pageField);
//                        pageField.getAnnotations().add(widget);
//                        pageField.getCOSObject().setNeedToBeUpdated(true);
//                        acroFormField.getFields().add(signatureField);
//                        setLock(signatureField, acroFormField);
//                        docEx.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
//                        docEx.saveIncremental(fos);
//
//                        fos.close();
//                        doc.close();
//
//                        copyFile(signedFile, inputFile);
//                        //Close and replace with created empty field signature
//                        PDDocument doc = PDDocument.load(inputFile);
//
//                        LogSystem.info(doc.getDocumentCatalog().getAcroForm().getFields().get(doc.getDocumentCatalog().getAcroForm().getFields().size()-1).getPartialName());
//
////                        String newSealLock = doc.getDocumentCatalog().getAcroForm().getFields().get(doc.getDocumentCatalog().getAcroForm().getFields().size()).getPartialName();
//                        String newSealLock = doc.getDocumentCatalog().getAcroForm().getFields().get(doc.getDocumentCatalog().getAcroForm().getFields().size()-1).getPartialName();
//                        FileOutputStream fosSeal = new FileOutputStream(signedFile);
//
//                        PDSignature signatureLock = new PDSignature();
//
//                        PDSignatureField signatureFieldLoad = (PDSignatureField) doc.getDocumentCatalog().getAcroForm().getField(newSealLock);
//
//                        LogSystem.info("signatureFieldLoad " + signatureFieldLoad.getValueAsString());
//                        LogSystem.info("signaturelock " + signatureLock);
//
//                        signatureFieldLoad.setValue(signatureLock);
//
//                        COSBase lock = signatureFieldLoad.getCOSObject().getDictionaryObject(COS_NAME_LOCK);
//                        LogSystem.info("lock " + lock);
//
//                        if (lock instanceof COSDictionary) {
//                            COSDictionary lockDict = new COSDictionary();
//                            lockDict.setItem(COS_NAME_ACTION, COS_NAME_ALL);
//                            lockDict.setItem(COSName.TYPE, COS_NAME_SIG_FIELD_LOCK);
//                            lockDict.setItem(COS_NAME_ACTION, COS_NAME_EXCLUDE);
//                            lockDict.setInt(COSName.P, 1);
//
//                            COSDictionary transformParams = new COSDictionary(lockDict);
//                            transformParams.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
//                            transformParams.setItem(COSName.V, COSName.getPDFName("1.2"));
////                            transformParams.setInt(COSName.P, 1);
//
//                            transformParams.setDirect(true);
//                            transformParams.setNeedToBeUpdated(true);
//
//                            COSDictionary sigRef = new COSDictionary();
//                            sigRef.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
//                            sigRef.setItem(COSName.getPDFName("TransformParams"), transformParams);
//                            sigRef.setItem(COSName.getPDFName("TransformMethod"), COSName.getPDFName("FieldMDP"));
//                            sigRef.setItem(COSName.getPDFName("Data"), doc.getDocumentCatalog());
//                            sigRef.setDirect(true);
//                            COSArray referenceArray = new COSArray();
//                            referenceArray.add(sigRef);
//                            signatureLock.getCOSObject().setItem(COSName.getPDFName("Reference"), referenceArray);
//                            LogSystem.info("LOCK DICTIONARY");
//
//                            final Predicate<PDField> shallBeLocked;
//                            final COSArray fieldsLock = lockDict.getCOSArray(COSName.FIELDS);
//                            final List<String> fieldNames = fieldsLock == null ? Collections.emptyList() :
//                                    fieldsLock.toList().stream().filter(c -> (c instanceof COSString)).map(s -> ((COSString) s).getString()).collect(Collectors.toList());
//                            final COSName action = lockDict.getCOSName(COSName.getPDFName("Action"));
//                            if (action.equals(COSName.getPDFName("Include"))) {
//                                shallBeLocked = f -> fieldNames.contains(f.getFullyQualifiedName());
//                            } else if (action.equals(COSName.getPDFName("Exclude"))) {
//                                shallBeLocked = f -> !fieldNames.contains(f.getFullyQualifiedName());
//                            } else if (action.equals(COSName.getPDFName("All"))) {
//                                shallBeLocked = f -> true;
//                            } else { // unknown action, lock nothing
//                                shallBeLocked = f -> false;
//                            }
//                            lockFields(doc.getDocumentCatalog().getAcroForm().getFields(), shallBeLocked);
//
//                            setMDPPermission(doc, signatureLock, 2);
//
//                            // default filter
//                            signatureLock.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
//
//                            // subfilter for basic and PAdES Part 2 signatures
//                            signatureLock.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//
//                            X509Certificate certUser = (X509Certificate) certificateChain[0];
//
//                            signatureLock.setName(name);
//                            signatureLock.setLocation(userSignature.getLocation());
//                            if (userSignature.getType().equals("initials")) {
//                                this.setExternalSigning(true);
//                                signatureLock.setReason("Saya mengetahui dan mengerti dokumen ini");
//                            }
//                            if (userSignature.getType().equals("sign")) {
//                                this.setExternalSigning(true);
//                                signatureLock.setReason("Saya menyetujui menandatangani dokumen ini. Saya menyetujui semua syarat dan ketentuan yang berlaku di Digisign");
//                            }
//                            if (userSignature.getType().equals("seal")) {
//                                this.setExternalSigning(true);
//                                signatureLock.setReason(userSignature.getQrText());
//                            }
//
//                            // the signing date, needed for valid signature
//                            signatureLock.setSignDate(getDate());
//
//                            // do not set SignatureInterface instance, if external signing used
//                            SignatureInterface signatureInterface = isExternalSigning() ? null : this;
//
//                            doc.addSignature(signatureLock, signatureInterface, signatureOptions);
//
//                            doc.getDocumentCatalog().getAcroForm().getField(newSealLock).setPartialName(SignatureField);
////                            doc.getDocumentCatalog().getAcroForm().getField(doc.getDocumentCatalog().getAcroForm().getFields().get(doc.getDocumentCatalog().getAcroForm().getFields().size()-1).getPartialName()).setPartialName(SignatureField);
//                            if (isExternalSigning()) {
//                                this.tsaUrl = tsaUrl;
//
//                                ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(fosSeal);
//
//                                // invoke external signature serviceUsing fallback
//                                byte[] cmsSignature = IOUtils.toByteArray(externalSigning.getContent());
//                                String sgn = null;
//                                try {
//                                    sgn = signingProcess(cmsSignature);
////                                sgn = "j+ZiOwWlc6dvIvxmizED5/QchmCit1BhscSjaiD10tzUxrULR/xnA2JoYARoR2TpShX8jMbqOIgdf5hGHduikBIHv9QKCY+wHSIZM0BJpmcFJcugAbUI20FMg4B195Bm0V+8fGCVZ9HxGmsbsBPgg0hjiURkfcNUXRTO4Y6T1lQfQfNzzD9toJsywSLhBi2Rk8WN83k4utqU/lHDaZ2BhEz6paYbxre5G9nZjM57QZWAZaGt56sW0CpOcLs5up5k2uUHJxY5lfv3p9VpnEBeLHHyZ0V+ZFmMi43f6KeXj4e14/AXibV4Fiek6+AB9N73dlVpNr8yrLqXlNhIhwE8HQ==";
//                                } catch (Exception e) {
//                                    LogSystem.error(e.toString());
//                                    e.printStackTrace();
//                                    doc.close();
//                                    return false;
//                                }
//
//                                // set signature bytes received from the service
//                                if (sgn != null) {
//                                    externalSigning.setSignature(attachSignature(sgn));
//                                } else {
//                                    return false;
//                                }
//
//                            } else {
//                                // write incremental (only for signing purpose)
//                                doc.saveIncremental(fos);
//                            }
//                            doc.close();
//                            docEx.close();
//
//                            IOUtils.closeQuietly(signatureOptions);
//                            return true;
//                        }
//                    }
//                }
//            }
//
//            // default filter
//            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
//
//            // subfilter for basic and PAdES Part 2 signatures
//            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//
//            signature.setName(name);
//            signature.setLocation(userSignature.getLocation());
//            if (userSignature.getType().equals("initials")) {
//                this.setExternalSigning(true);
//                signature.setReason("Saya mengetahui dan mengerti dokumen ini");
//            }
//            if (userSignature.getType().equals("sign")) {
//                this.setExternalSigning(true);
//                signature.setReason("Saya menyetujui menandatangani dokumen ini. Saya menyetujui semua syarat dan ketentuan yang berlaku di Digisign");
//            }
//            if (userSignature.getType().equals("seal")) {
//                this.setExternalSigning(true);
//                signature.setReason(userSignature.getQrText());
//            }
//
//            // the signing date, needed for valid signature
//            signature.setSignDate(getDate());
//
//            // do not set SignatureInterface instance, if external signing used
//            SignatureInterface signatureInterface = isExternalSigning() ? null : this;
//
//            if (getValidation()) {
////                try {
//                    makeLTV();
////                }
////                catch(Exception e)
////                {
////                    jsonFile.put("error", e.toString());
////                    throw new Exception(e.toString());
////                }
//            }
//
//            doc.addSignature(signature, signatureInterface, signatureOptions);
//
//            doc.getDocumentCatalog().getAcroForm().getField(doc.getDocumentCatalog().getAcroForm().getFields().get(doc.getDocumentCatalog().getAcroForm().getFields().size()-1).getPartialName()).setPartialName(SignatureField);
//
//            if (isExternalSigning()) {
//                this.tsaUrl = tsaUrl;
//
//                ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(fos);
//
//                // invoke external signature service
//                byte[] cmsSignature = IOUtils.toByteArray(externalSigning.getContent());
//                String sgn = null;
//                try {
//                    sgn = signingProcess(cmsSignature);
////                sgn = "j+ZiOwWlc6dvIvxmizED5/QchmCit1BhscSjaiD10tzUxrULR/xnA2JoYARoR2TpShX8jMbqOIgdf5hGHduikBIHv9QKCY+wHSIZM0BJpmcFJcugAbUI20FMg4B195Bm0V+8fGCVZ9HxGmsbsBPgg0hjiURkfcNUXRTO4Y6T1lQfQfNzzD9toJsywSLhBi2Rk8WN83k4utqU/lHDaZ2BhEz6paYbxre5G9nZjM57QZWAZaGt56sW0CpOcLs5up5k2uUHJxY5lfv3p9VpnEBeLHHyZ0V+ZFmMi43f6KeXj4e14/AXibV4Fiek6+AB9N73dlVpNr8yrLqXlNhIhwE8HQ==";
//                } catch (Exception e) {
//                    LogSystem.error(e.toString());
//                    e.printStackTrace();
//                    doc.close();
//                    return false;
//                }
//
//                // set signature bytes received from the service
//                if (sgn != null) {
//                    externalSigning.setSignature(attachSignature(sgn));  String sgn = null;
//                    try {
//                        sgn = signingProcess(cmsSignature);
////                sgn = "j+ZiOwWlc6dvIvxmizED5/QchmCit1BhscSjaiD10tzUxrULR/xnA2JoYARoR2TpShX8jMbqOIgdf5hGHduikBIHv9QKCY+wHSIZM0BJpmcFJcugAbUI20FMg4B195Bm0V+8fGCVZ9HxGmsbsBPgg0hjiURkfcNUXRTO4Y6T1lQfQfNzzD9toJsywSLhBi2Rk8WN83k4utqU/lHDaZ2BhEz6paYbxre5G9nZjM57QZWAZaGt56sW0CpOcLs5up5k2uUHJxY5lfv3p9VpnEBeLHHyZ0V+ZFmMi43f6KeXj4e14/AXibV4Fiek6+AB9N73dlVpNr8yrLqXlNhIhwE8HQ==";
//                    } catch (Exception e) {
//                        LogSystem.error(e.toString());
//                        e.printStackTrace();
//                        doc.close();
//                        return false;
//                    }
//
//                    // set signature bytes received from the service
//                    if (sgn != null) {
//                        externalSigning.setSignature(attachSignature(sgn));
//                    } else {
//                        return false;
//                    }
//                } else {
//                    return false;
//                }
//
//            } else {
//                // write incremental (only for signing purpose)
//                doc.saveIncremental(fos);
//            }
//            doc.close();
////        } catch (CertificateEncodingException e) {
////            e.printStackTrace();
////        } catch (NoSuchAlgorithmException e) {
////            e.printStackTrace();
////        } catch (OperatorCreationException e) {
////            e.printStackTrace();
////        } catch (CMSException e) {
////            e.printStackTrace();
////        }
//
//            // Do not close signatureOptions before saving, because some COSStream objects within
//            // are transferred to the signed document.
//            // Do not allow signatureOptions get out of scope before saving, because then the COSDocument
//            // in signature options might by closed by gc, which would close COSStream objects prematurely.
//            // See https://issues.apache.org/jira/browse/PDFBOX-3743
//
//            IOUtils.closeQuietly(signatureOptions);
//            return true;
//        } catch (Exception e) {
//            doc.close();
//            LogSystem.error(e.toString());
//            e.printStackTrace();
//            throw new Exception(e.toString());
////            return false;
//        } finally {
//            doc.close();
//            IOUtils.closeQuietly(signatureOptions);
//        }
//    }
//
//    boolean lockFields(List<PDField> fields, Predicate<PDField> shallBeLocked) {
//
//        boolean isUpdated = false;
//        if (fields != null) {
//            for (PDField field : fields) {
//                boolean isUpdatedField = false;
//                if (shallBeLocked.test(field)) {
//                    field.setFieldFlags(field.getFieldFlags() | 1);
//                    if (field instanceof PDTerminalField) {
//                        for (PDAnnotationWidget widget : ((PDTerminalField) field).getWidgets()) {
//                            widget.setLocked(true);
//                            widget.setPrinted(true);
//                        }
//                    }
//                    isUpdatedField = true;
//                }
//                if (field instanceof PDNonTerminalField) {
//                    if (lockFields(((PDNonTerminalField) field).getChildren(), shallBeLocked))
//                        isUpdatedField = true;
//                }
//                if (isUpdatedField) {
//                    field.getCOSObject().setNeedToBeUpdated(true);
//                    isUpdated = true;
//                }
//            }
//        }
//        return isUpdated;
//    }
//
//    private PDRectangle createSignatureRectangle(PDDocument doc, Rectangle2D humanRect, int pageNum) {
//        float x = (float) humanRect.getX();
////        float y = (float) humanRect.getY();
//
//        float width = (float) humanRect.getWidth();
//        float height = (float) humanRect.getHeight();
//        PDPage page = doc.getPage(pageNum);
//        PDRectangle pageRect = page.getCropBox();
//
//        PDRectangle rect = new PDRectangle();
//
//        float y = pageRect.getHeight() - (float) humanRect.getY();
//        // signing should be at the same position regardless of page rotation.
//        LogSystem.info("Rotation " + page.getRotation());
//        switch (page.getRotation()) {
//            case 90:
//                y = pageRect.getWidth() - (float) humanRect.getY();
//                rect.setLowerLeftY(x);
//                rect.setUpperRightY(x + width);
//                rect.setLowerLeftX(y);
//                rect.setUpperRightX(y + height);
//
//                LogSystem.info("LX " + rect.getLowerLeftX());
//                LogSystem.info("LY " + rect.getLowerLeftY());
//                LogSystem.info("RX " + rect.getUpperRightX());
//                LogSystem.info("RY " + rect.getUpperRightY());
//                LogSystem.info("WIDTH " + rect.getWidth()); //this.getUpperRightX() - this.getLowerLeftX();
//                LogSystem.info("HEIGHT " + rect.getHeight()); //this.getUpperRightY() - this.getLowerLeftY();
//
//                break;
//            case 180:
//                rect.setUpperRightX(pageRect.getWidth() - x);
//                rect.setLowerLeftX(pageRect.getWidth() - x - width);
//                rect.setLowerLeftY(y);
//                rect.setUpperRightY(y + height);
//                break;
//            case 270:
//                y = pageRect.getWidth() - (float) humanRect.getY();
//                rect.setLowerLeftY(pageRect.getHeight() - x - width);
//                rect.setUpperRightY(pageRect.getHeight() - x);
//                rect.setLowerLeftX(pageRect.getWidth() - y - height);
//                rect.setUpperRightX(pageRect.getWidth() - y);
//                break;
//            case 0:
//            default:
//                rect.setLowerLeftX(x);
//                rect.setUpperRightX(x + width);
//                rect.setLowerLeftY(pageRect.getHeight() - y - height);
//                rect.setUpperRightY(pageRect.getHeight() - y);
//                break;
//        }
//        return rect;
//    }
//
//    // create a template PDF document with empty signature and return it as a stream.
//    private InputStream createVisualSignatureTemplate(PDDocument srcDoc, int pageNum,
//                                                      PDRectangle rect, PDSignature signature, boolean isWithQR, String name, boolean descOnly, String type, boolean visible, String level, String fieldName) throws IOException {
//        try (PDDocument doc = new PDDocument()) {
//            Date dateSign = new Date();
//            PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
//            LogSystem.info("RECT : " + rect);
//            doc.addPage(page);
//            PDAcroForm acroForm = new PDAcroForm(doc);
//
//            doc.getDocumentCatalog().setAcroForm(acroForm);
//            PDSignatureField signatureField = new PDSignatureField(acroForm);
//
//            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
//
//            List<PDField> acroFormFields = acroForm.getFields();
//
//            acroForm.setSignaturesExist(true);
//            acroForm.setAppendOnly(true);
//            acroForm.getCOSObject().setDirect(true);
//            acroFormFields.add(signatureField);
//
//            PDAppearanceCharacteristicsDictionary fieldAppearance
//                    = new PDAppearanceCharacteristicsDictionary(new COSDictionary());
//            fieldAppearance.setRotation(0);
//            widget.setAppearanceCharacteristics(fieldAppearance);
//            widget.setRectangle(rect);
//
//            widget.setPrinted(visible);
//
//            // from PDVisualSigBuilder.createHolderForm()
//            PDStream stream = new PDStream(doc);
//            PDFormXObject form = new PDFormXObject(stream);
//            PDResources res = new PDResources();
//            form.setResources(res);
//            form.setFormType(1);
//            PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
//            LogSystem.info("BBOX " + bbox);
//            float height = bbox.getHeight();
//            float width = bbox.getWidth();
//
//            LogSystem.info("Rectangle Widht " + rect.getWidth());
//            LogSystem.info("Rectangle Height " + rect.getHeight());
//
////            LogSystem.info("Rectangle box Widht " + width);
////            LogSystem.info("Rectangle box Height " + height);
////            LogSystem.info("ROTATION " + srcDoc.getPage(pageNum).getRotation());
//
//            int rotasi = srcDoc.getPage(pageNum).getRotation();
//
//            Matrix initialScale = null;
//            switch (srcDoc.getPage(pageNum).getRotation()) {
//                case 90:
////                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
////                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
////                    height = bbox.getWidth();
//                    break;
//                case 180:
//                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
//                    break;
//                case 270:
//                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
//                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
////                    height = bbox.getWidth();
//                    break;
//                case 0:
//                default:
//                    break;
//            }
//            form.setBBox(bbox);
////            PDFont font = new PDType1Font(FontName.TIMES_ROMAN);
//            PDFont font = PDType1Font.HELVETICA;
//
//            // from PDVisualSigBuilder.createAppearanceDictionary()
//            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
//            appearance.getCOSObject().setDirect(true);
//            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
//            appearance.setNormalAppearance(appearanceStream);
//            widget.setAppearance(appearance);
//
//            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
//                // for 90° and 270° scale ratio of width / height
//                // not really sure about this
//                // why does scale have no effect when done in the form matrix???
//                if (initialScale != null) {
//                    cs.transform(initialScale);
//                }
//
//                LogSystem.info("Image File " + imageFile);
//
//                if (imageFile != null) {
//                    if (!isWithQR) {
//                        LogSystem.info("! is with QR");
//                        if (descOnly) {
//                            LogSystem.info("Desc only");
//                            cs.saveGraphicsState();
//                            cs.transform(Matrix.getScaleInstance(1.0f, 1.0f));
//
//                            // show text
//                            String title = "Ditandatangani Elektronik:";
//                            int marginTop = 10;
//                            float fontSize = 5;
//                            float leading = fontSize;
//
//                            // scale image
//                            float titleWidth = font.getStringWidth(title) / 1000 * fontSize;
//                            float titleHeight = font.getFontDescriptor().getFontBoundingBox().getHeight() / 1000 * fontSize;
//
//                            float startX = (rect.getWidth() - titleWidth) / 2;
//                            float startY = rect.getHeight() - titleHeight;
//
//                            cs.restoreGraphicsState();
//
//                            cs.beginText();
//
//                            if (rotasi == 90) {
//                                // Notice the post rotation position
//                                double radians = Math.toRadians(90);
//                                Matrix matrix = Matrix.getRotateInstance(radians, rect.getHeight(), rect.getWidth() - titleWidth);
//                                cs.setTextMatrix(matrix);
//                            }
//
//                            if (rotasi == 270) {
//                                double radians = Math.toRadians(90);
//                                Matrix matrix = Matrix.getRotateInstance(radians, rect.getHeight(), rect.getWidth() - titleWidth);
//                                cs.setTextMatrix(matrix);
//                            }
//
//                            cs.setFont(font, fontSize);
//                            cs.setNonStrokingColor(Color.black);
//                            cs.newLineAtOffset(startX, startY);
//                            cs.setLeading(leading);
//
//                            SimpleDateFormat dt = new SimpleDateFormat("dd-MM-yyyy");
//                            SimpleDateFormat tm = new SimpleDateFormat("HH:mm:ss");
//
//                            if (ds.devel == "devel") {
//                                cs.showText("[TESTING ONLY]");
//                                cs.newLine();
//                            }
//                            cs.showText(title);
//                            cs.newLine();
////                            cs.showText("Elektronik:");
////                            cs.newLine();
//
//                            List<String> namaLst = getNamaList(name);
//
//                            int i = 0;
//                            for (i = 0; i < namaLst.size(); i++) {
//                                if (i >= 2) break;
//                                cs.showText(namaLst.get(i));
//                                cs.newLine();
//                            }
//
//                            cs.showText(dt.format(dateSign));
//                            cs.newLine();
//                            cs.showText(tm.format(dateSign) + " WIB");
//
//                            cs.endText();
//                        } else {
//                            if (type.equals("initials")) {
//                                LogSystem.info("Initials");
//                                // save and restore graphics if the image is too large and needs to be scaled
//                                cs.saveGraphicsState();
//                                if (initialScale == null) {
//                                    cs.transform(Matrix.getScaleInstance(1.0f, 1.0f));
//                                }
//
//                                PDImageXObject img = PDImageXObject.createFromFileByExtension(imageFile, doc);
//
//                                // scale image
//                                Dimension scaledDim = null;
//
//                                int x = 0;
//                                int y = 0;
//
//                                if (rotasi == 0 || rotasi == 180) {
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getWidth() / 2, (int) rect.getHeight() / 2), 0);
//
//                                    x = ((int) rect.getWidth() - scaledDim.width) / 2;
//                                    y = ((int) rect.getHeight() - scaledDim.height) / 2;
//                                    cs.drawImage(img, x, y, scaledDim.width, scaledDim.height);
//                                }
//
//                                if (rotasi == 90) {
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight() / 2, (int) rect.getWidth() / 2), 0);
//                                    x = ((int) rect.getWidth() - ((int) rect.getWidth() - scaledDim.height) / 2);
//                                    y = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                    AffineTransform at = new AffineTransform(scaledDim.getHeight(), 0, 0, scaledDim.getWidth(), x, y);
//                                    at.rotate(Math.toRadians(90));
//                                    Matrix m = new Matrix(at);
//                                    cs.drawImage(img, m);
//                                }
//
//                                if (rotasi == 270) {
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight() / 2, (int) rect.getWidth() / 2), 0);
//                                    LogSystem.info("scaled : " + scaledDim);
//                                    x = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                    y = ((int) rect.getWidth() - scaledDim.height) / 2;
//
//                                    cs.drawImage(img, x, y, (int) scaledDim.getWidth(), (int) scaledDim.getHeight());
//                                }
//
//                                cs.restoreGraphicsState();
//                            } else {
//                                if (level.equals("C5")) {
//                                    LogSystem.info("Seal logo/gambar only");
//                                    // save and restore graphics if the image is too large and needs to be scaled
//                                    cs.saveGraphicsState();
//                                    if (initialScale == null) {
//                                        cs.transform(Matrix.getScaleInstance(1.0f, 1.0f));
//                                    }
//
//                                    PDImageXObject img = PDImageXObject.createFromFileByExtension(imageFile, doc);
//
//                                    // scale image
//                                    Dimension scaledDim = null;
//                                    int x = 0;
//                                    int y = 0;
//
//                                    if (rotasi == 0 || rotasi == 180) {
//                                        scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getWidth(), (int) rect.getHeight()), 0);
//                                        x = ((int) rect.getWidth() - scaledDim.width) / 2;
//                                        y = ((int) rect.getHeight() - scaledDim.height) / 2;
//                                        cs.drawImage(img, x, y, scaledDim.width, scaledDim.height);
//                                    }
//
//                                    if (rotasi == 90) {
//                                        scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight(), (int) rect.getWidth()), 0);
//                                        x = ((int) rect.getWidth() - ((int) rect.getWidth() - scaledDim.height) / 2);
//                                        y = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                        AffineTransform at = new AffineTransform(scaledDim.getHeight(), 0, 0, scaledDim.getWidth(), x, y);
//                                        at.rotate(Math.toRadians(90));
//                                        Matrix m = new Matrix(at);
//                                        cs.drawImage(img, m);
//                                    }
//
//                                    if (rotasi == 270) {
//                                        scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight(), (int) rect.getWidth()), 0);
//                                        LogSystem.info("Scaled : " + scaledDim);
//                                        x = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                        y = ((int) rect.getWidth() - scaledDim.height) / 2;
//                                        cs.drawImage(img, x, y, (int) scaledDim.getWidth(), (int) scaledDim.getHeight());
//                                    }
//                                    cs.restoreGraphicsState();
//                                } else {
//                                    LogSystem.info("Sign");
//                                    // save and restore graphics if the image is too large and needs to be scaled
//                                    cs.saveGraphicsState();
//                                    if (initialScale == null) {
//                                        cs.transform(Matrix.getScaleInstance(1.0f, 1.0f));
//                                    }
//
//                                    PDImageXObject img = PDImageXObject.createFromFileByExtension(imageFile, doc);
//
//                                    // scale image
//                                    Dimension scaledDim = null;
//                                    int x = 0;
//                                    int y = 0;
//
//                                    if (rotasi == 0 || rotasi == 180) {
//                                        scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getWidth(), (int) rect.getHeight()), 0);
//                                        x = ((int) rect.getWidth() - scaledDim.width) / 2;
//                                        y = ((int) rect.getHeight() - scaledDim.height) / 2;
//
//                                        cs.drawImage(img, x, y, scaledDim.width, scaledDim.height);
//                                    }
//
//                                    if (rotasi == 90) {
//                                        scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight(), (int) rect.getWidth()), 0);
//                                        x = ((int) rect.getWidth() - ((int) rect.getWidth() - scaledDim.height) / 2);
//                                        y = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                        AffineTransform at = new AffineTransform(scaledDim.getHeight(), 0, 0, scaledDim.getWidth(), x, y);
//                                        at.rotate(Math.toRadians(90));
//                                        Matrix m = new Matrix(at);
//                                        cs.drawImage(img, m);
//                                    }
//
//                                    if (rotasi == 270) {
//                                        scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight(), (int) rect.getWidth()), 0);
//                                        LogSystem.info("Scaled : " + scaledDim);
//                                        x = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                        y = ((int) rect.getWidth() - scaledDim.height) / 2;
//                                        cs.drawImage(img, x, y, (int) scaledDim.getWidth(), (int) scaledDim.getHeight());
//                                    }
//                                    cs.restoreGraphicsState();
//                                }
//                            }
//                        }
//                    } else {
//                        LogSystem.info("With QR");
//                        if (descOnly) {
//                            LogSystem.info("Desc only");
//                            cs.saveGraphicsState();
//                            if (initialScale == null) {
//                                cs.transform(Matrix.getScaleInstance(1.0f, 1.0f));
//                            }
//
//                            // show text
//                            String title = "Ditandatangani Elektronik:";
//                            int marginTop = 5;
//                            float fontSize = 5;
//                            float leading = fontSize;
//
//                            List<String> namaLst = getNamaList(name);
//                            // scale image
//                            float titleWidth = font.getStringWidth(title) / 1000 * fontSize;
//                            float titleHeight = font.getFontDescriptor().getFontBoundingBox().getHeight() / 1000 * fontSize;
//
//                            float startX = (rect.getWidth() - titleWidth) / 2;
//                            float startY = rect.getHeight() - (titleHeight);
//
//                            cs.restoreGraphicsState();
//
//                            cs.beginText();
//
//                            if (rotasi == 90) {
//                                // Notice the post rotation position
//                                double radians = Math.toRadians(90);
//                                Matrix matrix = Matrix.getRotateInstance(radians, rect.getHeight(), rect.getWidth() - titleWidth);
//                                cs.setTextMatrix(matrix);
//                            }
//
//                            cs.setFont(font, fontSize);
//                            cs.setNonStrokingColor(Color.black);
//                            cs.newLineAtOffset(startX, startY);
//                            cs.setLeading(leading);
//
//                            SimpleDateFormat dt = new SimpleDateFormat("dd-MM-yyyy");
//                            SimpleDateFormat tm = new SimpleDateFormat("HH:mm:ss");
//
//                            if (ds.devel == "devel") {
//                                cs.showText("[TESTING ONLY]");
//                                cs.newLine();
//                            }
//                            cs.showText(title);
//                            cs.newLine();
////                            cs.showText("Elektronik:");
////                            cs.newLine();
//
//
//                            int i = 0;
//                            for (i = 0; i < namaLst.size(); i++) {
//                                if (i >= 2) break;
//                                cs.showText(namaLst.get(i));
//                                cs.newLine();
//                            }
//                            cs.showText(dt.format(dateSign));
//                            cs.newLine();
//                            cs.showText(tm.format(dateSign) + " WIB");
//
//                            cs.endText();
//                        } else {
//                            if (type.equals("initials")) {
//                                LogSystem.info("Initials");
//                                // save and restore graphics if the image is too large and needs to be scaled
//                                cs.saveGraphicsState();
//                                if (initialScale == null) {
//                                    cs.transform(Matrix.getScaleInstance(1.0f, 1.0f));
//                                }
//                                PDImageXObject img = PDImageXObject.createFromFileByExtension(imageFile, doc);
//                                Dimension scaledDim = null;
//                                int x = 0;
//                                int y = 0;
//
//                                if (rotasi == 0 || rotasi == 180) {
//                                    // scale image
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getWidth() / 2, (int) rect.getHeight() / 2), 0);
//                                    x = ((int) rect.getWidth() - scaledDim.width) / 2;
//                                    y = ((int) rect.getHeight() - scaledDim.height) / 2;
//                                    cs.drawImage(img, x, y, scaledDim.width, scaledDim.height);
//                                }
//
//                                if (rotasi == 90) {
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight() / 2, (int) rect.getWidth() / 2), 0);
//                                    x = ((int) rect.getWidth() - ((int) rect.getWidth() - scaledDim.height) / 2);
//                                    y = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                    AffineTransform at = new AffineTransform(scaledDim.getHeight(), 0, 0, scaledDim.getWidth(), x, y);
//                                    at.rotate(Math.toRadians(90));
//                                    Matrix m = new Matrix(at);
//                                    cs.drawImage(img, m);
//                                }
//
//                                if (rotasi == 270) {
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight() / 2, (int) rect.getWidth() / 2), 0);
//                                    LogSystem.info("scaled : " + scaledDim);
//                                    x = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                    y = ((int) rect.getWidth() - scaledDim.height) / 2;
//
//                                    cs.drawImage(img, x, y, (int) scaledDim.getWidth(), (int) scaledDim.getHeight());
//                                }
//                                cs.restoreGraphicsState();
//                            } else {
//                                LogSystem.info("Sign");
//                                Dimension scaledDim = null;
//                                // save and restore graphics if the image is too large and needs to be scaled
//                                cs.saveGraphicsState();
//                                if (initialScale == null) {
//                                    cs.transform(Matrix.getScaleInstance(1.0f, 1.0f));
//                                }
//                                PDImageXObject img = PDImageXObject.createFromFileByExtension(imageFile, doc);
//
//                                int x = 0;
//                                int y = 0;
//
//                                // scale image
//                                if (rotasi == 0 || rotasi == 180) {
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getWidth(), (int) rect.getHeight()), 0);
//                                    x = ((int) rect.getWidth() - scaledDim.width) / 2;
//                                    y = ((int) rect.getHeight() - scaledDim.height) / 2;
//                                    cs.drawImage(img, x, y, scaledDim.width, scaledDim.height);
//                                }
//
//                                if (rotasi == 90) {
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight(), (int) rect.getWidth()), 0);
//                                    x = ((int) rect.getWidth() - ((int) rect.getWidth() - scaledDim.height) / 2);
//                                    y = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                    AffineTransform at = new AffineTransform(scaledDim.getHeight(), 0, 0, scaledDim.getWidth(), x, y);
//                                    at.rotate(Math.toRadians(90));
//                                    Matrix m = new Matrix(at);
//                                    cs.drawImage(img, m);
//                                }
//
//                                if (rotasi == 270) {
//                                    scaledDim = getScaledDimension(new Dimension(img.getWidth(), img.getHeight()), new Dimension((int) rect.getHeight(), (int) rect.getWidth()), 0);
//                                    LogSystem.info("Scaled : " + scaledDim);
//                                    x = ((int) rect.getHeight() - scaledDim.width) / 2;
//                                    y = ((int) rect.getWidth() - scaledDim.height) / 2;
//                                    cs.drawImage(img, x, y, (int) scaledDim.getWidth(), (int) scaledDim.getHeight());
//                                }
//                                cs.restoreGraphicsState();
//                            }
//                        }
//                    }
//                }
//            }catch(Exception e)
//            {
//                LogSystem.error(e.toString());
//                e.printStackTrace();
//                doc.close();
//                throw new Exception(e.toString());
//            }
//
//            // no need to set annotations and /P entry
//            ByteArrayOutputStream baos = new ByteArrayOutputStream();
//
//            doc.save(baos);
//            return new ByteArrayInputStream(baos.toByteArray());
//        } catch (Exception e) {
//            LogSystem.error(e.toString());
//            e.printStackTrace();
//            return null;
//        }
//
//    }
//
//
//    public static void setLock(PDSignatureField pdSignatureField, PDAcroForm acroForm) {
//        COSDictionary lockDict = new COSDictionary();
//        lockDict.setItem(COS_NAME_ACTION, COS_NAME_ALL);
//        lockDict.setItem(COSName.TYPE, COS_NAME_SIG_FIELD_LOCK);
//        pdSignatureField.getCOSObject().setItem(COS_NAME_LOCK, lockDict);
//    }
//
//    public static Dimension getScaledDimension(Dimension imgSize, Dimension boundary, int angle) {
//
//        int original_width = imgSize.width;
//        int original_height = imgSize.height;
//        int bound_width = boundary.width;
//        int bound_height = boundary.height;
//        int new_width = original_width;
//        int new_height = original_height;
//
//        if (angle == 0) {
//            // first check if we need to scale width
//            if (original_width > bound_width) {
//                //scale width to fit
//                new_width = bound_width;
//                //scale height to maintain aspect ratio
//                new_height = (new_width * original_height) / original_width;
//            }
//
//            // then check if we need to scale even with the new height
//            if (new_height > bound_height) {
//                //scale height to fit instead
//                new_height = bound_height;
//                //scale width to maintain aspect ratio
//                new_width = (new_height * original_width) / original_height;
//            }
//        }
//
//        if (angle == 90) {
//            if (original_height > bound_height) {
//                //scale width to fit
//                new_height = bound_height;
//                //scale height to maintain aspect ratio
//                new_width = (new_height * original_height) / original_width;
//                LogSystem.info(" " + new_width);
//            }
//
//            // first check if we need to scale width
//            if (new_width > bound_width) {
//                //scale width to fit
//                new_width = bound_width;
//                //scale height to maintain aspect ratio
//                new_height = (bound_height * original_width) / original_height;
//                LogSystem.info(" " + new_height);
//            }
//        }
//
//        return new Dimension(new_width, new_height);
//    }
//
//    // Find an existing signature (assumed to be empty). You will usually not need this.
//    private PDSignature findExistingSignature(PDAcroForm acroForm, String sigFieldName) {
//        PDSignature signature = null;
//        PDSignatureField signatureField;
//
//        if (acroForm != null) {
//            signatureField = (PDSignatureField) acroForm.getField(sigFieldName);
////            signatureField.setPartialName(sigFieldName);
//            if (signatureField != null) {
//                // retrieve signature dictionary
//                signature = signatureField.getSignature();
//
//                if (signature == null) {
//                    signature = new PDSignature();
//                    // after solving PDFBOX-3524
//                    // signatureField.setValue(signature)
//                    // until then:
//                    signatureField.getCOSObject().setItem(COSName.V, signature);
//                } else {
//                    throw new IllegalStateException("The signature field " + sigFieldName + " is already signed.");
//                }
//            }
//        }
//        return signature;
//    }
//
//    TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
//
//        @Override
//        public void checkClientTrusted(X509Certificate[] arg0, String arg1)
//                throws CertificateException {
//            // TODO Auto-generated method stub
//
//        }
//
//        @Override
//        public void checkServerTrusted(X509Certificate[] arg0, String arg1)
//                throws CertificateException {
//            // TODO Auto-generated method stub
//
//        }
//
//        @Override
//        public X509Certificate[] getAcceptedIssuers() {
//            // TODO Auto-generated method stub
//            return null;
//        }
//    }
//    };
//
//    public String signingProcess(byte[] data) throws Exception {
//        try {
//            Description ds = new Description();
//            LogSystem.info("Sending HSK");
//            MessageDigest digest = MessageDigest.getInstance("SHA256");
////            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            byte[] hash = digest.digest(data);
//
//            SSLContext ctx = SSLContext.getInstance("TLS");
////            ctx.init(new KeyManager[0], new TrustManager[] {new DefaultTrustManager()}, new SecureRandom());
//            ctx.init(new KeyManager[0], trustAllCerts, new java.security.SecureRandom());
//            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
//            // Create all-trusting host name verifier
//            HostnameVerifier allHostsValid = new HostnameVerifier() {
//                @Override
//                public boolean verify(String hostname, SSLSession session) {
//                    return true;
//                }
//            };
//            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
//
////            URL url = new URL("https://192.168.182.11:7010/sign");
//            URL url = new URL(ds.HSK_URL + "/sign");
//
//            LogSystem.info("POST : " + url.toString());
//
//            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
//
//            conn.setDoOutput(true);
//            conn.setRequestMethod("POST");
//            conn.setRequestProperty("Content-Type", "application/json");
//            conn.setConnectTimeout(10000);
//            conn.setReadTimeout(240000);
//
//            String base64Data = Base64.toBase64String(data);
//            String input = "{\"keyAlias\":\"" + keyAlias + "\", \"signAlgo\":\"SHA256withRSA\", \"message\":\"" + base64Data + "\"}";
//
//            LogSystem.info("Sending...");
//            OutputStream os = conn.getOutputStream();
//            os.write(input.getBytes());
//            os.flush();
//            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
//                throw new RuntimeException("Failed : HTTP error code : "
//                        + conn.getResponseCode());
//            }
//
//            BufferedReader br = new BufferedReader(new InputStreamReader(
//                    (conn.getInputStream())));
//
//            String output;
//            String response = "";
//            LogSystem.info("Output from Server ....");
//            while ((output = br.readLine()) != null) {
//                response += output;
//            }
//            conn.disconnect();
//
//            LogSystem.info(response);
//            JSONObject rspJSON = new JSONObject(response);
//            return rspJSON.getString("data");
//
//        } catch (MalformedURLException e) {
//            LogSystem.error(e.toString());
//            e.printStackTrace();
//            throw new Exception(e.toString());
//        } catch (IOException e) {
//            LogSystem.error(e.toString());
//            e.printStackTrace();
//            throw new Exception(e.toString());
//        } catch (NoSuchAlgorithmException e) {
//            LogSystem.error(e.toString());
//            e.printStackTrace();
//            throw new Exception(e.toString());
//        } catch (JSONException e) {
//            LogSystem.error(e.toString());
//            e.printStackTrace();
//            throw new Exception(e.toString());
//        } catch (KeyManagementException e) {
//            LogSystem.error(e.toString());
//            e.printStackTrace();
//            throw new Exception(e.toString());
//        }
//         catch (Exception e) {
//            LogSystem.error(e.toString());
////            e.printStackTrace();
//            if(ds.devel.equals("devel"))
//            {
//                try {
//                    LogSystem.info("Sending HSK SIM");
//                    MessageDigest digest = MessageDigest.getInstance("SHA256");
////            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
//                    byte[] hash = digest.digest(data);
//
//                    SSLContext ctx = SSLContext.getInstance("TLS");
////            ctx.init(new KeyManager[0], new TrustManager[] {new DefaultTrustManager()}, new SecureRandom());
//                    ctx.init(new KeyManager[0], trustAllCerts, new java.security.SecureRandom());
//                    HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
//                    // Create all-trusting host name verifier
//                    HostnameVerifier allHostsValid = new HostnameVerifier() {
//                        @Override
//                        public boolean verify(String hostname, SSLSession session) {
//                            return true;
//                        }
//                    };
//                    HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
//
////            URL url = new URL("https://192.168.182.11:7010/sign");
//                    URL url = new URL(ds.HSK_SIM_URL + "/sign");
//
//                    LogSystem.info("POST : " + url.toString());
//
//                    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
//
//                    conn.setDoOutput(true);
//                    conn.setRequestMethod("POST");
//                    conn.setRequestProperty("Content-Type", "application/json");
//                    conn.setConnectTimeout(10000);
//                    conn.setReadTimeout(240000);
//
//                    String base64Data = Base64.toBase64String(data);
//                    String input = "{\"keyAlias\":\"" + keyAlias + "\", \"signAlgo\":\"SHA256withRSA\", \"message\":\"" + base64Data + "\"}";
//
//                    LogSystem.info("Sending...");
//                    OutputStream os = conn.getOutputStream();
//                    os.write(input.getBytes());
//                    os.flush();
//                    if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
//                        throw new RuntimeException("Failed : HTTP error code : "
//                                + conn.getResponseCode());
//                    }
//
//                    BufferedReader br = new BufferedReader(new InputStreamReader(
//                            (conn.getInputStream())));
//
//                    String output;
//                    String response = "";
//                    LogSystem.info("Output from Server ....");
//                    while ((output = br.readLine()) != null) {
//                        response += output;
//                    }
//                    conn.disconnect();
//
//                    LogSystem.info(response);
//                    JSONObject rspJSON = new JSONObject(response);
//                    return rspJSON.getString("data");
//                }catch(Exception e2)
//                {
//                    LogSystem.error(e2.toString());
////                    e2.printStackTrace();
//                    throw new Exception(e2.toString());
//                }
//            }
//            throw new Exception(e.toString());
//        }
////        return null;
//    }
//
//    private static class DefaultTrustManager implements X509TrustManager {
//
//        @Override
//        public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
//        }
//
//        @Override
//        public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
//        }
//
//        @Override
//        public X509Certificate[] getAcceptedIssuers() {
//            return null;
//        }
//    }
//
//
//    public byte[] attachSignature(String signature) throws OperatorCreationException, CMSException, IOException, NoSuchAlgorithmException, CertificateEncodingException {
//        final byte[] signedHash = Base64.decode(signature);
//        Certificate cert = getCertificateChain()[0];
//        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
//
//        ContentSigner nonSigner = new ContentSigner() {
//
//            @Override
//            public byte[] getSignature() {
//                return signedHash;
//            }
//
//            @Override
//            public OutputStream getOutputStream() {
//                return new ByteArrayOutputStream();
//            }
//
//            @Override
//            public AlgorithmIdentifier getAlgorithmIdentifier() {
//                return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSA");
//            }
//        };
//
//        org.bouncycastle.asn1.x509.Certificate cert2 = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));
//        JcaSignerInfoGeneratorBuilder sigb = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
//        LogSystem.info(cert2.getSubject().toString());
//
//        sigb.setDirectSignature(true);
//        gen.addSignerInfoGenerator(sigb.build(nonSigner, new X509CertificateHolder(cert2)));
//        gen.addCertificates(new JcaCertStore(Arrays.asList(getCertificateChain())));
//
//        CMSTypedData msg = new id.idtrust.signing.core.pdf.CMSProcessableInputStream(new ByteArrayInputStream("not used".getBytes()));
//
//        CMSSignedData signedData = gen.generate((CMSTypedData) msg, false);
//
//        if (this.tsaUrl != null) {
//            ValidationTimeStamp validation = new ValidationTimeStamp(this.tsaUrl);
//            signedData = validation.addSignedTimeStamp(signedData);
//
//            LogSystem.info("add timestamp");
//        }
//
//        return signedData.getEncoded();
//
//    }
//
//
//    private void makeLTV() throws Exception {
//        try {
//            COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
//            catalogDict.setNeedToBeUpdated(true);
//            byte[][] certs = new byte[certificateChain.length][];
//            for (int i = 0; i < certificateChain.length; i++) {
//                certs[i] = certificateChain[i].getEncoded();
//            }
//            // Assign byte array for storing certificate in DSS Store.
//            List<CRL> crlList = new ArrayList<CRL>();
//            List<OCSPResp> ocspList = new ArrayList<OCSPResp>();
//            for (int i = 0; i < certificateChain.length; i++) {
//                X509Certificate cert = (X509Certificate) certificateChain[i];
//                if (!cert.getIssuerDN().equals(cert.getSubjectDN())) {
//                    X509Certificate issuerCert = (X509Certificate) certificateChain[i + 1];
//                    if (issuerCert != null) {
//                        OCSPResp ocspResp;
//                        ocspResp = new GetOcspResp().getOcspResp(cert, issuerCert);
//                        if (ocspResp != null) {
//                            ocspList.add(ocspResp);
//                        }
//                    }
//
//                    crlList.addAll(new DssHelper().readCRLsFromCert(cert));
//                }
//            }
//            byte[][] crls = new byte[crlList.size()][];
//            for (int i = 0; i < crlList.size(); i++) {
//                crls[i] = ((X509CRL) crlList.get(i)).getEncoded();
//                LogSystem.info("set CRL data");
//            }
//            byte[][] ocsps = new byte[ocspList.size()][];
//            for (int i = 0; i < ocspList.size(); i++) {
//                ocsps[i] = ocspList.get(i).getEncoded();
//            }
//            Iterable<byte[]> certifiates = Arrays.asList(certs);
//            COSDictionary dss = new DssHelper().createDssDictionary(certifiates, Arrays.asList(crls),
//                    Arrays.asList(ocsps));
//            catalogDict.setItem(COSName.getPDFName("DSS"), dss);
//
//        } catch (CertificateException e) {
//            // TODO Auto-generated catch block
//            LogSystem.error(e.toString());
////            e.printStackTrace();
////            throw new Exception(e.toString());
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            LogSystem.error(e.toString());
////            e.printStackTrace();
////            throw new Exception(e.toString());
//        } catch (Exception e) {
//            // TODO Auto-generated catch block
//            LogSystem.error(e.toString());
////            e.printStackTrace();
////            throw new Exception(e.toString());
//        }
//    }
//
//    public static void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions)
//            throws IOException {
//
//        COSDictionary sigDict = signature.getCOSObject();
//
//        // DocMDP specific stuff
//        COSDictionary transformParameters = new COSDictionary();
//        transformParameters.setItem(COSName.TYPE, COSName.TRANSFORM_PARAMS);
//        transformParameters.setInt(COSName.P, accessPermissions);
//        transformParameters.setName(COSName.V, "1.2");
//        transformParameters.setNeedToBeUpdated(true);
//
//        COSDictionary referenceDict = new COSDictionary();
//        referenceDict.setItem(COSName.TYPE, COSName.SIG_REF);
//        referenceDict.setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP);
//        referenceDict.setItem(COSName.DIGEST_METHOD, COSName.getPDFName("SHA1"));
//        referenceDict.setItem(COSName.TRANSFORM_PARAMS, transformParameters);
//        referenceDict.setNeedToBeUpdated(true);
//
//        COSArray referenceArray = new COSArray();
//        referenceArray.add(referenceDict);
//        sigDict.setItem(COSName.REFERENCE, referenceArray);
//        referenceArray.setNeedToBeUpdated(true);
//
//        // Catalog
//        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
//        COSDictionary permsDict = new COSDictionary();
//        catalogDict.setItem(COSName.PERMS, permsDict);
//        permsDict.setItem(COSName.DOCMDP, signature);
//        catalogDict.setNeedToBeUpdated(true);
//        permsDict.setNeedToBeUpdated(true);
//    }
//
//    static List<String> getNamaList(String nama) {
//        int size = 20;
//        String namaS[] = nama.split(" ");
//
//        List<String> row = new ArrayList<>();
//        String rowText = "";
//        for (int i = 0; i < namaS.length; i++) {
//            String nmTxt = namaS[i];
//
//            if ((rowText.length() + nmTxt.length()) <= size) {
//                rowText += nmTxt + " ";
//                continue;
//            }
//            int spaceSz = size - rowText.length();
//            int szDiff = nmTxt.length() - spaceSz;
//            if ((nmTxt.length() - szDiff > 3) && szDiff > 3) {
//                rowText += nmTxt.substring(0, spaceSz);
//                row.add(rowText);
//                rowText = "";
//                rowText += nmTxt.substring(spaceSz) + " ";
//            } else {
//                row.add(rowText);
//                rowText = "";
//                rowText += nmTxt.substring(0) + " ";
//            }
//        }
//
//        row.add(rowText);
//        return row;
//    }
//
////    public boolean lockPDF(File inputFile, File signedFile, int pageNum, Rectangle2D humanRect, UserSignature userSignature, String SignatureField) throws IOException, CertificateEncodingException, NoSuchAlgorithmException, OperatorCreationException, CMSException {
////        if (inputFile == null || !inputFile.exists()) {
////            throw new IOException("Document for signing does not exist");
////        }
////        PDDocument docEx = null;
////        PDDocument docSave = null;
////        try {
////            // creating output document and prepare the IO streams.
////            FileOutputStream fos = new FileOutputStream(signedFile);
////
////            // load document
////            //Create empty signature field
////            docEx = PDDocument.load(inputFile);
////            PDAcroForm acroFormField = docEx.getDocumentCatalog().getAcroForm();
////            acroFormField.getCOSObject().setNeedToBeUpdated(true);
////            COSObject fields = acroFormField.getCOSObject().getCOSObject(COSName.FIELDS);
////            if (fields != null)
////                fields.setNeedToBeUpdated(true);
////
////            acroFormField.setSignaturesExist(true);
////            acroFormField.setAppendOnly(true);
////            acroFormField.getCOSObject().setDirect(true);
////
////            PDPage pageField = docEx.getPage(pageNum);
////            // Create empty signature field, it will get the name "Signature1"
////            PDSignatureField signatureField = new PDSignatureField(acroFormField);
////            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
////            PDRectangle rectField = new PDRectangle((float) humanRect.getX(), (float) humanRect.getY(), (float) humanRect.getWidth(), (float) humanRect.getHeight());
////
////            widget.setRectangle(rectField);
////            widget.getCOSObject().setNeedToBeUpdated(true);
////            widget.setPage(pageField);
////            pageField.getAnnotations().add(widget);
////            pageField.getCOSObject().setNeedToBeUpdated(true);
////            acroFormField.getFields().add(signatureField);
////            setLock(signatureField, acroFormField);
////            docEx.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
////            docEx.saveIncremental(fos);
////
////            fos.close();
////            //Close and replace with created empty field signature
////            docSave = PDDocument.load(signedFile);
////
////            FileOutputStream fosSeal = new FileOutputStream(signedFile);
////
////            PDSignature signatureLock = new PDSignature();
////            PDSignatureField signatureFieldLoad = (PDSignatureField) docSave.getDocumentCatalog().getAcroForm().getField("Signature1");
////            LogSystem.info("signatureFieldLoad " + signatureFieldLoad.getValueAsString());
////            LogSystem.info("signaturelock " + signatureLock);
////            signatureFieldLoad.setValue(signatureLock);
////
////            COSBase lock = signatureFieldLoad.getCOSObject().getDictionaryObject(COS_NAME_LOCK);
////            if (lock instanceof COSDictionary) {
////                COSDictionary lockDict = new COSDictionary();
////                lockDict.setItem(COS_NAME_ACTION, COS_NAME_ALL);
////                lockDict.setItem(COSName.TYPE, COS_NAME_SIG_FIELD_LOCK);
////
////                COSDictionary transformParams = new COSDictionary(lockDict);
////                transformParams.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
////                transformParams.setItem(COSName.V, COSName.getPDFName("1.2"));
////                transformParams.setInt(COSName.P, 1);
////
////                transformParams.setDirect(true);
////                transformParams.setNeedToBeUpdated(true);
////
////                COSDictionary sigRef = new COSDictionary();
////                sigRef.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
////                sigRef.setItem(COSName.getPDFName("TransformParams"), transformParams);
////                sigRef.setItem(COSName.getPDFName("TransformMethod"), COSName.getPDFName("FieldMDP"));
////                sigRef.setItem(COSName.getPDFName("Data"), docSave.getDocumentCatalog());
////                sigRef.setDirect(true);
////                COSArray referenceArray = new COSArray();
////                referenceArray.add(sigRef);
////                signatureLock.getCOSObject().setItem(COSName.getPDFName("Reference"), referenceArray);
////                LogSystem.info("LOCK DICTIONARY");
////
////                final Predicate<PDField> shallBeLocked;
////                final COSArray fieldsLock = lockDict.getCOSArray(COSName.FIELDS);
////                final List<String> fieldNames = fieldsLock == null ? Collections.emptyList() :
////                        fieldsLock.toList().stream().filter(c -> (c instanceof COSString)).map(s -> ((COSString) s).getString()).collect(Collectors.toList());
////                final COSName action = lockDict.getCOSName(COSName.getPDFName("Action"));
////                if (action.equals(COSName.getPDFName("Include"))) {
////                    shallBeLocked = f -> fieldNames.contains(f.getFullyQualifiedName());
////                } else if (action.equals(COSName.getPDFName("Exclude"))) {
////                    shallBeLocked = f -> !fieldNames.contains(f.getFullyQualifiedName());
////                } else if (action.equals(COSName.getPDFName("All"))) {
////                    shallBeLocked = f -> true;
////                } else { // unknown action, lock nothing
////                    shallBeLocked = f -> false;
////                }
////                lockFields(docSave.getDocumentCatalog().getAcroForm().getFields(), shallBeLocked);
//////            setMDPPermission(doc, signatureLock, 1);
////
////                // default filter
////                signatureLock.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
////
////                // subfilter for basic and PAdES Part 2 signatures
////                signatureLock.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
////
////                signatureLock.setName("SEAL LOCK");
////                signatureLock.setLocation("PT. Solusi Net Internusa");
////
////                if (userSignature.getType().equals("seal")) {
////                    this.setExternalSigning(true);
////                    signatureLock.setReason(userSignature.getQrText());
////                }
////
////                // the signing date, needed for valid signature
////                signatureLock.setSignDate(getDate());
////
////                // do not set SignatureInterface instance, if external signing used
////                SignatureInterface signatureInterface = isExternalSigning() ? null : this;
////
////                docSave.addSignature(signatureLock, signatureInterface, signatureOptions);
////
////                docSave.getDocumentCatalog().getAcroForm().getField("Signature1").setPartialName("Sealing");
////
////                if (isExternalSigning()) {
////                    this.tsaUrl = tsaUrl;
////
////                    ExternalSigningSupport externalSigning = docSave.saveIncrementalForExternalSigning(fosSeal);
////
////                    // invoke external signature serviceUsing fallback
////                    byte[] cmsSignature = IOUtils.toByteArray(externalSigning.getContent());
////                    String sgn = null;
////                    try {
////                        sgn = signingProcess(cmsSignature);
//////                                sgn = "j+ZiOwWlc6dvIvxmizED5/QchmCit1BhscSjaiD10tzUxrULR/xnA2JoYARoR2TpShX8jMbqOIgdf5hGHduikBIHv9QKCY+wHSIZM0BJpmcFJcugAbUI20FMg4B195Bm0V+8fGCVZ9HxGmsbsBPgg0hjiURkfcNUXRTO4Y6T1lQfQfNzzD9toJsywSLhBi2Rk8WN83k4utqU/lHDaZ2BhEz6paYbxre5G9nZjM57QZWAZaGt56sW0CpOcLs5up5k2uUHJxY5lfv3p9VpnEBeLHHyZ0V+ZFmMi43f6KeXj4e14/AXibV4Fiek6+AB9N73dlVpNr8yrLqXlNhIhwE8HQ==";
////                    } catch (Exception e) {
////                        LogSystem.error(e.toString());
////                        e.printStackTrace();
////                        docSave.close();
////                        return false;
////                    }
////
////                    // set signature bytes received from the service
////                    if (sgn != null) {
////                        externalSigning.setSignature(attachSignature(sgn));
////                    } else {
////                        return false;
////                    }
////
////                } else {
////                    // write incremental (only for signing purpose)
////                    docSave.saveIncremental(fos);
////                }
////                docSave.close();
////                docEx.close();
////
////                IOUtils.closeQuietly(signatureOptions);
////            }
////        } catch (Exception e) {
////            e.printStackTrace();
////            LogSystem.error(e.toString());
////        } finally {
////            docEx.close();
////        }
////
////        return true;
////    }
//}
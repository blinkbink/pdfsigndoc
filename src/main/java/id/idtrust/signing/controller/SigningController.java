package id.idtrust.signing.controller;

import id.idtrust.signing.core.pdf.QRCode;
import id.idtrust.signing.core.signDoc;
import id.idtrust.signing.model.signer.*;
import id.idtrust.signing.util.Description;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import id.idtrust.signing.core.LTV.AddValidationInformation;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.util.Hex;
import org.bouncycastle.asn1.BEROctetString;
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.springframework.data.jpa.repository.support.SimpleJpaRepository;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

@RestController
@Setter
@Getter
@RequestMapping(value = "/api/")
public class SigningController {


    private static final Logger logger = LogManager.getLogger("idtrust");
    static Description ds = new Description();
    private static CertificateFactory certificateFactory = null;

    public SigningController() {

    }

    @PostMapping(value = "/signing", produces = {"application/json"})
    public ResponseEntity<?> SigningDocument(@RequestBody String json) throws Exception {

//            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : " + json);

            JSONObject request = new JSONObject(json);

            if(Boolean.parseBoolean(ds.DEBUG)) {
                File file = new File("debug/req"+System.currentTimeMillis()/1000+".json");
                FileWriter fr = null;
                try {
                    fr = new FileWriter(file);
                    fr.write(request.toString());
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    //close resources
                    try {
                        fr.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

            int status_code = 200;
            JSONObject signingProperties = null;
            JSONArray signingLocation = null;
            JSONArray initialLocation = null;
            JSONObject response = new JSONObject();

            int accessPermissions = 0;
            boolean canContinue = true;

            UserSigning userSigningData = new UserSigning();
            SigningProperties signingPropertiesData = new SigningProperties();
            List<SigningLocation> listSigningLocationData = new ArrayList<SigningLocation>();
            List<InitialLocation> listInitialsLocationData = new ArrayList<InitialLocation>();

            //Validation request
            if (!request.has("document")) {
                response.put("result_code", "W40");
                response.put("message", "Object document is required");
                response.put("timestamp", new Date().toInstant());
                canContinue = false;
                status_code = 400;
            }
            if (!request.has("private_key_alias")) {
                response.put("result_code", "W41");
                response.put("message", "Object private_key_alias is required");
                response.put("timestamp", new Date().toInstant());
                canContinue = false;
                status_code = 400;
            }
            if (!request.has("signer_certificate_chain")) {
                response.put("result_code", "W42");
                response.put("message", "Object signer_certificate_chain is required");
                response.put("timestamp", new Date().toInstant());
                canContinue = false;
                status_code = 400;
            }
            if (!request.has("signer_name")) {
                response.put("result_code", "W54");
                response.put("message", "Object signer_name is required");
                response.put("timestamp", new Date().toInstant());
                canContinue = false;
                status_code = 400;
            }
            if (!request.has("signature_image")) {
                response.put("result_code", "W55");
                response.put("message", "Object signature_image is required");
                response.put("timestamp", new Date().toInstant());
                canContinue = false;
                status_code = 400;
            }
            if (!request.has("signing_properties")) {
                response.put("result_code", "W43");
                response.put("message", "Object signing_properties is required");
                response.put("timestamp", new Date().toInstant());
                canContinue = false;
                status_code = 400;
            } else {

                userSigningData.setSignerName(request.getString("signer_name"));
                if(request.has("signature_image"))
                {
                    userSigningData.setSignatureImage(request.getString("signature_image"));
                }
                userSigningData.setDocument(request.getString("document"));
                userSigningData.setPrivate_key_alias(request.getString("private_key_alias"));
                userSigningData.setSigner_certificate_chain(request.getString("signer_certificate_chain"));
                if(request.has("initial_image"))
                {
                    userSigningData.setInitialImage(request.getString("initial_image"));
                }

                signingProperties = request.getJSONObject("signing_properties");

                if (!signingProperties.has("location")) {
                    response.put("result_code", "W44");
                    response.put("message", "Object location is required in signing_properties");
                    response.put("timestamp", new Date().toInstant());
                    canContinue = false;
                    status_code = 400;
                }
                if (!signingProperties.has("reason")) {
                    response.put("result_code", "W45");
                    response.put("message", "Object reason is required in signing_properties");
                    response.put("timestamp", new Date().toInstant());
                    canContinue = false;
                    status_code = 400;
                }
                if (!signingProperties.has("signature_id")) {
                    response.put("result_code", "W46");
                    response.put("message", "Object signature_id is required in signing_properties");
                    response.put("timestamp", new Date().toInstant());
                    canContinue = false;
                    status_code = 400;
                }
                if (!signingProperties.has("type_signature")) {
                    response.put("result_code", "W47");
                    response.put("message", "Object type_signature is required in type_signature");
                    response.put("timestamp", new Date().toInstant());
                    canContinue = false;
                    status_code = 400;
                }
                if (!signingProperties.has("signing_location")) {
                    response.put("result_code", "W48");
                    response.put("message", "Object signing_location is required in signing_properties");
                    response.put("timestamp", new Date().toInstant());
                    canContinue = false;
                    status_code = 400;
                } else {


                    if (!signingProperties.isNull("signing_location"))
                    {
                        signingLocation = signingProperties.getJSONArray("signing_location");
                    }
                    if (!signingProperties.isNull("initial_location"))
                    {
                        initialLocation = signingProperties.getJSONArray("initial_location");
                    }


                    if(signingProperties.getString("type_signature").equalsIgnoreCase("seal"))
                    {
                        accessPermissions = 1;
                    }

                    signingPropertiesData.setType_signature(accessPermissions);
                    signingPropertiesData.setLocation(signingProperties.getString("location"));
                    signingPropertiesData.setReason(signingProperties.getString("reason"));
                    signingPropertiesData.setSignature_id(signingProperties.getString("signature_id"));

                    if(signingLocation != null) {
                        for (int i = 0; i < signingLocation.length(); i++) {
                            if (!signingLocation.getJSONObject(i).has("llx")) {
                                response.put("result_code", "W49");
                                response.put("message", "Object llx is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }
                            if (!signingLocation.getJSONObject(i).has("lly")) {
                                response.put("result_code", "W50");
                                response.put("message", "Object lly is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }
                            if (!signingLocation.getJSONObject(i).has("page")) {
                                response.put("result_code", "W51");
                                response.put("message", "Object page is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }
                            if (!signingLocation.getJSONObject(i).has("urx")) {
                                response.put("result_code", "W52");
                                response.put("message", "Object urx is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }
                            if (!signingLocation.getJSONObject(i).has("ury")) {
                                response.put("result_code", "W53");
                                response.put("message", "Object ury is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }

                            SigningLocation signingLocationData = new SigningLocation();
                            signingLocationData.setLlx(Float.parseFloat(signingLocation.getJSONObject(i).getString("llx")));
                            signingLocationData.setLly(Float.parseFloat(signingLocation.getJSONObject(i).getString("lly")));
                            signingLocationData.setUrx(Float.parseFloat(signingLocation.getJSONObject(i).getString("urx")));
                            signingLocationData.setUry(Float.parseFloat(signingLocation.getJSONObject(i).getString("ury")));
                            signingLocationData.setPage(signingLocation.getJSONObject(i).getInt("page"));

                            listSigningLocationData.add(signingLocationData);
                        }
                        signingPropertiesData.setSigningLocationList(listSigningLocationData);
                    }
                    if(initialLocation != null) {
                        for (int i = 0; i < initialLocation.length(); i++) {
                            if (!initialLocation.getJSONObject(i).has("llx")) {
                                response.put("result_code", "W49");
                                response.put("message", "Object llx is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }
                            if (!initialLocation.getJSONObject(i).has("lly")) {
                                response.put("result_code", "W50");
                                response.put("message", "Object lly is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }
                            if (!initialLocation.getJSONObject(i).has("page")) {
                                response.put("result_code", "W51");
                                response.put("message", "Object page is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }
                            if (!initialLocation.getJSONObject(i).has("urx")) {
                                response.put("result_code", "W52");
                                response.put("message", "Object urx is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }
                            if (!initialLocation.getJSONObject(i).has("ury")) {
                                response.put("result_code", "W53");
                                response.put("message", "Object ury is required in signing_location");
                                response.put("timestamp", new Date().toInstant());
                                canContinue = false;
                                status_code = 400;
                            }

                            InitialLocation initialsLocationData = new InitialLocation();
                            initialsLocationData.setLlx(Float.parseFloat(initialLocation.getJSONObject(i).getString("llx")));
                            initialsLocationData.setLly(Float.parseFloat(initialLocation.getJSONObject(i).getString("lly")));
                            initialsLocationData.setUrx(Float.parseFloat(initialLocation.getJSONObject(i).getString("urx")));
                            initialsLocationData.setUry(Float.parseFloat(initialLocation.getJSONObject(i).getString("ury")));
                            initialsLocationData.setPage(initialLocation.getJSONObject(i).getInt("page"));

                            listInitialsLocationData.add(initialsLocationData);
                        }
                        signingPropertiesData.setInitialLocationList(listInitialsLocationData);
                    }

                    userSigningData.setSigningProperties(signingPropertiesData);
                }
            }

            if (!canContinue) {

                logger.info("[" + ds.VERSION + "]-[SIGNING/REQUEST] : " + response);

                return ResponseEntity
                        .status(status_code)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response.toString());
            } else {
                signDoc signing = null;
                String rootDir = "docs/"+UUID.randomUUID().toString().replace("-", "");
                File directory = new File(rootDir);

                try {

                    if (!directory.exists())
                    {
                        if (!directory.mkdir())
                        {
                            //Failed create root directory

                            status_code = 500;
                            response.put("result_code", "E52");
                            response.put("message", "Failed create root parent");
                            response.put("timestamp", new Date().toInstant());

                            logger.info("[" + ds.VERSION + "]-[SIGNING/RESPONSE] : " + response);

                            return ResponseEntity
                                    .status(status_code)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(response.toString());
                        }
                    }

                    logger.info("[" + ds.VERSION + "]-[SIGNING/REQUEST] : " + signingProperties.toString());

                    //save signer_image
                    try {
                        if(userSigningData.getSignatureImage() != null) {
                            byte[] imageBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(userSigningData.getSignatureImage());
                            BufferedImage img = ImageIO.read(new ByteArrayInputStream(imageBytes));
                            ImageIO.write(img, "png", new File(rootDir + "/signature.png"));
                        }

                        if(userSigningData.getInitialImage() != null) {
                            byte[] imageBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(userSigningData.getInitialImage());
                            BufferedImage img = ImageIO.read(new ByteArrayInputStream(imageBytes));
                            ImageIO.write(img, "png", new File(rootDir + "/initial.png"));
                        }
//                        //Create speciment for signing
//                        QRCode speciment = new QRCode();
//
//                        speciment.generateImageSignNoQr(userSigningData.getSignerName(), rootDir+"/signature.png", rootDir+"/signature_new.png", new Date());
                    }
                    catch(Exception e)
                    {
                        e.printStackTrace();

                        status_code = 500;
                        response.put("result_code", "E50");
                        response.put("message", "Failed process signature image");
                        response.put("error", e.toString());
                        response.put("timestamp", new Date().toInstant());

                        logger.info("[" + ds.VERSION + "]-[SIGNING/RESPONSE] : " + response);

                        return ResponseEntity
                                .status(status_code)
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(response.toString());
                    }
                    //end save signer_image

                    String[] d = request.getString("signer_certificate_chain").replace("\n", "").replace("\\n", "").replace("\\", "").replace("-----BEGIN CERTIFICATE-----", "").split("-----END CERTIFICATE-----");

                    KeySigner keySigner = new KeySigner();

                    Certificate[] certificates = null;

                    try{
                        logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Process certificate");
                        certificates =  keySigner.getCert2(d);
                        logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Certificate Done");

                    }catch(Exception e)
                    {
                        e.printStackTrace();

                        status_code = 400;
                        response.put("result_code", "W56");
                        response.put("message", "Failed read certificate chain");
                        response.put("error", e.toString());
                        response.put("timestamp", new Date().toInstant());

                        logger.info("[" + ds.VERSION + "]-[SIGNING/RESPONSE] : " + response);

                        return ResponseEntity
                                .status(status_code)
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(response.toString());
                    }

                    // sign PDF
                    byte[] rawPdfDecoded = Base64.getDecoder().decode(userSigningData.getDocument());

                    File infile = new File(rootDir+"/initfile.pdf");

                    try (FileOutputStream fos = new FileOutputStream(infile))
                    {
                        logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Process creating " + infile.getName());
                        fos.write(rawPdfDecoded);
                        logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Success creating temporary file " + infile.getName());
                    } catch (Exception e)
                    {
                        e.printStackTrace();

                        status_code = 500;
                        response.put("result_code", "E50");
                        response.put("message", "Failed");
                        response.put("error", e.toString());
                        response.put("timestamp", new Date().toInstant());

                        logger.info("[" + ds.VERSION + "]-[SIGNING/RESPONSE] : " + response);

                        return ResponseEntity
                                .status(status_code)
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(response.toString());
                    }

                    signing = new signDoc(certificates, userSigningData.getPrivate_key_alias());

                    signing.setExternalSigning(true);
                    signing.setTsaURL("http://"+ds.TSA_URL);
                    signing.setReason(signingPropertiesData.getReason());
                    signing.setLocation(signingPropertiesData.getLocation());
                    signing.setAccessPermissions(signingPropertiesData.getType_signature());

                    File outFile = new File(rootDir+"/endfile.pdf");

                    if(signingPropertiesData.getInitialLocationList() != null)
                    {
                        signing.setImageFile(new File(rootDir+"/initial.png"));
                        for(int j = 0 ; j < signingPropertiesData.getInitialLocationList().size() ; j++)
                        {
                            float lx = 0;
                            float ly = 0;
                            float rx = 0;
                            float ry = 0;
                            int page = 0;

                            lx = signingPropertiesData.getInitialLocationList().get(j).getLlx();
                            ly = signingPropertiesData.getInitialLocationList().get(j).getLly();
                            rx = signingPropertiesData.getInitialLocationList().get(j).getUrx();
                            ry = signingPropertiesData.getInitialLocationList().get(j).getUry();
                            page = signingPropertiesData.getInitialLocationList().get(j).getPage() - 1;

                            if (Float.compare(ry, ly) < 0)
                            {
                                ly = signingPropertiesData.getInitialLocationList().get(j).getUry();
                                ry = signingPropertiesData.getInitialLocationList().get(j).getLly();
                            }

                            float width = rx - lx;
                            float height = ry - ly;

    //                        page = page + 1

                            Rectangle2D humanRect = new Rectangle2D.Float(lx, ry, width, height);
                            Rectangle2D humanRect2 = new Rectangle2D.Float(lx+200, ry+200, width, height);

                            String signatureField = null;

                            if(signingPropertiesData.getSignature_id() != null)
                            {
                                if(j == 0)
                                {
                                    signatureField = "INIT"+signingPropertiesData.getSignature_id();
                                }
                                else {
                                    signatureField = "INIT"+signingPropertiesData.getSignature_id() + "_" + j;
                                }
                            }

                            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Initial "+signatureField+" Page " + page + " Width " + width + " " + "Height " + height);

                            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : In "+infile + " out " + outFile);

                            signing.signPDF(infile, outFile, humanRect, "", signatureField, page);

                            if(signing.getStatus_code() != 0 || signing.getThrowMessage() != null)
                            {
                                if(signing.getThrowMessage() != null)
                                {
                                    response.put("error", signing.getThrowMessage());
                                }

                                status_code = 500;
                                if(signing.getStatus_code() != 0)
                                {
                                    status_code = signing.getStatus_code();
                                }

                                response.put("result_code", "E51");
                                response.put("message", "Failed Signing Document");
                                response.put("timestamp", new Date().toInstant());

                                logger.info("[" + ds.VERSION + "]-[SIGNING/RESPONSE] : " + response);

                                return ResponseEntity
                                        .status(status_code)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .body(response.toString());
                            }

                            //Ubah file awal menjadi hasil setelah tandatangan
                            if(j <= signingPropertiesData.getInitialLocationList().size() - 1 && signingPropertiesData.getSigningLocationList() != null &&  signingPropertiesData.getSigningLocationList().size() > 0)
                            {
                                infile = new File(outFile.getAbsolutePath());
                                outFile = new File(rootDir + "/" + UUID.randomUUID().toString().replace("-", "") + ".pdf");
                            }
                        }
                    }

                    if(signingPropertiesData.getSigningLocationList() != null) {
                        signing.setImageFile(new File(rootDir+"/signature.png"));
                        for (int j = 0; j < signingPropertiesData.getSigningLocationList().size(); j++) {
                            float lx = 0;
                            float ly = 0;
                            float rx = 0;
                            float ry = 0;
                            int page = 0;

                            lx = signingPropertiesData.getSigningLocationList().get(j).getLlx();
                            ly = signingPropertiesData.getSigningLocationList().get(j).getLly();
                            rx = signingPropertiesData.getSigningLocationList().get(j).getUrx();
                            ry = signingPropertiesData.getSigningLocationList().get(j).getUry();
                            page = signingPropertiesData.getSigningLocationList().get(j).getPage() - 1;

                            if (Float.compare(ry, ly) < 0) {
                                ly = signingPropertiesData.getSigningLocationList().get(j).getUry();
                                ry = signingPropertiesData.getSigningLocationList().get(j).getLly();
                            }

                            float width = rx - lx;
                            float height = ry - ly;

                            Rectangle2D humanRect = new Rectangle2D.Float(lx, ry, width, height);

                            String signatureField = null;

                            if (signingPropertiesData.getSignature_id() != null) {
                                if (j == 0) {
                                    signatureField = "SGN" + signingPropertiesData.getSignature_id();
                                } else {
                                    signatureField = "SGN" + signingPropertiesData.getSignature_id() + "_" + j;
                                }
                            }

                            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : SIGNING " + signatureField + " Page " + page + " Width " + width + " " + "Height " + height);

                            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : In " + infile + " out " + outFile);

                            signing.signPDF(infile, outFile, humanRect, "", signatureField, page);

                            if (signing.getStatus_code() != 0 || signing.getThrowMessage() != null) {
                                if (signing.getThrowMessage() != null) {
                                    response.put("error", signing.getThrowMessage());
                                }

                                status_code = 500;
                                if (signing.getStatus_code() != 0) {
                                    status_code = signing.getStatus_code();
                                }

                                response.put("result_code", "E51");
                                response.put("message", "Failed Signing Document");
                                response.put("timestamp", new Date().toInstant());

                                logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : " + response);

                                return ResponseEntity
                                        .status(status_code)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .body(response.toString());
                            }

                            //Ubah file awal menjadi hasil setelah tandatangan
                            if (j < signingPropertiesData.getSigningLocationList().size() - 1) {
                                infile = new File(outFile.getAbsolutePath());
                                outFile = new File(rootDir + "/" + UUID.randomUUID().toString().replace("-", "") + ".pdf");
                            }
                        }
                    }

                    //result from signing
                    AddValidationInformation addValidationInformation = new AddValidationInformation();
                    String finalPdfPath = rootDir + "/" + UUID.randomUUID().toString().replace("-", "")+"_final.pdf";

                    byte[] inFileBytes = null;

                    if(signingPropertiesData.getType_signature() != 1 || signing.getDoValidation())
                    {
                        try
                        {
                            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Add validation information");
                            addValidationInformation.validateSignature(outFile, new File(finalPdfPath));
                            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Process done");
//                            checkLTV(new File (finalPdfPath));
                        }catch(Exception e)
                        {
                            logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Failed validation document");
                            e.printStackTrace();

                            status_code = 403;
                            response.put("result_code", "F40");
                            response.put("message", "Failed Signing Document");
                            response.put("error", e.toString());
                            response.put("timestamp", new Date().toInstant());

                            logger.info("[" + ds.VERSION + "]-[SIGNING/RESPONSE] : " + response);

                            return ResponseEntity
                                    .status(status_code)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(response.toString());
                        }
                        inFileBytes = Files.readAllBytes(Paths.get(finalPdfPath));
                    }
                    else
                    {
                        inFileBytes = Files.readAllBytes(Paths.get(outFile.getAbsolutePath()));
                    }

                    byte[] encoded = java.util.Base64.getEncoder().encode(inFileBytes);

                    String finalPdf = new String(encoded, StandardCharsets.UTF_8);

                    response.put("result_code", "S20");
                    response.put("message", "Success");
                    response.put("document", finalPdf.replace("\\", "").replace("\\\\", ""));
                    response.put("timestamp", new Date().toInstant());

                    logger.info("[" + ds.VERSION + "]-[SIGNING/INFO] : Success signing document");

                }catch(Exception e)
                {
                    e.printStackTrace();

                    status_code = 500;
                    response.put("result_code", "E50");
                    response.put("message", "Failed Signing Document");
                    response.put("error", e.toString());
                    response.put("timestamp", new Date().toInstant());

                    logger.info("[" + ds.VERSION + "]-[SIGNING/RESPONSE] : " + response);

                    return ResponseEntity
                            .status(status_code)
                            .contentType(MediaType.APPLICATION_JSON)
                            .body(response.toString());
                }
                finally {

                   if(directory.exists())
                   {
//                       FileUtils.deleteDirectory(directory);
                   }
                }

                
                return ResponseEntity
                        .status(status_code)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response.toString());
            }
    }

    private void checkLTV(File outFile)
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
        System.out.println("hexSignatureHash: " + hexSignatureHash);
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

            BEROctetString encodedSignature = new BEROctetString(crl.getSignature());
            byte[] crlSignatureHash = MessageDigest.getInstance("SHA-1").digest(encodedSignature.getEncoded());
            String hexCrlSignatureHash = Hex.getString(crlSignatureHash);
            System.out.println("hexCrlSignatureHash: " + hexCrlSignatureHash);

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
            BEROctetString encodedSignature = new BEROctetString(basicResponse.getSignature());
            byte[] ocspSignatureHash = MessageDigest.getInstance("SHA-1").digest(encodedSignature.getEncoded());
            String hexOcspSignatureHash = Hex.getString(ocspSignatureHash);
            System.out.println("ocspSignatureHash: " + hexOcspSignatureHash);
            long secondsOld = (System.currentTimeMillis() - basicResponse.getProducedAt().getTime()) / 1000;
            Assert.assertTrue("OCSP answer is too old, is from " + secondsOld + " seconds ago",
                    secondsOld < 20);

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

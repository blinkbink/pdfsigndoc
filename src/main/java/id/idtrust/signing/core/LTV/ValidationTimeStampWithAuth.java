package id.idtrust.signing.core.LTV;

import id.idtrust.signing.API.TSAClient;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ValidationTimeStampWithAuth {
    private TSAClient tsaClient;

    public ValidationTimeStampWithAuth(String tsaUrl, String username, String password) throws NoSuchAlgorithmException, MalformedURLException {
        if (tsaUrl != null) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            this.tsaClient = new TSAClient(new URL(tsaUrl), "devel19", "@Aminta77", digest);
        }

    }

    public byte[] getTimeStampToken(InputStream content) throws Exception {
        TimeStampToken timeStampToken = this.tsaClient.getTimeStampToken(IOUtils.toByteArray(content));
        return timeStampToken.getEncoded();
    }

    public CMSSignedData addSignedTimeStamp(CMSSignedData signedData) throws Exception {
        SignerInformationStore signerStore = signedData.getSignerInfos();
        List<SignerInformation> newSigners = new ArrayList();
        Iterator var4 = signerStore.getSigners().iterator();

        while(var4.hasNext()) {
            SignerInformation signer = (SignerInformation)var4.next();
            newSigners.add(this.signTimeStamp(signer));
        }

        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
    }

    private SignerInformation signTimeStamp(SignerInformation signer) throws Exception {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        TimeStampToken timeStampToken = this.tsaClient.getTimeStampToken(signer.getSignature());
        byte[] token = timeStampToken.getEncoded();
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
        ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));
        vector.add(signatureTimeStamp);
        Attributes signedAttributes = new Attributes(vector);
        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(signedAttributes));
    }
}

package id.idtrust.signing.core.LTV;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import id.idtrust.signing.core.LTV.CertInformationCollector;
import org.apache.pdfbox.util.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

public class CertInformationHelper {
    private static final Log LOG = LogFactory.getLog(CertInformationHelper.class);

    private CertInformationHelper() {
    }

    protected static String getSha1Hash(byte[] content) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return Hex.getString(md.digest(content));
        } catch (NoSuchAlgorithmException var2) {
            LOG.error("No SHA-1 Algorithm found", var2);
            return null;
        }
    }

    protected static void getAuthorityInfoExtensionValue(byte[] extensionValue, CertInformationCollector.CertSignatureInformation certInfo) throws IOException {
        ASN1Sequence asn1Seq = (ASN1Sequence)JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
        Enumeration<?> objects = asn1Seq.getObjects();

        while(true) {
            while(objects.hasMoreElements()) {
                ASN1Sequence obj = (ASN1Sequence)objects.nextElement();
                ASN1Encodable oid = obj.getObjectAt(0);
                ASN1TaggedObject location = (ASN1TaggedObject)obj.getObjectAt(1);
                ASN1OctetString uri;
                if (X509ObjectIdentifiers.id_ad_ocsp.equals(oid) && location.getTagNo() == 6) {
                    uri = (ASN1OctetString)location.getObject();
                    certInfo.setOcspUrl(new String(uri.getOctets()));
                } else if (X509ObjectIdentifiers.id_ad_caIssuers.equals(oid)) {
                    uri = (ASN1OctetString)location.getObject();
                    certInfo.setIssuerUrl(new String(uri.getOctets()));
                }
            }

            return;
        }
    }

    protected static String getCrlUrlFromExtensionValue(byte[] extensionValue) throws IOException {
        ASN1Sequence asn1Seq = (ASN1Sequence)JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
        Enumeration<?> objects = asn1Seq.getObjects();

        while(objects.hasMoreElements()) {
            Object obj = objects.nextElement();
            if (obj instanceof ASN1Sequence) {
                String url = extractCrlUrlFromSequence((ASN1Sequence)obj);
                if (url != null) {
                    return url;
                }
            }
        }

        return null;
    }

    private static String extractCrlUrlFromSequence(ASN1Sequence sequence) {
        ASN1TaggedObject taggedObject = (ASN1TaggedObject)sequence.getObjectAt(0);
        taggedObject = (ASN1TaggedObject)taggedObject.getObject();
        if (taggedObject.getObject() instanceof ASN1TaggedObject) {
            taggedObject = (ASN1TaggedObject)taggedObject.getObject();
        } else {
            if (!(taggedObject.getObject() instanceof ASN1Sequence)) {
                return null;
            }

            ASN1Sequence seq = (ASN1Sequence)taggedObject.getObject();
            if (!(seq.getObjectAt(0) instanceof ASN1TaggedObject)) {
                return null;
            }

            taggedObject = (ASN1TaggedObject)seq.getObjectAt(0);
        }

        if (taggedObject.getObject() instanceof ASN1OctetString) {
            ASN1OctetString uri = (ASN1OctetString)taggedObject.getObject();
            String url = new String(uri.getOctets());
            if (url.startsWith("http")) {
                return url;
            }
        }

        return null;
    }
}

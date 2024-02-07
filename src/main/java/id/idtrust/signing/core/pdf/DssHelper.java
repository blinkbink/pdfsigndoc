package id.idtrust.signing.core.pdf;


import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.examples.signature.cert.CRLVerifier;

import java.io.*;
import java.net.URI;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


public class DssHelper {

    public DssHelper() {

    }

    public COSDictionary createDssDictionary(Iterable<byte[]> certifiates, Iterable<byte[]> crls, Iterable<byte[]> ocspResponses) throws IOException
    {
        final COSDictionary dssDictionary = new COSDictionary();
        dssDictionary.setNeedToBeUpdated(true);
        dssDictionary.setName(COSName.TYPE, "DSS");

        if (certifiates != null)
            dssDictionary.setItem(COSName.getPDFName("Certs"), createArray(certifiates));
        if (crls != null)
            dssDictionary.setItem(COSName.getPDFName("CRLs"), createArray(crls));
        if (ocspResponses != null)
            dssDictionary.setItem(COSName.getPDFName("OCSPs"), createArray(ocspResponses));

        return dssDictionary;
    }

    public COSArray createArray(Iterable<byte[]> datas) throws IOException
    {
        COSArray array = new COSArray();
        array.setNeedToBeUpdated(true);

        if (datas != null)
        {
            for (byte[] data: datas)
                array.add(createStream(data));
        }

        return array;
    }

    public COSStream createStream(byte[] data) throws IOException {
        //RandomAccessBuffer storage = new RandomAccessBuffer();
        COSStream stream = new COSStream();
        stream.setNeedToBeUpdated(true);
        final OutputStream unfilteredStream = stream.createOutputStream(COSName.FLATE_DECODE);
        unfilteredStream.write(data);
        unfilteredStream.flush();
        unfilteredStream.close();
        return stream;
    }

    public List<CRL> readCRLsFromCert(X509Certificate cert)
            throws Exception {

        List<CRL> crls = new ArrayList<>();
        List<String> crlll=CRLVerifier.getCrlDistributionPoints(cert);
        for (String url:crlll){
            crls.add(CRLVerifier.downloadCRLFromWeb(url));

        }
        return crls;
    }

    public Collection<? extends CRL> loadCRLs(String src) throws Exception {
        InputStream in = null;
        URI uri = null;
        if (src == null) {
            in = System.in;
        } else {
            try {
                uri = new URI(src);
                if (uri.getScheme().equals("ldap")) {
                    // No input stream for LDAP
                } else {
                    in = uri.toURL().openStream();
                }
            } catch (Exception e) {
                try {
                    in = new FileInputStream(src);
                } catch (Exception e2) {
                    if (uri == null || uri.getScheme() == null) {
                        throw e2;   // More likely a bare file path
                    } else {
                        throw e;    // More likely a protocol or network problem
                    }
                }
            }
        }
        if (in != null) {
            try {
                // Read the full stream before feeding to X509Factory,
                // otherwise, keytool -gencrl | keytool -printcrl
                // might not work properly, since -gencrl is slow
                // and there's no data in the pipe at the beginning.
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                byte[] b = new byte[4096];
                while (true) {
                    int len = in.read(b);
                    if (len < 0) break;
                    bout.write(b, 0, len);
                }
                return CertificateFactory.getInstance("X509").generateCRLs(
                        new ByteArrayInputStream(bout.toByteArray()));
            } finally {
                if (in != System.in) {
                    in.close();
                }
            }
        } else {    // must be LDAP, and uri is not null
            throw new Exception("error");
        }
    }
}
package id.idtrust.signing.API;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;

public class TSAClient {
    private static final Log LOG = LogFactory.getLog(org.apache.pdfbox.examples.signature.TSAClient.class);
    private final URL url;
    private final String username;
    private final String password;
    private final MessageDigest digest;
    private static final Random RANDOM = new SecureRandom();

    public TSAClient(URL url, String username, String password, MessageDigest digest) {
        this.url = url;
        this.username = username;
        this.password = password;
        this.digest = digest;
    }

    public TimeStampToken getTimeStampToken(byte[] content) throws Exception {
        this.digest.reset();
        byte[] hash = this.digest.digest(content);
        int nonce = RANDOM.nextInt();
        TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
        tsaGenerator.setCertReq(true);
        ASN1ObjectIdentifier oid = this.getHashObjectIdentifier(this.digest.getAlgorithm());
        TimeStampRequest request = tsaGenerator.generate(oid, hash, BigInteger.valueOf((long)nonce));
        byte[] tsaResponse = this.getTSAResponse(request.getEncoded());

        TimeStampResponse response;
        try {
            response = new TimeStampResponse(tsaResponse);
            response.validate(request);
        } catch (TSPException var10) {
            throw new IOException(var10);
        }

        TimeStampToken timeStampToken = response.getTimeStampToken();
        if (timeStampToken == null) {
            throw new IOException("Response from " + this.url + " does not have a time stamp token, status: " + response.getStatus() + " (" + response.getStatusString() + ")");
        } else {
            return timeStampToken;
        }
    }

    private byte[] getTSAResponse(byte[] request) throws Exception {
        LOG.debug("Opening connection to TSA server");
        URLConnection connection = this.url.openConnection();

        if (username != null && password != null && !username.isEmpty() && !password.isEmpty())
        {
            connection.setRequestProperty("Authorization",
                    "Basic " + new String(Base64.encode((username + ":" + password).
                            getBytes(StandardCharsets.UTF_8))));
        }

        connection.setDoOutput(true);
        connection.setDoInput(true);

        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        LOG.debug("Established connection to TSA server");

//        String authen = new String(Base64.encode((username + ":" + password).getBytes()));
//
//        if (this.username != null && this.password != null && !this.username.isEmpty() && !this.password.isEmpty())
//        {
//            connection.setRequestProperty("Authorization", "Basic " + authen);
//        }

        OutputStream output = null;

        try {
            output = connection.getOutputStream();
            output.write(request);
        } catch (Exception var18) {
            LOG.error("Exception when writing to " + this.url, var18);
            throw new Exception("Exception when writing to " + this.url + " " +var18);
        } finally {
            IOUtils.closeQuietly(output);
        }

        LOG.debug("Waiting for response from TSA server");
        InputStream input = null;

        byte[] response;
        try {
            input = connection.getInputStream();
            response = IOUtils.toByteArray(input);
        } catch (IOException var16) {
            LOG.error("Exception when reading from " + this.url, var16);
            throw var16;
        } finally {
            IOUtils.closeQuietly(input);
        }

        LOG.debug("Received response from TSA server");
        return response;
    }

    private ASN1ObjectIdentifier getHashObjectIdentifier(String algorithm) {
        if (algorithm.equals("MD2")) {
            return new ASN1ObjectIdentifier(PKCSObjectIdentifiers.md2.getId());
        } else if (algorithm.equals("MD5")) {
            return new ASN1ObjectIdentifier(PKCSObjectIdentifiers.md5.getId());
        } else if (algorithm.equals("SHA-1")) {
            return new ASN1ObjectIdentifier(OIWObjectIdentifiers.idSHA1.getId());
        } else if (algorithm.equals("SHA-224")) {
            return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha224.getId());
        } else if (algorithm.equals("SHA-256")) {
            return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.getId());
        } else if (algorithm.equals("SHA-384")) {
            return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha384.getId());
        } else {
            return algorithm.equals("SHA-512") ? new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha512.getId()) : new ASN1ObjectIdentifier(algorithm);
        }
    }
}

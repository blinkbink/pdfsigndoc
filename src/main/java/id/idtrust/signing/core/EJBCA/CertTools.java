//package com.digisign.kms.core.EJBCA;
//
//
//import com.digisign.kms.core.certificate.CertificateRequest;
//import com.digisign.kms.util.LogSystem;
//import com.novell.ldap.LDAPDN;
//import java.io.BufferedReader;
//import java.io.ByteArrayInputStream;
//import java.io.ByteArrayOutputStream;
//import java.io.FileInputStream;
//import java.io.FileNotFoundException;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.InputStreamReader;
//import java.io.PrintStream;
//import java.math.BigInteger;
//import java.net.MalformedURLException;
//import java.net.URL;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.KeyFactory;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.SecureRandom;
//import java.security.cert.CRL;
//import java.security.cert.CRLException;
//import java.security.cert.CertPath;
//import java.security.cert.CertPathValidator;
//import java.security.cert.CertPathValidatorException;
//import java.security.cert.CertPathValidatorResult;
//import java.security.cert.Certificate;
//import java.security.cert.CertificateEncodingException;
//import java.security.cert.CertificateException;
//import java.security.cert.CertificateExpiredException;
//import java.security.cert.CertificateFactory;
//import java.security.cert.CertificateNotYetValidException;
//import java.security.cert.CertificateParsingException;
//import java.security.cert.PKIXCertPathChecker;
//import java.security.cert.PKIXCertPathValidatorResult;
//import java.security.cert.PKIXParameters;
//import java.security.cert.TrustAnchor;
//import java.security.cert.X509CRL;
//import java.security.cert.X509Certificate;
//import java.security.interfaces.ECPublicKey;
//import java.security.interfaces.RSAPublicKey;
//import java.security.spec.ECPublicKeySpec;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.RSAPublicKeySpec;
//import java.util.ArrayList;
//import java.util.Collection;
//import java.util.Collections;
//import java.util.Date;
//import java.util.Enumeration;
//import java.util.HashMap;
//import java.util.HashSet;
//import java.util.Iterator;
//import java.util.List;
//
//import org.apache.commons.lang.CharUtils;
//import org.apache.commons.lang.StringUtils;
//import org.apache.commons.lang.math.NumberUtils;
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
//import org.bouncycastle.asn1.ASN1Encodable;
//import org.bouncycastle.asn1.ASN1EncodableVector;
//import org.bouncycastle.asn1.ASN1Integer;
//import org.bouncycastle.asn1.ASN1ObjectIdentifier;
//import org.bouncycastle.asn1.ASN1OctetString;
//import org.bouncycastle.asn1.ASN1Primitive;
//import org.bouncycastle.asn1.ASN1Sequence;
//import org.bouncycastle.asn1.ASN1Set;
//import org.bouncycastle.asn1.ASN1TaggedObject;
//import org.bouncycastle.asn1.DERBitString;
//import org.bouncycastle.asn1.DERGeneralString;
//import org.bouncycastle.asn1.DERGeneralizedTime;
//import org.bouncycastle.asn1.DERIA5String;
//import org.bouncycastle.asn1.DEROctetString;
//import org.bouncycastle.asn1.DERSequence;
//import org.bouncycastle.asn1.DERTaggedObject;
//import org.bouncycastle.asn1.DERUTF8String;
//import org.bouncycastle.asn1.pkcs.Attribute;
//import org.bouncycastle.asn1.pkcs.CertificationRequest;
//import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
//import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
//import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
//import org.bouncycastle.asn1.x500.RDN;
//import org.bouncycastle.asn1.x500.X500Name;
//import org.bouncycastle.asn1.x500.X500NameBuilder;
//import org.bouncycastle.asn1.x500.X500NameStyle;
//import org.bouncycastle.asn1.x500.style.IETFUtils;
//import org.bouncycastle.asn1.x509.AccessDescription;
//import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
//import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
//import org.bouncycastle.asn1.x509.BasicConstraints;
//import org.bouncycastle.asn1.x509.Extension;
//import org.bouncycastle.asn1.x509.Extensions;
//import org.bouncycastle.asn1.x509.GeneralName;
//import org.bouncycastle.asn1.x509.GeneralNames;
//import org.bouncycastle.asn1.x509.GeneralSubtree;
//import org.bouncycastle.asn1.x509.KeyPurposeId;
//import org.bouncycastle.asn1.x509.NameConstraints;
//import org.bouncycastle.asn1.x509.PolicyInformation;
//import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
//import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
//import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
//import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
//import org.bouncycastle.cert.CertIOException;
//import org.bouncycastle.cert.X509CRLHolder;
//import org.bouncycastle.cert.X509CertificateHolder;
//import org.bouncycastle.cert.X509v3CertificateBuilder;
//import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
//import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
//import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
//import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
//import org.bouncycastle.cms.CMSAbsentContent;
//import org.bouncycastle.cms.CMSException;
//import org.bouncycastle.cms.CMSSignedData;
//import org.bouncycastle.cms.CMSSignedDataGenerator;
//import org.bouncycastle.jce.X509KeyUsage;
//import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
//import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
//import org.bouncycastle.openssl.PEMParser;
//import org.bouncycastle.operator.BufferingContentSigner;
//import org.bouncycastle.operator.ContentSigner;
//import org.bouncycastle.operator.ContentVerifierProvider;
//import org.bouncycastle.operator.OperatorCreationException;
//import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
//import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
//import org.bouncycastle.pkcs.PKCS10CertificationRequest;
//import org.bouncycastle.util.CollectionStore;
//import org.bouncycastle.util.encoders.DecoderException;
//import org.bouncycastle.util.encoders.Hex;
//import org.cesecore.certificates.ca.IllegalNameException;
//import org.cesecore.certificates.certificate.CertificateWrapper;
//import org.cesecore.certificates.crl.RevokedCertInfo;
//import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
//import org.cesecore.certificates.util.DnComponents;
//import org.cesecore.config.OcspConfiguration;
//import org.cesecore.internal.InternalResources;
//import org.cesecore.util.*;
//import org.ejbca.cvc.AuthorizationRole;
//import org.ejbca.cvc.CVCAuthorizationTemplate;
//import org.ejbca.cvc.CVCObject;
//import org.ejbca.cvc.CVCertificate;
//import org.ejbca.cvc.CardVerifiableCertificate;
//import org.ejbca.cvc.CertificateParser;
//import org.ejbca.cvc.ReferenceField;
//import org.ejbca.cvc.exception.ConstructionException;
//import org.ejbca.cvc.exception.ParseException;
//
//public abstract class CertTools {
//    private final static Logger log = LogManager.getLogger(CertTools.class);
//    private static final InternalResources intres = InternalResources.getInstance();
//    public static final String EMAIL = "rfc822name";
//    public static final String EMAIL1 = "email";
//    public static final String EMAIL2 = "EmailAddress";
//    public static final String EMAIL3 = "E";
//    public static final String DNS = "dNSName";
//    public static final String URI = "uniformResourceIdentifier";
//    public static final String URI1 = "uri";
//    public static final String URI2 = "uniformResourceId";
//    public static final String IPADDR = "iPAddress";
//    public static final String DIRECTORYNAME = "directoryName";
//    public static final String REGISTEREDID = "registeredID";
//    public static final String XMPPADDR = "xmppAddr";
//    public static final String SRVNAME = "srvName";
//    public static final String KRB5PRINCIPAL = "krb5principal";
//    public static final String KRB5PRINCIPAL_OBJECTID = "1.3.6.1.5.2.2";
//    public static final String UPN = "upn";
//    public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
//    public static final String XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
//    public static final String SRVNAME_OBJECTID = "1.3.6.1.5.5.7.8.7";
//    public static final String PERMANENTIDENTIFIER = "permanentIdentifier";
//    public static final String PERMANENTIDENTIFIER_OBJECTID = "1.3.6.1.5.5.7.8.3";
//    public static final String PERMANENTIDENTIFIER_SEP = "/";
//    public static final String GUID = "guid";
//    public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";
//    public static final String EFS_OBJECTID = "1.3.6.1.4.1.311.10.3.4";
//    public static final String EFSR_OBJECTID = "1.3.6.1.4.1.311.10.3.4.1";
//    public static final String MS_DOCUMENT_SIGNING_OBJECTID = "1.3.6.1.4.1.311.10.3.12";
//    public static final String id_pkix = "1.3.6.1.5.5.7";
//    public static final String id_kp = "1.3.6.1.5.5.7.3";
//    public static final String id_pda = "1.3.6.1.5.5.7.9";
//    public static final String id_pda_dateOfBirth = "1.3.6.1.5.5.7.9.1";
//    public static final String id_pda_placeOfBirth = "1.3.6.1.5.5.7.9.2";
//    public static final String id_pda_gender = "1.3.6.1.5.5.7.9.3";
//    public static final String id_pda_countryOfCitizenship = "1.3.6.1.5.5.7.9.4";
//    public static final String id_pda_countryOfResidence = "1.3.6.1.5.5.7.9.5";
//    public static final String OID_MSTEMPLATE = "1.3.6.1.4.1.311.20.2";
//    public static final String Intel_amt = "2.16.840.1.113741.1.2.3";
//    public static final String id_ct_redacted_domains = "1.3.6.1.4.1.11129.2.4.6";
//    private static final String[] EMAILIDS;
//    public static final String BEGIN_CERTIFICATE_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----";
//    public static final String END_CERTIFICATE_REQUEST = "-----END CERTIFICATE REQUEST-----";
//    public static final String BEGIN_KEYTOOL_CERTIFICATE_REQUEST = "-----BEGIN NEW CERTIFICATE REQUEST-----";
//    public static final String END_KEYTOOL_CERTIFICATE_REQUEST = "-----END NEW CERTIFICATE REQUEST-----";
//    public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
//    public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
//    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
//    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
//    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
//    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
//    public static final String BEGIN_X509_CRL_KEY = "-----BEGIN X509 CRL-----";
//    public static final String END_X509_CRL_KEY = "-----END X509 CRL-----";
//    public static final String BEGIN_PKCS7 = "-----BEGIN PKCS7-----";
//    public static final String END_PKCS7 = "-----END PKCS7-----";
//
//    public CertTools() {
//    }
//
//    public static X500Name stringToBcX500Name(String dn) {
//        X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
//        return stringToBcX500Name(dn, nameStyle, true);
//    }
//
//    public static X500Name stringToBcX500Name(String dn, boolean ldapOrder) {
//        X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
//        return stringToBcX500Name(dn, nameStyle, ldapOrder);
//    }
//
//    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder) {
//        return stringToBcX500Name(dn, nameStyle, ldaporder, (String[])null);
//    }
//
//    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder, String[] order) {
//        return stringToBcX500Name(dn, nameStyle, ldaporder, order, true);
//    }
//
//    public static X500Name stringToBcX500Name(String dn, X500NameStyle nameStyle, boolean ldaporder, String[] order, boolean applyLdapToCustomOrder) {
//        X500Name x500Name = stringToUnorderedX500Name(dn, nameStyle);
//        if (x500Name == null) {
//            return null;
//        } else {
//            X500Name orderedX500Name = getOrderedX500Name(x500Name, ldaporder, order, applyLdapToCustomOrder, nameStyle);
//            if (log.isTraceEnabled()) {
//                log.trace(">stringToBcX500Name: x500Name=" + x500Name.toString() + " orderedX500Name=" + orderedX500Name.toString());
//            }
//
//            return orderedX500Name;
//        }
//    }
//
//    public static X500Name stringToUnorderedX500Name(String dn, X500NameStyle nameStyle) {
//        if (log.isTraceEnabled()) {
//            log.trace(">stringToUnorderedX500Name: " + dn);
//        }
//
//        if (dn == null) {
//            return null;
//        } else {
//            if (dn.length() > 2 && dn.charAt(0) == '"' && dn.charAt(dn.length() - 1) == '"') {
//                dn = dn.substring(1, dn.length() - 1);
//            }
//
//            X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
//            boolean quoted = false;
//            boolean escapeNext = false;
//            int currentStartPosition = -1;
//            String currentPartName = null;
//
//            for(int i = 0; i < dn.length(); ++i) {
//                char current = dn.charAt(i);
//                if (!escapeNext && current == '"') {
//                    quoted = !quoted;
//                }
//
//                int endPosition;
//                if (currentStartPosition == -1 && !quoted && !escapeNext && current == '=' && 1 <= i) {
//                    for(endPosition = i; endPosition > 0 && dn.charAt(endPosition - 1) == ' '; --endPosition) {
//                    }
//
//                    int startIndexOfPartName = endPosition - 1;
//
//                    for(String var11 = ", +"; startIndexOfPartName > 0 && ", +".indexOf(dn.charAt(startIndexOfPartName - 1)) == -1; --startIndexOfPartName) {
//                    }
//
//                    currentPartName = dn.substring(startIndexOfPartName, endPosition);
//                    currentStartPosition = i + 1;
//                }
//
//                if (currentStartPosition != -1 && (!quoted && !escapeNext && (current == ',' || current == '+') || i == dn.length() - 1)) {
//                    for(endPosition = i == dn.length() - 1 ? dn.length() - 1 : i - 1; endPosition > currentStartPosition && dn.charAt(endPosition) == ' '; --endPosition) {
//                    }
//
//                    while(endPosition > currentStartPosition && dn.charAt(currentStartPosition) == ' ') {
//                        ++currentStartPosition;
//                    }
//
//                    if (currentStartPosition < dn.length() && dn.charAt(currentStartPosition) == '"' && dn.charAt(endPosition) == '"') {
//                        ++currentStartPosition;
//                        --endPosition;
//                    }
//
//                    String currentValue = dn.substring(currentStartPosition, endPosition + 1);
//                    currentValue = unescapeValue(new StringBuilder(currentValue)).toString();
//
//                    try {
//                        ASN1ObjectIdentifier oid = DnComponents.getOid(currentPartName);
//                        if (oid == null) {
//                            oid = new ASN1ObjectIdentifier(currentPartName);
//                        }
//
//                        nameBuilder.addRDN(oid, currentValue);
//                    } catch (IllegalArgumentException var12) {
//                        log.warn("Unknown DN component ignored and silently dropped: " + currentPartName);
//                    }
//
//                    currentStartPosition = -1;
//                    currentPartName = null;
//                }
//
//                if (escapeNext) {
//                    escapeNext = false;
//                } else if (!quoted && current == '\\') {
//                    escapeNext = true;
//                }
//            }
//
//            X500Name x500Name = nameBuilder.build();
//            if (log.isTraceEnabled()) {
//                log.trace("<stringToUnorderedX500Name: x500Name=" + x500Name.toString());
//            }
//
//            return x500Name;
//        }
//    }
//
//    private static StringBuilder unescapeValue(StringBuilder sb) {
//        boolean esq = false;
//        int index = 0;
//
//        while(true) {
//            while(index < sb.length() - 1) {
//                if (!esq && sb.charAt(index) == '\\' && sb.charAt(index + 1) != '#') {
//                    esq = true;
//                    sb.deleteCharAt(index);
//                } else {
//                    esq = false;
//                    ++index;
//                }
//            }
//
//            return sb;
//        }
//    }
//
//    public static String getUnescapedPlus(String value) {
//        StringBuilder buf = new StringBuilder(value);
//        int index = 0;
//
//        for(int end = buf.length(); index < end; ++index) {
//            if (buf.charAt(index) == '\\' && index + 1 != end) {
//                char c = buf.charAt(index + 1);
//                if (c == '+') {
//                    buf.deleteCharAt(index);
//                    --end;
//                }
//            }
//        }
//
//        return buf.toString();
//    }
//
//    public static String handleUnescapedPlus(String dn) {
//        if (dn == null) {
//            return dn;
//        } else {
//            StringBuilder buf = new StringBuilder(dn);
//            int index = 0;
//
//            for(int end = buf.length(); index < end; ++index) {
//                if (buf.charAt(index) == '+') {
//                    log.warn("DN \"" + dn + "\" contains an unescaped '+'-character that will be automatically escaped. RFC 2253 reservs this for multi-valued RelativeDistinguishedNames. Encourage clients to use '\\+' instead, since future behaviour might change.");
//                    buf.insert(index, '\\');
//                    ++index;
//                } else if (buf.charAt(index) == '\\') {
//                    ++index;
//                }
//            }
//
//            return buf.toString();
//        }
//    }
//
//    public static String stringToBCDNString(String dn) {
//        dn = handleUnescapedPlus(dn);
//        if (isDNReversed(dn)) {
//            dn = reverseDN(dn);
//        }
//
//        String ret = null;
//        X500Name name = stringToBcX500Name(dn);
//        if (name != null) {
//            ret = name.toString();
//        }
//
//        if (ret != null && ret.length() > 250) {
//            log.info("Warning! DN is more than 250 characters long. Some databases have only 250 characters in the database for SubjectDN. Clipping may occur! DN (" + ret.length() + " chars): " + ret);
//        }
//
//        return ret;
//    }
//
//    public static ArrayList<String> getEmailFromDN(String dn) {
//        if (log.isTraceEnabled()) {
//            log.trace(">getEmailFromDN(" + dn + ")");
//        }
//
//        ArrayList<String> ret = new ArrayList();
//
//        for(int i = 0; i < EMAILIDS.length; ++i) {
//            List<String> emails = getPartsFromDN(dn, EMAILIDS[i]);
//            if (!emails.isEmpty()) {
//                ret.addAll(emails);
//            }
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("<getEmailFromDN(" + dn + "): " + ret.size());
//        }
//
//        return ret;
//    }
//
//    public static String getEMailAddress(Certificate certificate) {
//        log.debug("Searching for EMail Address in SubjectAltName");
//        if (certificate == null) {
//            return null;
//        } else {
//            if (certificate instanceof X509Certificate) {
//                X509Certificate x509cert = (X509Certificate)certificate;
//
//                try {
//                    if (x509cert.getSubjectAlternativeNames() != null) {
//                        Iterator var2 = x509cert.getSubjectAlternativeNames().iterator();
//
//                        while(var2.hasNext()) {
//                            List<?> item = (List)var2.next();
//                            Integer type = (Integer)item.get(0);
//                            if (type == 1) {
//                                return (String)item.get(1);
//                            }
//                        }
//                    }
//                } catch (CertificateParsingException var5) {
//                    log.error("Error parsing certificate: ", var5);
//                }
//
//                log.debug("Searching for EMail Address in Subject DN");
//                ArrayList<String> emails = getEmailFromDN(x509cert.getSubjectDN().getName());
//                if (!emails.isEmpty()) {
//                    return (String)emails.get(0);
//                }
//            }
//
//            return null;
//        }
//    }
//
//    public static String reverseDN(String dn) {
//        if (log.isTraceEnabled()) {
//            log.trace(">reverseDN: dn: " + dn);
//        }
//
//        String ret = null;
//        if (dn != null) {
//            BasicX509NameTokenizer xt = new BasicX509NameTokenizer(dn);
//            StringBuilder buf = new StringBuilder();
//
//            String o;
//            for(boolean first = true; xt.hasMoreTokens(); buf.insert(0, o)) {
//                o = xt.nextToken();
//                if (!first) {
//                    buf.insert(0, ",");
//                } else {
//                    first = false;
//                }
//            }
//
//            if (buf.length() > 0) {
//                ret = buf.toString();
//            }
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("<reverseDN: resulting dn: " + ret);
//        }
//
//        return ret;
//    }
//
//    public static boolean isDNReversed(String dn) {
//        boolean ret = false;
//        if (dn != null) {
//            String first = null;
//            String last = null;
//            X509NameTokenizer xt = new X509NameTokenizer(dn);
//            if (xt.hasMoreTokens()) {
//                first = xt.nextToken().trim();
//            }
//
//            while(xt.hasMoreTokens()) {
//                last = xt.nextToken().trim();
//            }
//
//            String[] dNObjects = DnComponents.getDnObjects(true);
//            if (first != null && last != null) {
//                first = first.substring(0, first.indexOf(61));
//                last = last.substring(0, last.indexOf(61));
//                int firsti = 0;
//                int lasti = 0;
//
//                for(int i = 0; i < dNObjects.length; ++i) {
//                    if (first.equalsIgnoreCase(dNObjects[i])) {
//                        firsti = i;
//                    }
//
//                    if (last.equalsIgnoreCase(dNObjects[i])) {
//                        lasti = i;
//                    }
//                }
//
//                if (lasti < firsti) {
//                    ret = true;
//                }
//            }
//        }
//
//        return ret;
//    }
//
//    public static boolean dnHasMultipleComponents(String dn) {
//        X509NameTokenizer xt = new X509NameTokenizer(dn);
//        if (xt.hasMoreTokens()) {
//            xt.nextToken();
//            return xt.hasMoreTokens();
//        } else {
//            return false;
//        }
//    }
//
//    public static String getPartFromDN(String dn, String dnpart) {
//        String part = null;
//        List<String> dnParts = getPartsFromDNInternal(dn, dnpart, true);
//        if (!dnParts.isEmpty()) {
//            part = (String)dnParts.get(0);
//        }
//
//        return part;
//    }
//
//    public static List<String> getPartsFromDN(String dn, String dnpart) {
//        return getPartsFromDNInternal(dn, dnpart, false);
//    }
//
//    public static List<String> getPartsFromDNInternal(String dn, String dnPart, boolean onlyReturnFirstMatch) {
//        if (log.isTraceEnabled()) {
//            log.trace(">getPartsFromDNInternal: dn:'" + dn + "', dnpart=" + dnPart + ", onlyReturnFirstMatch=" + onlyReturnFirstMatch);
//        }
//
//        List<String> parts = new ArrayList();
//        if (dn != null && dnPart != null) {
//            String dnPartLowerCase = dnPart.toLowerCase();
//            int dnPartLenght = dnPart.length();
//            boolean quoted = false;
//            boolean escapeNext = false;
//            int currentStartPosition = -1;
//
//            for(int i = 0; i < dn.length(); ++i) {
//                char current = dn.charAt(i);
//                if (!escapeNext && current == '"') {
//                    quoted = !quoted;
//                }
//
//                if (!quoted && !escapeNext && current == '=' && dnPartLenght <= i && (i - dnPartLenght - 1 < 0 || !Character.isLetter(dn.charAt(i - dnPartLenght - 1)))) {
//                    boolean match = true;
//
//                    for(int j = 0; j < dnPartLenght; ++j) {
//                        if (Character.toLowerCase(dn.charAt(i - dnPartLenght + j)) != dnPartLowerCase.charAt(j)) {
//                            match = false;
//                            break;
//                        }
//                    }
//
//                    if (match) {
//                        currentStartPosition = i + 1;
//                    }
//                }
//
//                if (currentStartPosition != -1 && (!quoted && !escapeNext && (current == ',' || current == '+') || i == dn.length() - 1)) {
//                    int endPosition;
//                    for(endPosition = i == dn.length() - 1 ? dn.length() - 1 : i - 1; endPosition > currentStartPosition && dn.charAt(endPosition) == ' '; --endPosition) {
//                    }
//
//                    while(endPosition > currentStartPosition && dn.charAt(currentStartPosition) == ' ') {
//                        ++currentStartPosition;
//                    }
//
//                    if (currentStartPosition != dn.length() && dn.charAt(currentStartPosition) == '"' && dn.charAt(endPosition) == '"') {
//                        ++currentStartPosition;
//                        --endPosition;
//                    }
//
//                    parts.add(dn.substring(currentStartPosition, endPosition + 1));
//                    if (onlyReturnFirstMatch) {
//                        break;
//                    }
//
//                    currentStartPosition = -1;
//                }
//
//                if (escapeNext) {
//                    escapeNext = false;
//                } else if (!quoted && current == '\\') {
//                    escapeNext = true;
//                }
//            }
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("<getPartsFromDNInternal: resulting DN part=" + parts.toString());
//        }
//
//        return parts;
//    }
//
//    public static ArrayList<String> getCustomOids(String dn) {
//        if (log.isTraceEnabled()) {
//            log.trace(">getCustomOids: dn:'" + dn);
//        }
//
//        ArrayList<String> parts = new ArrayList();
//        if (dn != null) {
//            X509NameTokenizer xt = new X509NameTokenizer(dn);
//
//            while(xt.hasMoreTokens()) {
//                String o = xt.nextToken().trim();
//
//                try {
//                    int i = o.indexOf(61);
//                    if (i > 2 && o.charAt(1) == '.') {
//                        String oid = o.substring(0, i);
//                        if (!parts.contains(oid)) {
//                            new ASN1ObjectIdentifier(oid);
//                            parts.add(oid);
//                        }
//                    }
//                } catch (IllegalArgumentException var6) {
//                }
//            }
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("<getCustomOids: resulting DN part=" + parts.toString());
//        }
//
//        return parts;
//    }
//
//    public static String getSubjectDN(Certificate cert) {
//        return getDN(cert, 1);
//    }
//
//    public static String getIssuerDN(Certificate cert) {
//        return getDN(cert, 2);
//    }
//
//    private static String getDN(Certificate cert, int which) {
//        String ret = null;
//        if (cert == null) {
//            return null;
//        } else {
//            X509Certificate x509cert = null;
//            String dn;
//            if (cert instanceof X509Certificate) {
//                String clazz = cert.getClass().getName();
////                    CertificateFactory dns;
////                    if (clazz.contains("org.bouncycastle")) {
////                        x509cert = (X509Certificate)cert;
////                    } else {
////                        dns = getCertificateFactory();
////                        x509cert = (X509Certificate)dns.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
////                    }
////
////                    dns = null;
//                if (which == 1) {
//                    dn = x509cert.getSubjectDN().toString();
//                } else {
//                    dn = x509cert.getIssuerDN().toString();
//                }
//
//                ret = stringToBCDNString(dn);
//            } else if (StringUtils.equals(cert.getType(), "CVC")) {
//                CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//
//                try {
//                    x509cert = null;
//                    Object rf;
//                    if (which == 1) {
//                        rf = cvccert.getCVCertificate().getCertificateBody().getHolderReference();
//                    } else {
//                        rf = cvccert.getCVCertificate().getCertificateBody().getAuthorityReference();
//                    }
//
//                    if (rf != null) {
//                        dn = "";
//                        if (((ReferenceField)rf).getMnemonic() != null) {
//                            if (StringUtils.isNotEmpty(dn)) {
//                                dn = dn + ", ";
//                            }
//
//                            dn = dn + "CN=" + ((ReferenceField)rf).getMnemonic();
//                        }
//
//                        if (((ReferenceField)rf).getCountry() != null) {
//                            if (StringUtils.isNotEmpty(dn)) {
//                                dn = dn + ", ";
//                            }
//
//                            dn = dn + "C=" + ((ReferenceField)rf).getCountry();
//                        }
//
//                        ret = stringToBCDNString(dn);
//                    }
//                } catch (NoSuchFieldException var6) {
//                    log.error("NoSuchFieldException: ", var6);
//                    return null;
//                }
//            }
//
//            return ret;
//        }
//    }
//
//    public static BigInteger getSerialNumber(Certificate cert) {
//        if (cert == null) {
//            throw new IllegalArgumentException("Null input");
//        } else {
//            BigInteger ret = null;
//            if (cert instanceof X509Certificate) {
//                X509Certificate xcert = (X509Certificate)cert;
//                ret = xcert.getSerialNumber();
//            } else {
//                if (!StringUtils.equals(cert.getType(), "CVC")) {
//                    throw new IllegalArgumentException("getSerialNumber: Certificate of type " + cert.getType() + " is not implemented");
//                }
//
//                CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//
//                try {
//                    String sequence = cvccert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
//                    ret = getSerialNumberFromString(sequence);
//                } catch (NoSuchFieldException var4) {
//                    log.error("getSerialNumber: NoSuchFieldException: ", var4);
//                    ret = BigInteger.valueOf(0L);
//                }
//            }
//
//            return ret;
//        }
//    }
//
//    public static BigInteger getSerialNumberFromString(String sernoString) {
//        if (sernoString == null) {
//            throw new IllegalArgumentException("getSerialNumberFromString: cert is null");
//        } else {
//            BigInteger ret;
//            try {
//                if (sernoString.length() != 5) {
//                    ret = new BigInteger(sernoString, 16);
//                } else if (NumberUtils.isNumber(sernoString)) {
//                    ret = NumberUtils.createBigInteger(sernoString);
//                } else {
//                    log.info("getSerialNumber: Sequence is not a numeric string, trying to extract numerical sequence part.");
//                    StringBuilder buf = new StringBuilder();
//
//                    int numSeq;
//                    for(numSeq = 0; numSeq < sernoString.length(); ++numSeq) {
//                        char c = sernoString.charAt(numSeq);
//                        if (CharUtils.isAsciiNumeric(c)) {
//                            buf.append(c);
//                        }
//                    }
//
//                    if (buf.length() > 0) {
//                        ret = NumberUtils.createBigInteger(buf.toString());
//                    } else {
//                        log.info("getSerialNumber: can not extract numeric sequence part, trying alfanumeric value (radix 36).");
//                        if (sernoString.matches("[0-9A-Z]{1,5}")) {
//                            numSeq = Integer.parseInt(sernoString, 36);
//                            ret = BigInteger.valueOf((long)numSeq);
//                        } else {
//                            log.info("getSerialNumber: Sequence does not contain any numeric parts, returning 0.");
//                            ret = BigInteger.valueOf(0L);
//                        }
//                    }
//                }
//            } catch (NumberFormatException var5) {
//                log.debug("getSerialNumber: NumberFormatException for sequence: " + sernoString);
//                ret = BigInteger.valueOf(0L);
//            }
//
//            return ret;
//        }
//    }
//
//    public static String getSerialNumberAsString(Certificate cert) {
//        String ret = null;
//        if (cert == null) {
//            throw new IllegalArgumentException("getSerialNumber: cert is null");
//        } else {
//            if (cert instanceof X509Certificate) {
//                X509Certificate xcert = (X509Certificate)cert;
//                ret = xcert.getSerialNumber().toString(16).toUpperCase();
//            } else {
//                if (!StringUtils.equals(cert.getType(), "CVC")) {
//                    throw new IllegalArgumentException("getSerialNumber: Certificate of type " + cert.getType() + " is not implemented");
//                }
//
//                CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//
//                try {
//                    ret = cvccert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
//                } catch (NoSuchFieldException var4) {
//                    log.error("getSerialNumber: NoSuchFieldException: ", var4);
//                    ret = "N/A";
//                }
//            }
//
//            return ret;
//        }
//    }
//
//    public static byte[] getSignature(Certificate cert) {
//        byte[] ret = null;
//        if (cert == null) {
//            ret = new byte[0];
//        } else if (cert instanceof X509Certificate) {
//            X509Certificate xcert = (X509Certificate)cert;
//            ret = xcert.getSignature();
//        } else if (StringUtils.equals(cert.getType(), "CVC")) {
//            CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//
//            try {
//                ret = cvccert.getCVCertificate().getSignature();
//            } catch (NoSuchFieldException var4) {
//                log.error("NoSuchFieldException: ", var4);
//                return null;
//            }
//        }
//
//        return ret;
//    }
//
//    public static String getIssuerDN(X509CRL crl) {
//        String dn = null;
//
//        try {
//            CertificateFactory cf = getCertificateFactory();
//            X509CRL x509crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crl.getEncoded()));
//            dn = x509crl.getIssuerDN().toString();
//        } catch (CRLException var4) {
//            log.error("CRLException: ", var4);
//            return null;
//        }
//
//        return stringToBCDNString(dn);
//    }
//
//    public static Date getNotBefore(Certificate cert) {
//        Date ret = null;
//        if (cert == null) {
//            throw new IllegalArgumentException("getNotBefore: cert is null");
//        } else {
//            if (cert instanceof X509Certificate) {
//                X509Certificate xcert = (X509Certificate)cert;
//                ret = xcert.getNotBefore();
//            } else if (StringUtils.equals(cert.getType(), "CVC")) {
//                CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//
//                try {
//                    ret = cvccert.getCVCertificate().getCertificateBody().getValidFrom();
//                } catch (NoSuchFieldException var4) {
//                    log.debug("NoSuchFieldException: " + var4.getMessage());
//                    return null;
//                }
//            }
//
//            return ret;
//        }
//    }
//
//    public static Date getNotAfter(Certificate cert) {
//        Date ret = null;
//        if (cert == null) {
//            throw new IllegalArgumentException("getNotAfter: cert is null");
//        } else {
//            if (cert instanceof X509Certificate) {
//                X509Certificate xcert = (X509Certificate)cert;
//                ret = xcert.getNotAfter();
//            } else if (StringUtils.equals(cert.getType(), "CVC")) {
//                CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//
//                try {
//                    ret = cvccert.getCVCertificate().getCertificateBody().getValidTo();
//                } catch (NoSuchFieldException var4) {
//                    if (log.isDebugEnabled()) {
//                        log.debug("NoSuchFieldException: " + var4.getMessage());
//                    }
//
//                    return null;
//                }
//            }
//
//            return ret;
//        }
//    }
//
//    public static CertificateFactory getCertificateFactory(String provider) {
//        String prov;
//        if (provider == null) {
//            prov = "BC";
//        } else {
//            prov = provider;
//        }
//
//        if ("BC".equals(prov)) {
//            CryptoProviderTools.installBCProviderIfNotAvailable();
//        }
//
//        try {
//            return CertificateFactory.getInstance("X.509", prov);
//        } catch (NoSuchProviderException var3) {
//            log.error("NoSuchProvider: ", var3);
//        } catch (CertificateException var4) {
//            log.error("CertificateException: ", var4);
//        }
//
//        return null;
//    }
//
//    public static CertificateFactory getCertificateFactory() {
//        return getCertificateFactory("BC");
//    }
//
//    /** @deprecated */
//    @Deprecated
//    public static List<Certificate> getCertsFromPEM(String certFilename) throws FileNotFoundException, CertificateParsingException {
//        return getCertsFromPEM(certFilename, Certificate.class);
//    }
//
//    public static <T extends Certificate> List<T> getCertsFromPEM(String certFilename, Class<T> returnType) throws FileNotFoundException, CertificateParsingException {
//        if (log.isTraceEnabled()) {
//            log.trace(">getCertfromPEM: certFilename=" + certFilename);
//        }
//
//        FileInputStream inStrm = null;
//
//        List certs;
//        try {
//            inStrm = new FileInputStream(certFilename);
//            certs = getCertsFromPEM((InputStream)inStrm, returnType);
//        } finally {
//            if (inStrm != null) {
//                try {
//                    inStrm.close();
//                } catch (IOException var10) {
//                    throw new IllegalStateException("Could not clode input stream", var10);
//                }
//            }
//
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("<getCertfromPEM: certFile=" + certFilename);
//        }
//
//        return certs;
//    }
//
//    public static final byte[] readCertificateChainAsArrayOrThrow(String file) throws FileNotFoundException, IOException, CertificateParsingException, CertificateEncodingException {
//        ArrayList cachain = new ArrayList();
//
//        Throwable var36;
//        try {
//            FileInputStream fis = new FileInputStream(file);
//            var36 = null;
//
//            try {
//                Collection<Certificate> certs = getCertsFromPEM((InputStream)fis, Certificate.class);
//                Iterator iter = certs.iterator();
//
//                while(iter.hasNext()) {
//                    Certificate cert = (Certificate)iter.next();
//                    cachain.add(cert.getEncoded());
//                }
//            } catch (Throwable var32) {
//                var36 = var32;
//                throw var32;
//            } finally {
//                if (fis != null) {
//                    if (var36 != null) {
//                        try {
//                            fis.close();
//                        } catch (Throwable var29) {
//                            var36.addSuppressed(var29);
//                        }
//                    } else {
//                        fis.close();
//                    }
//                }
//
//            }
//        } catch (CertificateParsingException var34) {
//            byte[] certbytes = FileTools.readFiletoBuffer(file);
//            Certificate cert = getCertfromByteArray(certbytes, Certificate.class);
//            cachain.add(cert.getEncoded());
//        }
//
//        ByteArrayOutputStream bos = new ByteArrayOutputStream();
//        var36 = null;
//
//        try {
//            Iterator var38 = cachain.iterator();
//
//            byte[] bytes;
//            while(var38.hasNext()) {
//                bytes = (byte[])var38.next();
//                bos.write(bytes);
//            }
//
//            byte[] result = bos.toByteArray();
//            bytes = result;
//            return bytes;
//        } catch (Throwable var30) {
//            var36 = var30;
//            throw var30;
//        } finally {
//            if (bos != null) {
//                if (var36 != null) {
//                    try {
//                        bos.close();
//                    } catch (Throwable var28) {
//                        var36.addSuppressed(var28);
//                    }
//                } else {
//                    bos.close();
//                }
//            }
//
//        }
//    }
//
//    public static final List<CertificateWrapper> bytesToListOfCertificateWrapperOrThrow(byte[] bytes) throws CertificateParsingException {
//        Object certs = null;
//
//        try {
//            certs = getCertsFromPEM((InputStream)(new ByteArrayInputStream(bytes)), Certificate.class);
//        } catch (CertificateException var4) {
//            log.debug("Input stream is not PEM certificate(s): " + var4.getMessage());
//            Certificate cert = getCertfromByteArray(bytes, Certificate.class);
//            certs = new ArrayList();
//            ((Collection)certs).add(cert);
//        }
//
//        return EJBTools.wrapCertCollection((Collection)certs);
//    }
//
//    /** @deprecated */
//    @Deprecated
//    public static List<Certificate> getCertsFromPEM(InputStream certstream) throws CertificateParsingException {
//        return getCertsFromPEM(certstream, Certificate.class);
//    }
//
//    public static <T extends Certificate> List<T> getCertsFromPEM(InputStream certstream, Class<T> returnType) throws CertificateParsingException {
//        if (log.isTraceEnabled()) {
//            log.trace(">getCertfromPEM");
//        }
//
//        ArrayList<T> ret = new ArrayList();
//        String beginKeyTrust = "-----BEGIN TRUSTED CERTIFICATE-----";
//        String endKeyTrust = "-----END TRUSTED CERTIFICATE-----";
//        BufferedReader bufRdr = null;
//        ByteArrayOutputStream ostr = null;
//        PrintStream opstr = null;
//
//        try {
//            try {
//                bufRdr = new BufferedReader(new InputStreamReader(new SecurityFilterInputStream(certstream)));
//
//                while(bufRdr.ready()) {
//                    ostr = new ByteArrayOutputStream();
//                    opstr = new PrintStream(ostr);
//
//                    String temp;
//                    while((temp = bufRdr.readLine()) != null && !temp.equals("-----BEGIN CERTIFICATE-----") && !temp.equals(beginKeyTrust)) {
//                    }
//
//                    if (temp == null) {
//                        if (ret.isEmpty()) {
//                            throw new CertificateParsingException("Error in " + certstream.toString() + ", missing " + "-----BEGIN CERTIFICATE-----" + " boundary");
//                        }
//                        break;
//                    }
//
//                    while((temp = bufRdr.readLine()) != null && !temp.equals("-----END CERTIFICATE-----") && !temp.equals(endKeyTrust)) {
//                        opstr.print(temp);
//                    }
//
//                    if (temp == null) {
//                        throw new IllegalArgumentException("Error in " + certstream.toString() + ", missing " + "-----END CERTIFICATE-----" + " boundary");
//                    }
//
//                    opstr.close();
//                    byte[] certbuf = Base64.decode(ostr.toByteArray());
//                    ostr.close();
//                    T cert = getCertfromByteArray(certbuf, returnType);
//                    ret.add(cert);
//                }
//            } finally {
//                if (bufRdr != null) {
//                    bufRdr.close();
//                }
//
//                if (opstr != null) {
//                    opstr.close();
//                }
//
//                if (ostr != null) {
//                    ostr.close();
//                }
//
//            }
//        } catch (IOException var15) {
//            throw new IllegalStateException("Exception caught when attempting to read stream, see underlying IOException", var15);
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("<getcertfromPEM:" + ret.size());
//        }
//
//        return ret;
//    }
//
//    public static Collection<Certificate> getCertCollectionFromArray(Certificate[] certs, String provider) throws CertificateException, NoSuchProviderException {
//        if (log.isTraceEnabled()) {
//            log.trace(">getCertCollectionFromArray: " + provider);
//        }
//
//        ArrayList<Certificate> ret = new ArrayList();
//        String prov = provider;
//        if (provider == null) {
//            prov = "BC";
//        }
//
//        for(int i = 0; i < certs.length; ++i) {
//            Certificate cert = certs[i];
//            Certificate newcert = getCertfromByteArray(cert.getEncoded(), prov);
//            ret.add(newcert);
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("<getCertCollectionFromArray: " + ret.size());
//        }
//
//        return ret;
//    }
//
//    /** @deprecated */
//    @Deprecated
//    public static byte[] getPEMFromCerts(Collection<Certificate> certs) throws CertificateException {
//        return getPemFromCertificateChain(certs);
//    }
//
//    public static byte[] getPemFromCertificateChain(Collection<Certificate> certs) throws CertificateEncodingException {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        PrintStream printStream = new PrintStream(baos);
//        Throwable var3 = null;
//
//        try {
//            Iterator var4 = certs.iterator();
//
//            while(var4.hasNext()) {
//                Certificate certificate = (Certificate)var4.next();
//                if (certificate != null) {
//                    printStream.println("Subject: " + getSubjectDN(certificate));
//                    printStream.println("Issuer: " + getIssuerDN(certificate));
//                    writeAsPemEncoded(printStream, certificate.getEncoded(), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
//                }
//            }
//        } catch (Throwable var13) {
//            var3 = var13;
//            throw var13;
//        } finally {
//            if (printStream != null) {
//                if (var3 != null) {
//                    try {
//                        printStream.close();
//                    } catch (Throwable var12) {
//                        var3.addSuppressed(var12);
//                    }
//                } else {
//                    printStream.close();
//                }
//            }
//
//        }
//
//        return baos.toByteArray();
//    }
//
//    public static byte[] getPEMFromCrl(byte[] crlBytes) {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        PrintStream printStream = new PrintStream(baos);
//        Throwable var3 = null;
//
//        try {
//            writeAsPemEncoded(printStream, crlBytes, "-----BEGIN X509 CRL-----", "-----END X509 CRL-----");
//        } catch (Throwable var12) {
//            var3 = var12;
//            throw var12;
//        } finally {
//            if (printStream != null) {
//                if (var3 != null) {
//                    try {
//                        printStream.close();
//                    } catch (Throwable var11) {
//                        var3.addSuppressed(var11);
//                    }
//                } else {
//                    printStream.close();
//                }
//            }
//
//        }
//
//        return baos.toByteArray();
//    }
//
//    public static byte[] getPEMFromPublicKey(byte[] publicKeyBytes) {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        PrintStream printStream = new PrintStream(baos);
//        Throwable var3 = null;
//
//        try {
//            writeAsPemEncoded(printStream, publicKeyBytes, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
//        } catch (Throwable var12) {
//            var3 = var12;
//            throw var12;
//        } finally {
//            if (printStream != null) {
//                if (var3 != null) {
//                    try {
//                        printStream.close();
//                    } catch (Throwable var11) {
//                        var3.addSuppressed(var11);
//                    }
//                } else {
//                    printStream.close();
//                }
//            }
//
//        }
//
//        return baos.toByteArray();
//    }
//
//    public static byte[] getPEMFromPrivateKey(byte[] privateKeyBytes) {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        PrintStream printStream = new PrintStream(baos);
//        Throwable var3 = null;
//
//        try {
//            writeAsPemEncoded(printStream, privateKeyBytes, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
//        } catch (Throwable var12) {
//            var3 = var12;
//            throw var12;
//        } finally {
//            if (printStream != null) {
//                if (var3 != null) {
//                    try {
//                        printStream.close();
//                    } catch (Throwable var11) {
//                        var3.addSuppressed(var11);
//                    }
//                } else {
//                    printStream.close();
//                }
//            }
//
//        }
//
//        return baos.toByteArray();
//    }
//
//    public static byte[] getPEMFromCertificateRequest(byte[] certificateRequestBytes) {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        PrintStream printStream = new PrintStream(baos);
//        Throwable var3 = null;
//
//        try {
//            writeAsPemEncoded(printStream, certificateRequestBytes, "-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----");
//        } catch (Throwable var12) {
//            var3 = var12;
//            throw var12;
//        } finally {
//            if (printStream != null) {
//                if (var3 != null) {
//                    try {
//                        printStream.close();
//                    } catch (Throwable var11) {
//                        var3.addSuppressed(var11);
//                    }
//                } else {
//                    printStream.close();
//                }
//            }
//
//        }
//
//        return baos.toByteArray();
//    }
//
//    public static byte[] getPemFromPkcs7(byte[] pkcs7Binary) {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        PrintStream printStream = new PrintStream(baos);
//        Throwable var3 = null;
//
//        try {
//            writeAsPemEncoded(printStream, pkcs7Binary, "-----BEGIN PKCS7-----", "-----END PKCS7-----");
//        } catch (Throwable var12) {
//            var3 = var12;
//            throw var12;
//        } finally {
//            if (printStream != null) {
//                if (var3 != null) {
//                    try {
//                        printStream.close();
//                    } catch (Throwable var11) {
//                        var3.addSuppressed(var11);
//                    }
//                } else {
//                    printStream.close();
//                }
//            }
//
//        }
//
//        return baos.toByteArray();
//    }
//
//    private static void writeAsPemEncoded(PrintStream printStream, byte[] unencodedData, String beginKey, String endKey) {
//        printStream.println(beginKey);
//        printStream.println(new String(Base64.encode(unencodedData)));
//        printStream.println(endKey);
//    }
//
//    /** @deprecated */
//    @Deprecated
//    public static Certificate getCertfromByteArray(byte[] cert, String provider) throws CertificateParsingException {
//        LogSystem.info("MASUK NIH MASUK");
//        return getCertfromByteArray(cert, provider, Certificate.class);
//    }
//
//    public static <T extends Certificate> T getCertfromByteArray(byte[] cert, String provider, Class<T> returnType) throws CertificateParsingException {
//        LogSystem.info("MASUK LAGI NIH MASUK");
//        T ret = null;
//        String prov = provider;
//        if (provider == null) {
//            prov = "BC";
//        }
//
//        if (returnType.equals(X509Certificate.class)) {
//            ret = (T) parseX509Certificate(prov, cert);
//        } else if (returnType.equals(CardVerifiableCertificate.class)) {
//            ret = (T) parseCardVerifiableCertificate(prov, cert);
//        } else {
//            try {
//                ret = (T) parseX509Certificate(prov, cert);
//            } catch (CertificateParsingException var8) {
//                try {
//                    ret = (T) parseCardVerifiableCertificate(prov, cert);
//                } catch (CertificateParsingException var7) {
//                    throw new CertificateParsingException("No certificate could be parsed from byte array. See debug logs for details.");
//                }
//            }
//        }
//
//        return (T) ret;
//    }
//
//    private static X509Certificate parseX509Certificate(String provider, byte[] cert) throws CertificateParsingException {
//        CertificateFactory cf = getCertificateFactory(provider);
//
//        X509Certificate result;
//        try {
//            result = (X509Certificate)cf.generateCertificate(new SecurityFilterInputStream(new ByteArrayInputStream(cert)));
//        } catch (CertificateException var5) {
//            throw new CertificateParsingException("Could not parse byte array as X509Certificate." + var5.getCause().getMessage(), var5);
//        }
//
//        if (result != null) {
//            return result;
//        } else {
//            throw new CertificateParsingException("Could not parse byte array as X509Certificate.");
//        }
//    }
//
//    private static CardVerifiableCertificate parseCardVerifiableCertificate(String provider, byte[] cert) throws CertificateParsingException {
//        try {
//            CVCertificate parsedObject = CertificateParser.parseCertificate(cert);
//            return new CardVerifiableCertificate(parsedObject);
//        } catch (ParseException var3) {
//            throw new CertificateParsingException("ParseException trying to read CVCCertificate.", var3);
//        } catch (ConstructionException var4) {
//            throw new CertificateParsingException("ConstructionException trying to read CVCCertificate.", var4);
//        }
//    }
//
//    /** @deprecated
//     * @return */
//    @Deprecated
//    public static CertificateRequest getCertfromByteArray(byte[] cert, Class<CertificateRequest> returnType) throws CertificateParsingException {
//        try {
//            LogSystem.info("MASUKK 5");
//
//        }catch(Exception e)
//        {
//            e.printStackTrace();
//        }
//        return getCertfromByteArray(cert, CertificateRequest.class);
//
//    }
//
//    public static <T extends CertificateRequest> T getCertfromByteArray(byte[] cert, Class<T> returnType) throws CertificateParsingException {
//        LogSystem.info("MASUKK 2");
//        return getCertfromByteArray(cert, "BC", returnType);
//    }
//
//    public static X509CRL getCRLfromByteArray(byte[] crl) throws CRLException {
//        log.trace(">getCRLfromByteArray");
//        if (crl == null) {
//            throw new CRLException("No content in crl byte array");
//        } else {
//            CertificateFactory cf = getCertificateFactory();
//            X509CRL x509crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crl));
//            log.trace("<getCRLfromByteArray");
//            return x509crl;
//        }
//    }
//
//    public static boolean isSelfSigned(Certificate cert) {
//        if (log.isTraceEnabled()) {
//            log.trace(">isSelfSigned: cert: " + getIssuerDN(cert) + "\n" + getSubjectDN(cert));
//        }
//
//        boolean ret = getSubjectDN(cert).equals(getIssuerDN(cert));
//        if (log.isTraceEnabled()) {
//            log.trace("<isSelfSigned:" + ret);
//        }
//
//        return ret;
//    }
//
//    public static boolean isCertificateValid(X509Certificate signerCert) {
//        try {
//            signerCert.checkValidity();
//        } catch (CertificateExpiredException var5) {
//            if (log.isDebugEnabled()) {
//                log.debug(intres.getLocalizedMessage("ocsp.errorcerthasexpired", new Object[]{signerCert.getSerialNumber().toString(16), signerCert.getIssuerDN()}));
//            }
//
//            return false;
//        } catch (CertificateNotYetValidException var6) {
//            if (log.isDebugEnabled()) {
//                log.debug(intres.getLocalizedMessage("ocsp.errornotyetvalid", new Object[]{signerCert.getSerialNumber().toString(16), signerCert.getIssuerDN()}));
//            }
//
//            return false;
//        }
//
//        long warnBeforeExpirationTime = OcspConfiguration.getWarningBeforeExpirationTime();
//        if (warnBeforeExpirationTime < 1L) {
//            return true;
//        } else {
//            Date warnDate = new Date((new Date()).getTime() + warnBeforeExpirationTime);
//
//            try {
//                signerCert.checkValidity(warnDate);
//            } catch (CertificateExpiredException var7) {
//                if (log.isDebugEnabled()) {
//                    log.debug(intres.getLocalizedMessage("ocsp.warncertwillexpire", new Object[]{signerCert.getSerialNumber().toString(16), signerCert.getIssuerDN(), signerCert.getNotAfter()}));
//                }
//            } catch (CertificateNotYetValidException var8) {
//                throw new IllegalStateException("This should never happen.", var8);
//            }
//
//            if (log.isDebugEnabled()) {
//                log.debug("Time for \"certificate will soon expire\" not yet reached. You will be warned after: " + new Date(signerCert.getNotAfter().getTime() - warnBeforeExpirationTime));
//            }
//
//            return true;
//        }
//    }
//
//    public static boolean isCA(Certificate cert) {
//        if (log.isTraceEnabled()) {
//            log.trace(">isCA");
//        }
//
//        boolean ret = false;
//        if (cert instanceof X509Certificate) {
//            X509Certificate x509cert = (X509Certificate)cert;
//            if (x509cert.getBasicConstraints() > -1) {
//                ret = true;
//            }
//        } else if (StringUtils.equals(cert.getType(), "CVC")) {
//            CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//
//            try {
//                CVCAuthorizationTemplate templ = cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate();
//                AuthorizationRole role = templ.getAuthorizationField().getAuthRole();
//                if (role.isCVCA() || role.isDV()) {
//                    ret = true;
//                }
//            } catch (NoSuchFieldException var5) {
//                log.error("NoSuchFieldException: ", var5);
//            }
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("<isCA:" + ret);
//        }
//
//        return ret;
//    }
//
//    public static boolean isOCSPCert(X509Certificate cert) {
//        List keyUsages;
//        try {
//            keyUsages = cert.getExtendedKeyUsage();
//        } catch (CertificateParsingException var3) {
//            return false;
//        }
//
//        return keyUsages != null && keyUsages.contains(KeyPurposeId.id_kp_OCSPSigning.getId());
//    }
//
//    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA) throws OperatorCreationException, CertificateException {
//        return genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, "BC");
//    }
//
//    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, String provider, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
//        byte keyUsage;
//        if (isCA) {
//            keyUsage = 6;
//        } else {
//            keyUsage = 0;
//        }
//
//        return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyUsage, (Date)null, (Date)null, provider, ldapOrder);
//    }
//
//    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, String provider) throws OperatorCreationException, CertificateException {
//        return genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, provider, true);
//    }
//
//    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
//        return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, (Date)null, (Date)null, "BC", ldapOrder);
//    }
//
//    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider) throws CertificateParsingException, OperatorCreationException {
//        return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, true);
//    }
//
//    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
//        try {
//            return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, ldapOrder, (List)null);
//        } catch (CertIOException var14) {
//            throw new IllegalStateException("CertIOException was thrown due to an invalid extension, but no extensions were provided.", var14);
//        }
//    }
//
//    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder, List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
//        Date firstDate = new Date();
//        firstDate.setTime(firstDate.getTime() - 600000L);
//        Date lastDate = new Date();
//        lastDate.setTime(lastDate.getTime() + validity * 86400000L);
//        return genSelfCertForPurpose(dn, firstDate, lastDate, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, ldapOrder, additionalExtensions);
//    }
//
//    public static X509Certificate genSelfCertForPurpose(String dn, Date firstDate, Date lastDate, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder, List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
//        PublicKey publicKey = null;
//        if (pubKey instanceof RSAPublicKey) {
//            RSAPublicKey rsapk = (RSAPublicKey)pubKey;
//            RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(rsapk.getModulus(), rsapk.getPublicExponent());
//
//            try {
//                publicKey = KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
//            } catch (InvalidKeySpecException var32) {
//                log.error("Error creating RSAPublicKey from spec: ", var32);
//                publicKey = pubKey;
//            } catch (NoSuchAlgorithmException var33) {
//                throw new IllegalStateException("RSA was not a known algorithm", var33);
//            }
//        } else if (pubKey instanceof ECPublicKey) {
//            ECPublicKey ecpk = (ECPublicKey)pubKey;
//
//            try {
//                ECPublicKeySpec ecspec = new ECPublicKeySpec(ecpk.getW(), ecpk.getParams());
//                String algo = ecpk.getAlgorithm();
//                if (algo.equals("ECGOST3410")) {
//                    try {
//                        publicKey = KeyFactory.getInstance("ECGOST3410").generatePublic(ecspec);
//                    } catch (NoSuchAlgorithmException var29) {
//                        throw new IllegalStateException("ECGOST3410 was not a known algorithm", var29);
//                    }
//                } else if (algo.equals("DSTU4145")) {
//                    try {
//                        publicKey = KeyFactory.getInstance("DSTU4145").generatePublic(ecspec);
//                    } catch (NoSuchAlgorithmException var28) {
//                        throw new IllegalStateException("DSTU4145 was not a known algorithm", var28);
//                    }
//                } else {
//                    try {
//                        publicKey = KeyFactory.getInstance("EC").generatePublic(ecspec);
//                    } catch (NoSuchAlgorithmException var27) {
//                        throw new IllegalStateException("EC was not a known algorithm", var27);
//                    }
//                }
//            } catch (InvalidKeySpecException var30) {
//                log.error("Error creating ECPublicKey from spec: ", var30);
//                publicKey = pubKey;
//            } catch (NullPointerException var31) {
//                log.debug("NullPointerException, probably it is implicitlyCA generated keys: " + var31.getMessage());
//                publicKey = pubKey;
//            }
//        } else {
//            log.debug("Not converting key of class. " + pubKey.getClass().getName());
//            publicKey = pubKey;
//        }
//
//        byte[] serno = new byte[8];
//
//        SecureRandom random;
//        try {
//            random = SecureRandom.getInstance("SHA1PRNG");
//        } catch (NoSuchAlgorithmException var26) {
//            throw new IllegalStateException("SHA1PRNG was not a known algorithm", var26);
//        }
//
//        random.setSeed((new Date()).getTime());
//        random.nextBytes(serno);
//        SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
//        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(stringToBcX500Name(dn, ldapOrder), (new BigInteger(serno)).abs(), firstDate, lastDate, stringToBcX500Name(dn, ldapOrder), pkinfo);
//        BasicConstraints bc = new BasicConstraints(isCA);
//        certbuilder.addExtension(Extension.basicConstraints, true, bc);
//        if (isCA || keyusage != 0) {
//            X509KeyUsage ku = new X509KeyUsage(keyusage);
//            certbuilder.addExtension(Extension.keyUsage, true, ku);
//        }
//
//        if (privateKeyNotBefore != null || privateKeyNotAfter != null) {
//            ASN1EncodableVector v = new ASN1EncodableVector();
//            if (privateKeyNotBefore != null) {
//                v.add(new DERTaggedObject(false, 0, new DERGeneralizedTime(privateKeyNotBefore)));
//            }
//
//            if (privateKeyNotAfter != null) {
//                v.add(new DERTaggedObject(false, 1, new DERGeneralizedTime(privateKeyNotAfter)));
//            }
//
//            certbuilder.addExtension(Extension.privateKeyUsagePeriod, false, new DERSequence(v));
//        }
//
//        try {
//            if (isCA) {
//                JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
//                SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(publicKey);
//                AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(publicKey);
//                certbuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
//                certbuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
//            }
//        } catch (IOException var25) {
//        }
//
//        if (policyId != null) {
//            PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(policyId));
//            DERSequence seq = new DERSequence(pi);
//            certbuilder.addExtension(Extension.certificatePolicies, false, seq);
//        }
//
//        if (additionalExtensions != null) {
//            Iterator var43 = additionalExtensions.iterator();
//
//            while(var43.hasNext()) {
//                Extension extension = (Extension)var43.next();
//                certbuilder.addExtension(extension.getExtnId(), extension.isCritical(), extension.getParsedValue());
//            }
//        }
//
//        ContentSigner signer = new BufferingContentSigner((new JcaContentSignerBuilder(sigAlg)).setProvider(provider).build(privKey), 20480);
//        X509CertificateHolder certHolder = certbuilder.build(signer);
//
//        try {
//            X509Certificate selfcert = (X509Certificate)getCertfromByteArray(certHolder.getEncoded(), CertificateRequest.class);
//            return selfcert;
//        } catch (IOException var24) {
//            throw new IllegalStateException("Unexpected IOException was caught.", var24);
//        }
//    }
//
//    public static byte[] getAuthorityKeyId(Certificate certificate) {
//        if (certificate != null && certificate instanceof X509Certificate) {
//            ASN1Primitive asn1Sequence = getExtensionValue((X509Certificate)certificate, Extension.authorityKeyIdentifier.getId());
//            if (asn1Sequence != null) {
//                return AuthorityKeyIdentifier.getInstance(asn1Sequence).getKeyIdentifier();
//            }
//        }
//
//        return null;
//    }
//
//    public static byte[] getSubjectKeyId(Certificate certificate) {
//        if (certificate != null && certificate instanceof X509Certificate) {
//            ASN1Primitive asn1Sequence = getExtensionValue((X509Certificate)certificate, Extension.subjectKeyIdentifier.getId());
//            if (asn1Sequence != null) {
//                return SubjectKeyIdentifier.getInstance(asn1Sequence).getKeyIdentifier();
//            }
//        }
//
//        return null;
//    }
//
//    public static String getCertificatePolicyId(Certificate certificate, int pos) throws IOException {
//        if (certificate != null && certificate instanceof X509Certificate) {
//            ASN1Sequence asn1Sequence = (ASN1Sequence)getExtensionValue((X509Certificate)certificate, Extension.certificatePolicies.getId());
//            if (asn1Sequence != null && asn1Sequence.size() >= pos + 1) {
//                return PolicyInformation.getInstance(asn1Sequence.getObjectAt(pos)).getPolicyIdentifier().getId();
//            }
//        }
//
//        return null;
//    }
//
//    public static List<ASN1ObjectIdentifier> getCertificatePolicyIds(Certificate certificate) throws IOException {
//        List<ASN1ObjectIdentifier> ret = new ArrayList();
//        if (certificate != null && certificate instanceof X509Certificate) {
//            ASN1Sequence asn1Sequence = (ASN1Sequence)getExtensionValue((X509Certificate)certificate, Extension.certificatePolicies.getId());
//            if (asn1Sequence != null) {
//                Iterator var3 = asn1Sequence.iterator();
//
//                while(var3.hasNext()) {
//                    ASN1Encodable asn1Encodable = (ASN1Encodable)var3.next();
//                    PolicyInformation pi = PolicyInformation.getInstance(asn1Encodable);
//                    ret.add(pi.getPolicyIdentifier());
//                }
//            }
//        }
//
//        return ret;
//    }
//
//    public static List<PolicyInformation> getCertificatePolicies(Certificate certificate) throws IOException {
//        List<PolicyInformation> ret = new ArrayList();
//        if (certificate != null && certificate instanceof X509Certificate) {
//            ASN1Sequence asn1Sequence = (ASN1Sequence)getExtensionValue((X509Certificate)certificate, Extension.certificatePolicies.getId());
//            if (asn1Sequence != null) {
//                Iterator var3 = asn1Sequence.iterator();
//
//                while(var3.hasNext()) {
//                    ASN1Encodable asn1Encodable = (ASN1Encodable)var3.next();
//                    PolicyInformation pi = PolicyInformation.getInstance(asn1Encodable);
//                    ret.add(pi);
//                }
//            }
//        }
//
//        return ret;
//    }
//
//    public static String getUPNAltName(Certificate cert) throws IOException, CertificateParsingException {
//        return getUTF8AltNameOtherName(cert, "1.3.6.1.4.1.311.20.2.3");
//    }
//
//    public static String getUTF8AltNameOtherName(Certificate cert, String oid) throws IOException, CertificateParsingException {
//        String ret = null;
//        if (cert instanceof X509Certificate) {
//            X509Certificate x509cert = (X509Certificate)cert;
//            Collection<List<?>> altNames = x509cert.getSubjectAlternativeNames();
//            if (altNames != null) {
//                Iterator var5 = altNames.iterator();
//
//                while(var5.hasNext()) {
//                    List<?> next = (List)var5.next();
//                    ret = getUTF8StringFromSequence(getAltnameSequence(next), oid);
//                    if (ret != null) {
//                        break;
//                    }
//                }
//            }
//        }
//
//        return ret;
//    }
//
//    private static String getUTF8StringFromSequence(ASN1Sequence seq, String oid) {
//        if (seq != null) {
//            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
//            if (id.getId().equals(oid)) {
//                ASN1TaggedObject oobj = (ASN1TaggedObject)seq.getObjectAt(1);
//                ASN1Primitive obj = oobj.getObject();
//                if (obj instanceof ASN1TaggedObject) {
//                    obj = ASN1TaggedObject.getInstance(obj).getObject();
//                }
//
//                DERUTF8String str = DERUTF8String.getInstance(obj);
//                return str.getString();
//            }
//        }
//
//        return null;
//    }
//
//    private static String getIA5StringFromSequence(ASN1Sequence seq, String oid) {
//        if (seq != null) {
//            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
//            if (id.getId().equals(oid)) {
//                ASN1TaggedObject oobj = (ASN1TaggedObject)seq.getObjectAt(1);
//                ASN1Primitive obj = oobj.getObject();
//                if (obj instanceof ASN1TaggedObject) {
//                    obj = ASN1TaggedObject.getInstance(obj).getObject();
//                }
//
//                DERIA5String str = DERIA5String.getInstance(obj);
//                return str.getString();
//            }
//        }
//
//        return null;
//    }
//
//    public static String getPermanentIdentifierAltName(Certificate cert) throws IOException, CertificateParsingException {
//        String ret = null;
//        if (cert instanceof X509Certificate) {
//            X509Certificate x509cert = (X509Certificate)cert;
//            Collection<List<?>> altNames = x509cert.getSubjectAlternativeNames();
//            if (altNames != null) {
//                Iterator i = altNames.iterator();
//
//                while(i.hasNext()) {
//                    ASN1Sequence seq = getAltnameSequence((List)i.next());
//                    ret = getPermanentIdentifierStringFromSequence(seq);
//                    if (ret != null) {
//                        break;
//                    }
//                }
//            }
//        }
//
//        return ret;
//    }
//
//    static String getPermanentIdentifierStringFromSequence(ASN1Sequence seq) {
//        if (seq != null) {
//            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
//            if (id.getId().equals("1.3.6.1.5.5.7.8.3")) {
//                String identifierValue = null;
//                String assigner = null;
//                ASN1TaggedObject oobj = (ASN1TaggedObject)seq.getObjectAt(1);
//                ASN1Primitive obj = oobj.getObject();
//                if (obj instanceof ASN1TaggedObject) {
//                    obj = ASN1TaggedObject.getInstance(obj).getObject();
//                }
//
//                ASN1Sequence piSeq = ASN1Sequence.getInstance(obj);
//                Enumeration<?> e = piSeq.getObjects();
//                if (e.hasMoreElements()) {
//                    Object element = e.nextElement();
//                    if (element instanceof DERUTF8String) {
//                        identifierValue = ((DERUTF8String)element).getString();
//                        if (e.hasMoreElements()) {
//                            element = e.nextElement();
//                        }
//                    }
//
//                    if (element instanceof ASN1ObjectIdentifier) {
//                        assigner = ((ASN1ObjectIdentifier)element).getId();
//                    }
//                }
//
//                StringBuilder buff = new StringBuilder();
//                if (identifierValue != null) {
//                    buff.append(escapePermanentIdentifierValue(identifierValue));
//                }
//
//                buff.append("/");
//                if (assigner != null) {
//                    buff.append(assigner);
//                }
//
//                return buff.toString();
//            }
//        }
//
//        return null;
//    }
//
//    private static String escapePermanentIdentifierValue(String realValue) {
//        return realValue.replace("/", "\\/");
//    }
//
//    private static String unescapePermanentIdentifierValue(String escapedValue) {
//        return escapedValue.replace("\\permanentIdentifier", "permanentIdentifier");
//    }
//
//    static String[] getPermanentIdentifierValues(String permanentIdentifierString) {
//        String[] result = new String[2];
//        int sepPos = permanentIdentifierString.lastIndexOf("/");
//        if (sepPos == -1) {
//            if (!permanentIdentifierString.isEmpty()) {
//                result[0] = unescapePermanentIdentifierValue(permanentIdentifierString);
//            }
//        } else if (sepPos == 0) {
//            if (permanentIdentifierString.length() > 1) {
//                result[1] = permanentIdentifierString.substring(1);
//            }
//        } else if (permanentIdentifierString.charAt(sepPos - "/".length()) != '\\') {
//            result[0] = unescapePermanentIdentifierValue(permanentIdentifierString.substring(0, sepPos));
//            if (permanentIdentifierString.length() > sepPos + "/".length()) {
//                result[1] = permanentIdentifierString.substring(sepPos + 1);
//            }
//        }
//
//        return result;
//    }
//
//    private static String getGUIDStringFromSequence(ASN1Sequence seq) {
//        String ret = null;
//        if (seq != null) {
//            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
//            if (id.getId().equals("1.3.6.1.4.1.311.25.1")) {
//                ASN1TaggedObject oobj = (ASN1TaggedObject)seq.getObjectAt(1);
//                ASN1Primitive obj = oobj.getObject();
//                if (obj instanceof ASN1TaggedObject) {
//                    obj = ASN1TaggedObject.getInstance(obj).getObject();
//                }
//
//                ASN1OctetString str = ASN1OctetString.getInstance(obj);
//                ret = new String(Hex.encode(str.getOctets()));
//            }
//        }
//
//        return ret;
//    }
//
//    protected static String getKrb5PrincipalNameFromSequence(ASN1Sequence seq) {
//        String ret = null;
//        if (seq != null) {
//            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
//            if (id.getId().equals("1.3.6.1.5.2.2")) {
//                ASN1TaggedObject oobj = (ASN1TaggedObject)seq.getObjectAt(1);
//                ASN1Primitive obj = oobj.getObject();
//                if (obj instanceof ASN1TaggedObject) {
//                    obj = ASN1TaggedObject.getInstance(obj).getObject();
//                }
//
//                ASN1Sequence krb5Seq = ASN1Sequence.getInstance(obj);
//                ASN1TaggedObject robj = (ASN1TaggedObject)krb5Seq.getObjectAt(0);
//                DERGeneralString realmObj = DERGeneralString.getInstance(robj.getObject());
//                String realm = realmObj.getString();
//                ASN1TaggedObject pobj = (ASN1TaggedObject)krb5Seq.getObjectAt(1);
//                ASN1Sequence nseq = ASN1Sequence.getInstance(pobj.getObject());
//                ASN1TaggedObject nobj = (ASN1TaggedObject)nseq.getObjectAt(1);
//                ASN1Sequence sseq = ASN1Sequence.getInstance(nobj.getObject());
//                Enumeration en = sseq.getObjects();
//
//                while(en.hasMoreElements()) {
//                    ASN1Primitive o = (ASN1Primitive)en.nextElement();
//                    DERGeneralString str = DERGeneralString.getInstance(o);
//                    if (ret != null) {
//                        ret = ret + "/" + str.getString();
//                    } else {
//                        ret = str.getString();
//                    }
//                }
//
//                ret = ret + "@" + realm;
//            }
//        }
//
//        return ret;
//    }
//
//    public static String getGuidAltName(Certificate cert) throws IOException, CertificateParsingException {
//        if (cert instanceof X509Certificate) {
//            X509Certificate x509cert = (X509Certificate)cert;
//            Collection<List<?>> altNames = x509cert.getSubjectAlternativeNames();
//            if (altNames != null) {
//                Iterator i = altNames.iterator();
//
//                while(i.hasNext()) {
//                    ASN1Sequence seq = getAltnameSequence((List)i.next());
//                    if (seq != null) {
//                        String guid = getGUIDStringFromSequence(seq);
//                        if (guid != null) {
//                            return guid;
//                        }
//                    }
//                }
//            }
//        }
//
//        return null;
//    }
//
//    private static ASN1Sequence getAltnameSequence(List<?> listitem) {
//        Integer no = (Integer)listitem.get(0);
//        if (no == 0) {
//            byte[] altName = (byte[])((byte[])listitem.get(1));
//            return getAltnameSequence(altName);
//        } else {
//            return null;
//        }
//    }
//
//    private static ASN1Sequence getAltnameSequence(byte[] value) {
//        ASN1Primitive oct = null;
//
//        try {
//            oct = ASN1Primitive.fromByteArray(value);
//        } catch (IOException var3) {
//            throw new RuntimeException("Could not read ASN1InputStream", var3);
//        }
//
//        if (oct instanceof ASN1TaggedObject) {
//            oct = ((ASN1TaggedObject)oct).getObject();
//        }
//
//        ASN1Sequence seq = ASN1Sequence.getInstance(oct);
//        return seq;
//    }
//
//    public static String getAltNameStringFromExtension(Extension ext) {
//        String altName = null;
//        GeneralNames names = getGeneralNamesFromExtension(ext);
//        if (names != null) {
//            try {
//                GeneralName[] gns = names.getNames();
//                GeneralName[] var4 = gns;
//                int var5 = gns.length;
//
//                for(int var6 = 0; var6 < var5; ++var6) {
//                    GeneralName gn = var4[var6];
//                    int tag = gn.getTagNo();
//                    ASN1Encodable name = gn.getName();
//                    String str = getGeneralNameString(tag, name);
//                    if (str != null) {
//                        if (altName == null) {
//                            altName = escapeFieldValue(str);
//                        } else {
//                            altName = altName + ", " + escapeFieldValue(str);
//                        }
//                    }
//                }
//            } catch (IOException var11) {
//                log.error("IOException parsing altNames: ", var11);
//                return null;
//            }
//        }
//
//        return altName;
//    }
//
//    public static GeneralNames getGeneralNamesFromExtension(Extension ext) {
//        ASN1Encodable gnames = ext.getParsedValue();
//        if (gnames != null) {
//            GeneralNames names = GeneralNames.getInstance(gnames);
//            return names;
//        } else {
//            return null;
//        }
//    }
//
//    protected static String escapeFieldValue(String value) {
//        return value != null ? value.replaceAll("([,\\\\+\"])", "\\\\$1") : null;
//    }
//
//    public static String getSubjectAlternativeName(Certificate certificate) {
//        if (log.isTraceEnabled()) {
//            log.trace(">getSubjectAlternativeName");
//        }
//
//        String result = "";
//        if (certificate instanceof X509Certificate) {
//            X509Certificate x509cert = (X509Certificate)certificate;
//            Collection altNames = null;
//
//            try {
//                altNames = x509cert.getSubjectAlternativeNames();
//            } catch (CertificateParsingException var15) {
//                throw new RuntimeException("Could not parse certificate", var15);
//            }
//
//            if (altNames == null) {
//                return null;
//            }
//
//            Iterator<List<?>> iter = altNames.iterator();
//            String append = new String();
//            List<?> item = null;
//            Integer type = null;
//            Object value = null;
//
//            while(iter.hasNext()) {
//                item = (List)iter.next();
//                type = (Integer)item.get(0);
//                value = item.get(1);
//                if (!StringUtils.isEmpty(result)) {
//                    append = ", ";
//                }
//
//                String rdn;
//                rdn = null;
//                label78:
//                switch(type) {
//                    case 0:
//                        ASN1Sequence sequence = getAltnameSequence(item);
//                        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
//                        String var12 = oid.getId();
//                        byte var13 = -1;
//                        switch(var12.hashCode()) {
//                            case -1559167387:
//                                if (var12.equals("1.3.6.1.4.1.311.25.1")) {
//                                    var13 = 4;
//                                }
//                                break;
//                            case -96981936:
//                                if (var12.equals("1.3.6.1.5.2.2")) {
//                                    var13 = 2;
//                                }
//                                break;
//                            case 579112230:
//                                if (var12.equals("1.3.6.1.4.1.311.20.2.3")) {
//                                    var13 = 0;
//                                }
//                                break;
//                            case 767061159:
//                                if (var12.equals("1.3.6.1.5.5.7.8.3")) {
//                                    var13 = 1;
//                                }
//                                break;
//                            case 767061161:
//                                if (var12.equals("1.3.6.1.5.5.7.8.5")) {
//                                    var13 = 5;
//                                }
//                                break;
//                            case 767061162:
//                                if (var12.equals("1.3.6.1.5.5.7.8.6")) {
//                                    var13 = 3;
//                                }
//                                break;
//                            case 767061163:
//                                if (var12.equals("1.3.6.1.5.5.7.8.7")) {
//                                    var13 = 6;
//                                }
//                        }
//
//                        switch(var13) {
//                            case 0:
//                                rdn = "upn=" + getUTF8StringFromSequence(sequence, "1.3.6.1.4.1.311.20.2.3");
//                                break label78;
//                            case 1:
//                                rdn = "permanentIdentifier=" + getPermanentIdentifierStringFromSequence(sequence);
//                                break label78;
//                            case 2:
//                                rdn = "krb5principal=" + getKrb5PrincipalNameFromSequence(sequence);
//                                break label78;
//                            case 3:
//                                String sim = RFC4683Tools.getSimStringSequence(sequence);
//                                rdn = "subjectIdentificationMethod=" + sim;
//                                break label78;
//                            case 4:
//                                rdn = "guid=" + getGUIDStringFromSequence(sequence);
//                                break label78;
//                            case 5:
//                                rdn = "xmppAddr=" + getUTF8StringFromSequence(sequence, "1.3.6.1.5.5.7.8.5");
//                                break label78;
//                            case 6:
//                                rdn = "srvName=" + getIA5StringFromSequence(sequence, "1.3.6.1.5.5.7.8.7");
//                            default:
//                                break label78;
//                        }
//                    case 1:
//                        rdn = "rfc822name=" + (String)value;
//                        break;
//                    case 2:
//                        rdn = "dNSName=" + (String)value;
//                    case 3:
//                    case 5:
//                    default:
//                        break;
//                    case 4:
//                        rdn = "directoryName=" + (String)value;
//                        break;
//                    case 6:
//                        rdn = "uniformResourceIdentifier=" + (String)value;
//                        break;
//                    case 7:
//                        rdn = "iPAddress=" + (String)value;
//                        break;
//                    case 8:
//                        rdn = "registeredID=" + (String)value;
//                }
//
//                if (rdn != null) {
//                    result = result + append + escapeFieldValue(rdn);
//                }
//            }
//
//            if (log.isTraceEnabled()) {
//                log.trace("<getSubjectAlternativeName: " + result);
//            }
//
//            if (StringUtils.isEmpty(result)) {
//                return null;
//            }
//        }
//
//        return result;
//    }
//
//    public static GeneralNames getGeneralNamesFromAltName(String altName) {
//        if (log.isTraceEnabled()) {
//            log.trace(">getGeneralNamesFromAltName: " + altName);
//        }
//
//        ASN1EncodableVector vec = new ASN1EncodableVector();
//        Iterator var2 = getEmailFromDN(altName).iterator();
//
//        String dns;
//        while(var2.hasNext()) {
//            dns = (String)var2.next();
//            vec.add(new GeneralName(1, dns));
//        }
//
//        var2 = getPartsFromDN(altName, "dNSName").iterator();
//
//        while(var2.hasNext()) {
//            dns = (String)var2.next();
//            vec.add(new GeneralName(2, new DERIA5String(dns)));
//        }
//
//        String directoryName = getDirectoryStringFromAltName(altName);
//        if (directoryName != null) {
//            X500Name x500DirectoryName = new X500Name(CeSecoreNameStyle.INSTANCE, LDAPDN.unescapeRDN(directoryName));
//            GeneralName gn = new GeneralName(4, x500DirectoryName);
//            vec.add(gn);
//        }
//
//        Iterator var18 = getPartsFromDN(altName, "uniformResourceIdentifier").iterator();
//
//        String principalString;
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            vec.add(new GeneralName(6, new DERIA5String(principalString)));
//        }
//
//        var18 = getPartsFromDN(altName, "uri").iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            vec.add(new GeneralName(6, new DERIA5String(principalString)));
//        }
//
//        var18 = getPartsFromDN(altName, "uniformResourceId").iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            vec.add(new GeneralName(6, new DERIA5String(principalString)));
//        }
//
//        var18 = getPartsFromDN(altName, "iPAddress").iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            byte[] ipoctets = StringTools.ipStringToOctets(principalString);
//            if (ipoctets.length > 0) {
//                GeneralName gn = new GeneralName(7, new DEROctetString(ipoctets));
//                vec.add(gn);
//            } else {
//                log.error("Cannot parse/encode ip address, ignoring: " + principalString);
//            }
//        }
//
//        var18 = getPartsFromDN(altName, "registeredID").iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            vec.add(new GeneralName(8, principalString));
//        }
//
//        var18 = getPartsFromDN(altName, "upn").iterator();
//
//        ASN1EncodableVector v;
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            v = new ASN1EncodableVector();
//            v.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"));
//            v.add(new DERTaggedObject(true, 0, new DERUTF8String(principalString)));
//            vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
//        }
//
//        var18 = getPartsFromDN(altName, "xmppAddr").iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            v = new ASN1EncodableVector();
//            v.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.8.5"));
//            v.add(new DERTaggedObject(true, 0, new DERUTF8String(principalString)));
//            vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
//        }
//
//        var18 = getPartsFromDN(altName, "srvName").iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            v = new ASN1EncodableVector();
//            v.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.8.7"));
//            v.add(new DERTaggedObject(true, 0, new DERIA5String(principalString)));
//            vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
//        }
//
//        var18 = getPartsFromDN(altName, "permanentIdentifier").iterator();
//
////        ASN1EncodableVector v;
//        DERTaggedObject gn;
//        String[] tokens;
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            tokens = getPermanentIdentifierValues(principalString);
//            v = new ASN1EncodableVector();
//            v.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.8.3"));
//            v = new ASN1EncodableVector();
//            if (tokens[0] != null) {
//                v.add(new DERUTF8String(tokens[0]));
//            }
//
//            if (tokens[1] != null) {
//                v.add(new ASN1ObjectIdentifier(tokens[1]));
//            }
//
//            v.add(new DERTaggedObject(true, 0, new DERSequence(v)));
//            gn = new DERTaggedObject(false, 0, new DERSequence(v));
//            vec.add(gn);
//        }
//
//        var18 = getPartsFromDN(altName, "guid").iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            v = new ASN1EncodableVector();
//            byte[] guidbytes = Hex.decode(principalString);
//            if (guidbytes != null) {
//                v.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.25.1"));
//                v.add(new DERTaggedObject(true, 0, new DEROctetString(guidbytes)));
//                gn = new DERTaggedObject(false, 0, new DERSequence(v));
//                vec.add(gn);
//            } else {
//                log.error("Cannot decode hexadecimal guid, ignoring: " + principalString);
//            }
//        }
//
//        var18 = getPartsFromDN(altName, "krb5principal").iterator();
//
//        String realm;
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            if (log.isDebugEnabled()) {
//                log.debug("principalString: " + principalString);
//            }
//
//            int index = principalString.lastIndexOf(64);
//            realm = "";
//            if (index > 0) {
//                realm = principalString.substring(index + 1);
//            }
//
//            if (log.isDebugEnabled()) {
//                log.debug("realm: " + realm);
//            }
//
//            ArrayList<String> principalarr = new ArrayList();
//            int jndex = 0;
//
//            for(int bindex = 0; jndex < index; bindex = jndex + 1) {
//                jndex = principalString.indexOf(47, bindex);
//                if (jndex == -1) {
//                    jndex = index;
//                }
//
//                String s = principalString.substring(bindex, jndex);
//                if (log.isDebugEnabled()) {
//                    log.debug("adding principal name: " + s);
//                }
//
//                principalarr.add(s);
//            }
//
//            v = new ASN1EncodableVector();
//            v.add(new ASN1ObjectIdentifier("1.3.6.1.5.2.2"));
//            ASN1EncodableVector krb5p = new ASN1EncodableVector();
//            krb5p.add(new DERTaggedObject(true, 0, new DERGeneralString(realm)));
//            ASN1EncodableVector principals = new ASN1EncodableVector();
//            principals.add(new DERTaggedObject(true, 0, new ASN1Integer(0L)));
//            ASN1EncodableVector names = new ASN1EncodableVector();
//            Iterator var14 = principalarr.iterator();
//
//            while(var14.hasNext()) {
//                String principalName = (String)var14.next();
//                names.add(new DERGeneralString(principalName));
//            }
//
//            principals.add(new DERTaggedObject(true, 1, new DERSequence(names)));
//            krb5p.add(new DERTaggedObject(true, 1, new DERSequence(principals)));
//            v.add(new DERTaggedObject(true, 0, new DERSequence(krb5p)));
//            gn = new DERTaggedObject(false, 0, new DERSequence(v));
//            vec.add(gn);
//        }
//
//        var18 = getPartsFromDN(altName, "subjectIdentificationMethod").iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            if (StringUtils.isNotBlank(principalString)) {
//                tokens = principalString.split("::");
//                if (tokens.length == 3) {
//                    gn = (DERTaggedObject) RFC4683Tools.createSimGeneralName(tokens[0], tokens[1], tokens[2]);
//                    vec.add(gn);
//                    if (log.isDebugEnabled()) {
//                        log.debug("SIM GeneralName added: " + gn.toString());
//                    }
//                }
//            }
//        }
//
//        var18 = getCustomOids(altName).iterator();
//
//        while(var18.hasNext()) {
//            principalString = (String)var18.next();
//            Iterator var27 = getPartsFromDN(altName, principalString).iterator();
//
//            while(var27.hasNext()) {
//                realm = (String)var27.next();
//                v = new ASN1EncodableVector();
//                v.add(new ASN1ObjectIdentifier(principalString));
//                v.add(new DERTaggedObject(true, 0, new DERUTF8String(realm)));
//                gn = new DERTaggedObject(false, 0, new DERSequence(v));
//                vec.add(gn);
//            }
//        }
//
//        if (vec.size() > 0) {
//            return GeneralNames.getInstance(new DERSequence(vec));
//        } else {
//            return null;
//        }
//    }
//
//    public static String getGeneralNameString(int tag, ASN1Encodable value) throws IOException {
//        String ret = null;
//        switch(tag) {
//            case 0:
//                ASN1Sequence sequence = getAltnameSequence(value.toASN1Primitive().getEncoded());
//                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
//                String var9 = oid.getId();
//                byte var6 = -1;
//                switch(var9.hashCode()) {
//                    case -96981936:
//                        if (var9.equals("1.3.6.1.5.2.2")) {
//                            var6 = 2;
//                        }
//                        break;
//                    case 579112230:
//                        if (var9.equals("1.3.6.1.4.1.311.20.2.3")) {
//                            var6 = 0;
//                        }
//                        break;
//                    case 767061159:
//                        if (var9.equals("1.3.6.1.5.5.7.8.3")) {
//                            var6 = 1;
//                        }
//                        break;
//                    case 767061161:
//                        if (var9.equals("1.3.6.1.5.5.7.8.5")) {
//                            var6 = 4;
//                        }
//                        break;
//                    case 767061162:
//                        if (var9.equals("1.3.6.1.5.5.7.8.6")) {
//                            var6 = 3;
//                        }
//                        break;
//                    case 767061163:
//                        if (var9.equals("1.3.6.1.5.5.7.8.7")) {
//                            var6 = 5;
//                        }
//                }
//
//                switch(var6) {
//                    case 0:
//                        ret = "upn=" + getUTF8StringFromSequence(sequence, "1.3.6.1.4.1.311.20.2.3");
//                        return ret;
//                    case 1:
//                        ret = "permanentIdentifier=" + getPermanentIdentifierStringFromSequence(sequence);
//                        return ret;
//                    case 2:
//                        ret = "krb5principal=" + getKrb5PrincipalNameFromSequence(sequence);
//                        return ret;
//                    case 3:
//                        ret = "subjectIdentificationMethod=" + RFC4683Tools.getSimStringSequence(sequence);
//                        return ret;
//                    case 4:
//                        ret = "xmppAddr=" + getUTF8StringFromSequence(sequence, "1.3.6.1.5.5.7.8.5");
//                        return ret;
//                    case 5:
//                        ret = "srvName=" + getIA5StringFromSequence(sequence, "1.3.6.1.5.5.7.8.7");
//                        return ret;
//                    default:
//                        return ret;
//                }
//            case 1:
//                ret = "rfc822name=" + DERIA5String.getInstance(value).getString();
//                break;
//            case 2:
//                ret = "dNSName=" + DERIA5String.getInstance(value).getString();
//            case 3:
//            case 5:
//            default:
//                break;
//            case 4:
//                X500Name name = X500Name.getInstance(value);
//                ret = "directoryName=" + name.toString();
//                break;
//            case 6:
//                ret = "uniformResourceIdentifier=" + DERIA5String.getInstance(value).getString();
//                break;
//            case 7:
//                ASN1OctetString oct = ASN1OctetString.getInstance(value);
//                ret = "iPAddress=" + StringTools.ipOctetsToString(oct.getOctets());
//                break;
//            case 8:
//                oid = ASN1ObjectIdentifier.getInstance(value);
//                ret = "registeredID=" + oid.getId();
//        }
//
//        return ret;
//    }
//
//    public static boolean verify(X509Certificate certificate, Collection<X509Certificate> caCertChain, Date date, PKIXCertPathChecker... pkixCertPathCheckers) throws CertPathValidatorException {
//        try {
//            ArrayList<X509Certificate> certlist = new ArrayList();
//            certlist.add(certificate);
//            CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certlist);
//            X509Certificate[] cac = (X509Certificate[])caCertChain.toArray(new X509Certificate[caCertChain.size()]);
//            TrustAnchor anchor = new TrustAnchor(cac[0], (byte[])null);
//            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
//            PKIXCertPathChecker[] var9 = pkixCertPathCheckers;
//            int var10 = pkixCertPathCheckers.length;
//
//            for(int var11 = 0; var11 < var10; ++var11) {
//                PKIXCertPathChecker pkixCertPathChecker = var9[var11];
//                params.addCertPathChecker(pkixCertPathChecker);
//            }
//
//            params.setRevocationEnabled(false);
//            params.setDate(date);
//            CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
//            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)cpv.validate(cp, params);
//            if (log.isDebugEnabled()) {
//                log.debug("Certificate verify result: " + result.toString());
//            }
//
//            return true;
//        } catch (CertPathValidatorException var13) {
//            throw new CertPathValidatorException("Invalid certificate or certificate not issued by specified CA: " + var13.getMessage());
//        } catch (CertificateException var14) {
//            throw new IllegalArgumentException("Something was wrong with the supplied certificate", var14);
//        } catch (NoSuchProviderException var15) {
//            throw new IllegalStateException("BouncyCastle provider not found.", var15);
//        } catch (NoSuchAlgorithmException var16) {
//            throw new IllegalStateException("Algorithm PKIX was not found.", var16);
//        } catch (InvalidAlgorithmParameterException var17) {
//            throw new IllegalArgumentException("Either ca certificate chain was empty, or the certificate was on an inappropraite type for a PKIX path checker.", var17);
//        }
//    }
//
//    public static boolean verify(X509Certificate certificate, Collection<X509Certificate> caCertChain) throws CertPathValidatorException {
//        return verify(certificate, caCertChain, (Date)null);
//    }
//
//    public static boolean verifyWithTrustedCertificates(X509Certificate certificate, List<Collection<X509Certificate>> trustedCertificates, PKIXCertPathChecker... pkixCertPathCheckers) {
//        if (trustedCertificates == null) {
//            if (log.isDebugEnabled()) {
//                log.debug("Input of trustedCertificates was null. Trusting nothing.");
//            }
//
//            return false;
//        } else if (trustedCertificates.size() == 0) {
//            if (log.isDebugEnabled()) {
//                log.debug("Input of trustedCertificates was empty. Trusting everything.");
//            }
//
//            return true;
//        } else {
//            BigInteger certSN = getSerialNumber(certificate);
//            Iterator var4 = trustedCertificates.iterator();
//
//            while(var4.hasNext()) {
//                Collection<X509Certificate> trustedCertChain = (Collection)var4.next();
//                X509Certificate trustedCert = (X509Certificate)trustedCertChain.iterator().next();
//                BigInteger trustedCertSN = getSerialNumber(trustedCert);
//                if (certSN.equals(trustedCertSN) && trustedCertChain.size() > 1) {
//                    trustedCertChain.remove(trustedCert);
//                }
//
//                try {
//                    verify(certificate, trustedCertChain, (Date)null, pkixCertPathCheckers);
//                    if (log.isDebugEnabled()) {
//                        log.debug("Trusting certificate with SubjectDN '" + getSubjectDN(certificate) + "' and issuerDN '" + getIssuerDN((Certificate)certificate) + "'.");
//                    }
//
//                    return true;
//                } catch (CertPathValidatorException var9) {
//                }
//            }
//
//            return false;
//        }
//    }
//
//    public static void checkValidity(Certificate cert, Date date) throws CertificateExpiredException, CertificateNotYetValidException {
//        if (cert != null) {
//            if (cert instanceof X509Certificate) {
//                X509Certificate xcert = (X509Certificate)cert;
//                xcert.checkValidity(date);
//            } else if (StringUtils.equals(cert.getType(), "CVC")) {
//                CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//
//                try {
//                    Date start = cvccert.getCVCertificate().getCertificateBody().getValidFrom();
//                    Date end = cvccert.getCVCertificate().getCertificateBody().getValidTo();
//                    String msg;
//                    if (start.after(date)) {
//                        msg = "CV Certificate startDate '" + start + "' is after check date '" + date + "'. Subject: " + getSubjectDN(cert);
//                        if (log.isTraceEnabled()) {
//                            log.trace(msg);
//                        }
//
//                        throw new CertificateNotYetValidException(msg);
//                    }
//
//                    if (end.before(date)) {
//                        msg = "CV Certificate endDate '" + end + "' is before check date '" + date + "'. Subject: " + getSubjectDN(cert);
//                        if (log.isTraceEnabled()) {
//                            log.trace(msg);
//                        }
//
//                        throw new CertificateExpiredException(msg);
//                    }
//                } catch (NoSuchFieldException var6) {
//                    log.error("NoSuchFieldException: ", var6);
//                }
//            }
//        }
//
//    }
//
//    public static URL getCrlDistributionPoint(Certificate certificate) {
//        if (certificate instanceof X509Certificate) {
//            X509Certificate x509cert = (X509Certificate)certificate;
//            Collection<URL> cdps = getCrlDistributionPoints(x509cert, true);
//            if (!cdps.isEmpty()) {
//                return (URL)cdps.iterator().next();
//            }
//        }
//
//        return null;
//    }
//
//    public static Collection<URL> getCrlDistributionPoints(X509Certificate x509cert) {
//        return getCrlDistributionPoints(x509cert, false);
//    }
//
//    private static Collection<URL> getCrlDistributionPoints(X509Certificate x509cert, boolean onlyfirst) {
//        ArrayList<URL> cdps = new ArrayList();
//        ASN1Primitive obj = getExtensionValue(x509cert, Extension.cRLDistributionPoints.getId());
//        if (obj == null) {
//            return cdps;
//        } else {
//            ASN1Sequence crlDistributionPoints = (ASN1Sequence)obj;
//
//            for(int i = 0; i < crlDistributionPoints.size(); ++i) {
//                ASN1Sequence distributionPoint = (ASN1Sequence)crlDistributionPoints.getObjectAt(i);
//
//                for(int j = 0; j < distributionPoint.size(); ++j) {
//                    ASN1TaggedObject tagged = (ASN1TaggedObject)distributionPoint.getObjectAt(j);
//                    if (tagged.getTagNo() == 0) {
//                        String url = getStringFromGeneralNames(tagged.getObject());
//                        if (url != null) {
//                            try {
//                                cdps.add(new URL(url));
//                            } catch (MalformedURLException var11) {
//                                if (log.isDebugEnabled()) {
//                                    log.debug("Error parsing '" + url + "' as a URL. " + var11.getLocalizedMessage());
//                                }
//                            }
//                        }
//
//                        if (onlyfirst) {
//                            return cdps;
//                        }
//                    }
//                }
//            }
//
//            return cdps;
//        }
//    }
//
//    public static Collection<String> getAuthorityInformationAccess(CRL crl) {
//        Collection<String> result = new ArrayList();
//        if (crl instanceof X509CRL) {
//            X509CRL x509crl = (X509CRL)crl;
//            ASN1Primitive derObject = getExtensionValue(x509crl, Extension.authorityInfoAccess.getId());
//            if (derObject != null) {
//                AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(derObject);
//                AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
//                if (accessDescriptions != null && accessDescriptions.length > 0) {
//                    AccessDescription[] var6 = accessDescriptions;
//                    int var7 = accessDescriptions.length;
//
//                    for(int var8 = 0; var8 < var7; ++var8) {
//                        AccessDescription accessDescription = var6[var8];
//                        if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
//                            GeneralName generalName = accessDescription.getAccessLocation();
//                            if (generalName.getTagNo() == 6) {
//                                ASN1Primitive obj = generalName.toASN1Primitive();
//                                if (obj instanceof ASN1TaggedObject) {
//                                    obj = ASN1TaggedObject.getInstance(obj).getObject();
//                                }
//
//                                DERIA5String deria5String = DERIA5String.getInstance(obj);
//                                result.add(deria5String.getString());
//                            }
//                        }
//                    }
//                }
//            }
//        }
//
//        return result;
//    }
//
//    public static List<String> getAuthorityInformationAccessCAIssuerUris(Certificate cert) {
//        return getAuthorityInformationAccessCaIssuerUris(cert, false);
//    }
//
//    public static String getAuthorityInformationAccessOcspUrl(Certificate cert) {
//        Collection<String> urls = getAuthorityInformationAccessOcspUrls(cert);
//        return !urls.isEmpty() ? (String)urls.iterator().next() : null;
//    }
//
//    public static List<String> getAuthorityInformationAccessOcspUrls(Certificate cert) {
//        return getAuthorityInformationAccessOcspUrls(cert, false);
//    }
//
//    private static List<String> getAuthorityInformationAccessCaIssuerUris(Certificate cert, boolean onlyfirst) {
//        List<String> urls = new ArrayList();
//        if (cert instanceof X509Certificate) {
//            X509Certificate x509cert = (X509Certificate)cert;
//            ASN1Primitive obj = getExtensionValue(x509cert, Extension.authorityInfoAccess.getId());
//            if (obj != null) {
//                AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(obj).getAccessDescriptions();
//                if (accessDescriptions != null) {
//                    AccessDescription[] var6 = accessDescriptions;
//                    int var7 = accessDescriptions.length;
//
//                    for(int var8 = 0; var8 < var7; ++var8) {
//                        AccessDescription accessDescription = var6[var8];
//                        if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
//                            GeneralName generalName = accessDescription.getAccessLocation();
//                            if (generalName.getTagNo() == 6) {
//                                ASN1Primitive gnobj = generalName.toASN1Primitive();
//                                if (gnobj instanceof ASN1TaggedObject) {
//                                    gnobj = ASN1TaggedObject.getInstance(gnobj).getObject();
//                                }
//
//                                DERIA5String str = DERIA5String.getInstance(gnobj);
//                                if (str != null) {
//                                    urls.add(str.getString());
//                                }
//
//                                if (onlyfirst) {
//                                    return urls;
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//
//        return urls;
//    }
//
//    private static List<String> getAuthorityInformationAccessOcspUrls(Certificate cert, boolean onlyfirst) {
//        List<String> urls = new ArrayList();
//        if (cert instanceof X509Certificate) {
//            X509Certificate x509cert = (X509Certificate)cert;
//            ASN1Primitive obj = getExtensionValue(x509cert, Extension.authorityInfoAccess.getId());
//            if (obj != null) {
//                AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(obj).getAccessDescriptions();
//                if (accessDescriptions != null) {
//                    AccessDescription[] var6 = accessDescriptions;
//                    int var7 = accessDescriptions.length;
//
//                    for(int var8 = 0; var8 < var7; ++var8) {
//                        AccessDescription accessDescription = var6[var8];
//                        if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod)) {
//                            GeneralName generalName = accessDescription.getAccessLocation();
//                            if (generalName.getTagNo() == 6) {
//                                ASN1Primitive gnobj = generalName.toASN1Primitive();
//                                if (gnobj instanceof ASN1TaggedObject) {
//                                    gnobj = ASN1TaggedObject.getInstance(gnobj).getObject();
//                                }
//
//                                DERIA5String str = DERIA5String.getInstance(gnobj);
//                                if (str != null) {
//                                    urls.add(str.getString());
//                                }
//
//                                if (onlyfirst) {
//                                    return urls;
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//
//        return urls;
//    }
//
//    public static PrivateKeyUsagePeriod getPrivateKeyUsagePeriod(X509Certificate cert) {
//        PrivateKeyUsagePeriod res = null;
//        byte[] extvalue = cert.getExtensionValue(Extension.privateKeyUsagePeriod.getId());
//        if (extvalue != null && extvalue.length > 0) {
//            if (log.isTraceEnabled()) {
//                log.trace("Found a PrivateKeyUsagePeriod in the certificate with subject: " + cert.getSubjectDN().toString());
//            }
//
//            res = PrivateKeyUsagePeriod.getInstance(DEROctetString.getInstance(extvalue).getOctets());
//        }
//
//        return res;
//    }
//
//    protected static ASN1Primitive getExtensionValue(X509Certificate cert, String oid) {
//        return cert == null ? null : getDerObjectFromByteArray(cert.getExtensionValue(oid));
//    }
//
//    protected static ASN1Primitive getExtensionValue(X509CRL crl, String oid) {
//        return crl != null && oid != null ? getDerObjectFromByteArray(crl.getExtensionValue(oid)) : null;
//    }
//
//    public static Extension getExtension(PKCS10CertificationRequest pkcs10CertificateRequest, String oid) {
//        if (pkcs10CertificateRequest != null && oid != null) {
//            Extensions extensions = getPKCS10Extensions(pkcs10CertificateRequest);
//            if (extensions != null) {
//                return extensions.getExtension(new ASN1ObjectIdentifier(oid));
//            }
//        }
//
//        return null;
//    }
//
//    private static Extensions getPKCS10Extensions(PKCS10CertificationRequest pkcs10CertificateRequest) {
//        Attribute[] attributes = pkcs10CertificateRequest.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
//        Attribute[] var2 = attributes;
//        int var3 = attributes.length;
//
//        for(int var4 = 0; var4 < var3; ++var4) {
//            Attribute attribute = var2[var4];
//            ASN1Set attributeValues = attribute.getAttrValues();
//            if (attributeValues.size() > 0) {
//                return Extensions.getInstance(attributeValues.getObjectAt(0));
//            }
//        }
//
//        return null;
//    }
//
//    private static ASN1Primitive getDerObjectFromByteArray(byte[] bytes) {
//        if (bytes == null) {
//            return null;
//        } else {
//            try {
//                return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(bytes).getOctets());
//            } catch (IOException var2) {
//                throw new RuntimeException("Caught an unexected IOException", var2);
//            }
//        }
//    }
//
//    private static String getStringFromGeneralNames(ASN1Primitive names) {
//        ASN1Sequence namesSequence = ASN1Sequence.getInstance((ASN1TaggedObject)names, false);
//        if (namesSequence.size() == 0) {
//            return null;
//        } else {
//            DERTaggedObject taggedObject = (DERTaggedObject)namesSequence.getObjectAt(0);
//            return taggedObject.getTagNo() != 6 ? null : new String(ASN1OctetString.getInstance(taggedObject, false).getOctets());
//        }
//    }
//
//    public static String getFingerprintAsString(Certificate cert) {
//        if (cert == null) {
//            return null;
//        } else {
//            try {
//                byte[] res = generateSHA1Fingerprint(cert.getEncoded());
//                return new String(Hex.encode(res));
//            } catch (CertificateEncodingException var2) {
//                log.error("Error encoding certificate.", var2);
//                return null;
//            }
//        }
//    }
//
//    public static String getFingerprintAsString(X509CRL crl) {
//        try {
//            byte[] res = generateSHA1Fingerprint(crl.getEncoded());
//            return new String(Hex.encode(res));
//        } catch (CRLException var2) {
//            log.error("Error encoding CRL.", var2);
//            return null;
//        }
//    }
//
//    public static String getFingerprintAsString(byte[] in) {
//        byte[] res = generateSHA1Fingerprint(in);
//        return new String(Hex.encode(res));
//    }
//
//    public static String getSHA256FingerprintAsString(byte[] in) {
//        byte[] res = generateSHA256Fingerprint(in);
//        return new String(Hex.encode(res));
//    }
//
//    public static byte[] generateSHA1Fingerprint(byte[] ba) {
//        try {
//            MessageDigest md = MessageDigest.getInstance("SHA1");
//            return md.digest(ba);
//        } catch (NoSuchAlgorithmException var2) {
//            log.error("SHA1 algorithm not supported", var2);
//            return null;
//        }
//    }
//
//    public static byte[] generateSHA256Fingerprint(byte[] ba) {
//        try {
//            MessageDigest md = MessageDigest.getInstance("SHA-256");
//            return md.digest(ba);
//        } catch (NoSuchAlgorithmException var2) {
//            log.error("SHA-256 algorithm not supported", var2);
//            return null;
//        }
//    }
//
//    public static byte[] generateMD5Fingerprint(byte[] ba) {
//        try {
//            MessageDigest md = MessageDigest.getInstance("MD5");
//            return md.digest(ba);
//        } catch (NoSuchAlgorithmException var2) {
//            log.error("MD5 algorithm not supported", var2);
//            return null;
//        }
//    }
//
//    public static int sunKeyUsageToBC(boolean[] sku) {
//        if (sku == null) {
//            return -1;
//        } else {
//            int bcku = 0;
//            if (sku[0]) {
//                bcku |= 128;
//            }
//
//            if (sku[1]) {
//                bcku |= 64;
//            }
//
//            if (sku[2]) {
//                bcku |= 32;
//            }
//
//            if (sku[3]) {
//                bcku |= 16;
//            }
//
//            if (sku[4]) {
//                bcku |= 8;
//            }
//
//            if (sku[5]) {
//                bcku |= 4;
//            }
//
//            if (sku[6]) {
//                bcku |= 2;
//            }
//
//            if (sku[7]) {
//                bcku |= 1;
//            }
//
//            if (sku[8]) {
//                bcku |= 32768;
//            }
//
//            return bcku;
//        }
//    }
//
//    public static int bitStringToRevokedCertInfo(DERBitString reasonFlags) {
//        int ret = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
//        if (reasonFlags == null) {
//            return ret;
//        } else {
//            int val = reasonFlags.intValue();
//            if (log.isDebugEnabled()) {
//                log.debug("Int value of bitString revocation reason: " + val);
//            }
//
//            if ((val & '耀') != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE;
//            }
//
//            if ((val & 16) != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED;
//            }
//
//            if ((val & 32) != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE;
//            }
//
//            if ((val & 2) != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
//            }
//
//            if ((val & 4) != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION;
//            }
//
//            if ((val & 64) != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE;
//            }
//
//            if ((val & 1) != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN;
//            }
//
//            if ((val & 8) != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_SUPERSEDED;
//            }
//
//            if ((val & 128) != 0) {
//                ret = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
//            }
//
//            return ret;
//        }
//    }
//
//    public static String insertCNPostfix(String dn, String cnpostfix, X500NameStyle nameStyle) {
//        if (log.isTraceEnabled()) {
//            log.trace(">insertCNPostfix: dn=" + dn + ", cnpostfix=" + cnpostfix);
//        }
//
//        if (dn == null) {
//            return null;
//        } else {
//            RDN[] rdns = IETFUtils.rDNsFromString(dn, nameStyle);
//            X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
//            boolean replaced = false;
//            RDN[] var6 = rdns;
//            int var7 = rdns.length;
//
//            for(int var8 = 0; var8 < var7; ++var8) {
//                RDN rdn = var6[var8];
//                AttributeTypeAndValue[] attributeTypeAndValues = rdn.getTypesAndValues();
//                AttributeTypeAndValue[] var11 = attributeTypeAndValues;
//                int var12 = attributeTypeAndValues.length;
//
//                for(int var13 = 0; var13 < var12; ++var13) {
//                    AttributeTypeAndValue atav = var11[var13];
//                    if (atav.getType() != null) {
//                        String currentSymbol = (String)CeSecoreNameStyle.DefaultSymbols.get(atav.getType());
//                        if (!replaced && "CN".equals(currentSymbol)) {
//                            nameBuilder.addRDN(atav.getType(), IETFUtils.valueToString(atav.getValue()) + cnpostfix);
//                            replaced = true;
//                        } else {
//                            nameBuilder.addRDN(atav);
//                        }
//                    }
//                }
//            }
//
//            String ret = nameBuilder.build().toString();
//            if (log.isTraceEnabled()) {
//                log.trace("<reverseDN: " + ret);
//            }
//
//            return ret;
//        }
//    }
//
//    public static List<String> getX500NameComponents(String dn) {
//        List<String> ret = new ArrayList();
//        X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
//
//        while(tokenizer.hasMoreTokens()) {
//            ret.add(tokenizer.nextToken());
//        }
//
//        return ret;
//    }
//
//    public static String getParentDN(String dn) {
//        X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
//        tokenizer.nextToken();
//        return tokenizer.getRemainingString();
//    }
//
//    private static List<ASN1ObjectIdentifier> getX509FieldOrder(String[] order) {
//        List<ASN1ObjectIdentifier> fieldOrder = new ArrayList();
//        String[] var2 = order;
//        int var3 = order.length;
//
//        for(int var4 = 0; var4 < var3; ++var4) {
//            String dNObject = var2[var4];
//            fieldOrder.add(DnComponents.getOid(dNObject));
//        }
//
//        return fieldOrder;
//    }
//
//    public static List<ASN1ObjectIdentifier> getX509FieldOrder(boolean ldaporder) {
//        return getX509FieldOrder(DnComponents.getDnObjects(ldaporder));
//    }
//
//    private static X500Name getOrderedX500Name(X500Name x500Name, boolean ldaporder, String[] order, boolean applyLdapToCustomOrder, X500NameStyle nameStyle) {
//        List<ASN1ObjectIdentifier> newOrdering = new ArrayList();
//        List<ASN1Encodable> newValues = new ArrayList();
//        ASN1ObjectIdentifier[] allOids = x500Name.getAttributeTypes();
//        boolean isLdapOrder = !isDNReversed(x500Name.toString());
//        boolean useCustomOrder = order != null && order.length > 0;
//        List ordering;
//        if (useCustomOrder) {
//            log.debug("Using custom DN order");
//            ordering = getX509FieldOrder(order);
//        } else {
//            ordering = getX509FieldOrder(isLdapOrder);
//        }
//
//        HashSet<ASN1ObjectIdentifier> hs = new HashSet(allOids.length + ordering.size());
//        Iterator var12 = ordering.iterator();
//
//        while(true) {
//            ASN1ObjectIdentifier oid;
//            do {
//                if (!var12.hasNext()) {
//                    ASN1ObjectIdentifier[] var21 = allOids;
//                    int i = allOids.length;
//
//                    for(int var24 = 0; var24 < i; ++var24) {
//                        oid = var21[var24];
//                        if (!hs.contains(oid)) {
//                            hs.add(oid);
//                            RDN[] valueList = x500Name.getRDNs(oid);
//                            RDN[] var27 = valueList;
//                            int var28 = valueList.length;
//
//                            for(int var19 = 0; var19 < var28; ++var19) {
//                                RDN value = var27[var19];
//                                newOrdering.add(oid);
//                                newValues.add(value.getFirst().getValue());
//                                if (log.isDebugEnabled()) {
//                                    log.debug("added --> " + oid + " val: " + value);
//                                }
//                            }
//                        }
//                    }
//
//                    if ((useCustomOrder && applyLdapToCustomOrder || !useCustomOrder) && ldaporder != isLdapOrder) {
//                        if (log.isDebugEnabled()) {
//                            log.debug("Reversing order of DN, ldaporder=" + ldaporder + ", isLdapOrder=" + isLdapOrder);
//                        }
//
//                        Collections.reverse(newOrdering);
//                        Collections.reverse(newValues);
//                    }
//
//                    X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
//
//                    for(i = 0; i < newOrdering.size(); ++i) {
//                        nameBuilder.addRDN((ASN1ObjectIdentifier)newOrdering.get(i), (ASN1Encodable)newValues.get(i));
//                    }
//
//                    return nameBuilder.build();
//                }
//
//                oid = (ASN1ObjectIdentifier)var12.next();
//            } while(hs.contains(oid));
//
//            hs.add(oid);
//            RDN[] valueList = x500Name.getRDNs(oid);
//            RDN[] var15 = valueList;
//            int var16 = valueList.length;
//
//            for(int var17 = 0; var17 < var16; ++var17) {
//                RDN value = var15[var17];
//                newOrdering.add(oid);
//                newValues.add(value.getFirst().getValue());
//            }
//        }
//    }
//
//    private static String getDirectoryStringFromAltName(String altName) {
//        String directoryName = getPartFromDN(altName, "directoryName");
//        return "".equals(directoryName) ? null : directoryName;
//    }
//
//    public static List<Certificate> createCertChain(Collection<?> certlistin) throws CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
//        return createCertChain(certlistin, new Date());
//    }
//
//    public static List<Certificate> createCertChain(Collection<?> certlistin, Date now) throws CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
//        List<Certificate> returnval = new ArrayList();
//        Collection<Certificate> certlist = orderCertificateChain(certlistin);
//        Certificate rootca = null;
//        Iterator var5 = certlist.iterator();
//
//        while(var5.hasNext()) {
//            Certificate crt = (Certificate)var5.next();
//            if (isSelfSigned(crt)) {
//                rootca = crt;
//            }
//        }
//
//        if (rootca == null) {
//            throw new CertPathValidatorException("No root CA certificate found in certificate list");
//        } else {
//            Certificate rootcert = null;
//            ArrayList<Certificate> calist = new ArrayList();
//            Iterator var7 = certlist.iterator();
//
//            while(var7.hasNext()) {
//                Certificate next = (Certificate)var7.next();
//                if (isSelfSigned(next)) {
//                    rootcert = next;
//                } else {
//                    calist.add(next);
//                }
//            }
//
//            if (calist.isEmpty()) {
//                returnval.add(rootcert);
//            } else {
//                Certificate test = (Certificate)calist.get(0);
//                if (test.getType().equals("CVC")) {
//                    if (calist.size() != 1) {
//                        throw new CertPathValidatorException("CVC certificate chain can not be of length longer than two.");
//                    }
//
//                    returnval.add(test);
//                    returnval.add(rootcert);
//                } else {
//                    HashSet<TrustAnchor> trustancors = new HashSet();
//                    TrustAnchor trustanchor = null;
//                    trustanchor = new TrustAnchor((X509Certificate)rootcert, (byte[])null);
//                    trustancors.add(trustanchor);
//                    PKIXParameters params = new PKIXParameters(trustancors);
//                    params.setRevocationEnabled(false);
//                    params.setDate(now);
//                    CertPathValidator certPathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType(), "BC");
//                    CertificateFactory fact = getCertificateFactory();
//                    CertPath certpath = fact.generateCertPath(calist);
//                    CertPathValidatorResult result = certPathValidator.validate(certpath, params);
//                    PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult)result;
//                    returnval.addAll(certpath.getCertificates());
//                    TrustAnchor ta = pkixResult.getTrustAnchor();
//                    X509Certificate cert = ta.getTrustedCert();
//                    returnval.add(cert);
//                }
//            }
//
//            return returnval;
//        }
//    }
//
//    private static List<Certificate> orderCertificateChain(Collection<?> certlist) throws CertPathValidatorException {
//        ArrayList<Certificate> returnval = new ArrayList();
//        Certificate rootca = null;
//        HashMap<String, Certificate> cacertmap = new HashMap();
//        Iterator var4 = certlist.iterator();
//
//        Certificate nextcert;
//        while(var4.hasNext()) {
//            Object possibleCertificate = var4.next();
//            nextcert = null;
//
//            try {
//                nextcert = (Certificate)possibleCertificate;
//            } catch (ClassCastException var11) {
//                byte[] certBytes = (byte[])((byte[])possibleCertificate);
//
//                try {
//                    nextcert = getCertfromByteArray(certBytes, CertificateRequest.class);
//                } catch (CertificateParsingException var10) {
//                    throw new CertPathValidatorException(var10);
//                }
//            }
//
//            if (isSelfSigned(nextcert)) {
//                rootca = nextcert;
//            } else {
//                log.debug("Adding to cacertmap with index '" + getIssuerDN(nextcert) + "'");
//                cacertmap.put(getIssuerDN(nextcert), nextcert);
//            }
//        }
//
//        if (rootca == null) {
//            throw new CertPathValidatorException("No root CA certificate found in certificatelist");
//        } else {
//            returnval.add(0, rootca);
//            Certificate currentcert = rootca;
//
//            int i;
//            for(i = 0; certlist.size() != returnval.size() && i <= certlist.size(); ++i) {
//                if (log.isDebugEnabled()) {
//                    log.debug("Looking in cacertmap for '" + getSubjectDN(currentcert) + "'");
//                }
//
//                nextcert = (Certificate)cacertmap.get(getSubjectDN(currentcert));
//                if (nextcert == null) {
//                    if (log.isDebugEnabled()) {
//                        log.debug("Dumping keys of CA certificate map:");
//                        Iterator var7 = cacertmap.keySet().iterator();
//
//                        while(var7.hasNext()) {
//                            String issuerDn = (String)var7.next();
//                            log.debug(issuerDn);
//                        }
//                    }
//
//                    throw new CertPathValidatorException("Error building certificate path. Could find certificate with SubjectDN " + getSubjectDN(currentcert) + " in certificate map. See debug log for details.");
//                }
//
//                returnval.add(0, nextcert);
//                currentcert = nextcert;
//            }
//
//            if (i > certlist.size()) {
//                throw new CertPathValidatorException("Error building certificate path");
//            } else {
//                return returnval;
//            }
//        }
//    }
//
//    public static List<X509Certificate> orderX509CertificateChain(List<X509Certificate> certlist) throws CertPathValidatorException {
//        CertPath cp;
//        try {
//            cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certlist);
//        } catch (CertificateException var3) {
//            throw new CertPathValidatorException(var3);
//        } catch (NoSuchProviderException var4) {
//            throw new IllegalStateException("BouncyCastle was not found as a provider.", var4);
//        }
//
//        return (List<X509Certificate>) cp.getCertificates();
//    }
//
//    public static boolean compareCertificateChains(Certificate[] chainA, Certificate[] chainB) {
//        if (chainA != null && chainB != null) {
//            if (chainA.length != chainB.length) {
//                return false;
//            } else {
//                for(int i = 0; i < chainA.length; ++i) {
//                    if (chainA[i] == null || !chainA[i].equals(chainB[i])) {
//                        return false;
//                    }
//                }
//
//                return true;
//            }
//        } else {
//            return false;
//        }
//    }
//
//    public static String dumpCertificateAsString(Certificate cert) {
//        String ret = null;
//        if (cert instanceof X509Certificate) {
//            try {
//                Certificate c = getCertfromByteArray(cert.getEncoded(), CertificateRequest.class);
//                ret = c.toString();
//            } catch (CertificateException var4) {
//                ret = var4.getMessage();
//            }
//        } else {
//            if (!StringUtils.equals(cert.getType(), "CVC")) {
//                throw new IllegalArgumentException("dumpCertificateAsString: Certificate of type " + cert.getType() + " is not implemented");
//            }
//
//            CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cert;
//            CVCObject obj = cvccert.getCVCertificate();
//            ret = obj.getAsText("");
//        }
//
//        return ret;
//    }
//
//    public static PKCS10CertificationRequest getCertificateRequestFromPem(String pemEncodedCsr) {
//        if (pemEncodedCsr == null) {
//            return null;
//        } else {
//            PKCS10CertificationRequest csr = null;
//            ByteArrayInputStream pemStream = new ByteArrayInputStream(pemEncodedCsr.getBytes(StandardCharsets.UTF_8));
//
//            try {
//                PEMParser pemParser = new PEMParser(new BufferedReader(new InputStreamReader(pemStream)));
//                Throwable var4 = null;
//
//                try {
//                    Object parsedObj = pemParser.readObject();
//                    if (parsedObj instanceof PKCS10CertificationRequest) {
//                        csr = (PKCS10CertificationRequest)parsedObj;
//                    }
//                } catch (Throwable var14) {
//                    var4 = var14;
//                    throw var14;
//                } finally {
//                    if (pemParser != null) {
//                        if (var4 != null) {
//                            try {
//                                pemParser.close();
//                            } catch (Throwable var13) {
//                                var4.addSuppressed(var13);
//                            }
//                        } else {
//                            pemParser.close();
//                        }
//                    }
//
//                }
//            } catch (DecoderException | IOException var16) {
//                log.info("IOException while decoding certificate request from PEM: " + var16.getMessage());
//                log.debug("IOException while decoding certificate request from PEM.", var16);
//            }
//
//            return csr;
//        }
//    }
//
//    public static PKCS10CertificationRequest genPKCS10CertificationRequest(String signatureAlgorithm, X500Name subject, PublicKey publickey, ASN1Set attributes, PrivateKey privateKey, String provider) throws OperatorCreationException {
//        BufferingContentSigner signer;
//        CertificationRequestInfo reqInfo;
//        try {
//            SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publickey.getEncoded());
//            reqInfo = new CertificationRequestInfo(subject, pkinfo, attributes);
//            if (provider == null) {
//                provider = "BC";
//            }
//
//            signer = new BufferingContentSigner((new JcaContentSignerBuilder(signatureAlgorithm)).setProvider(provider).build(privateKey), 20480);
//            signer.getOutputStream().write(reqInfo.getEncoded("DER"));
//            signer.getOutputStream().flush();
//        } catch (IOException var11) {
//            throw new IllegalStateException("Unexpected IOException was caught.", var11);
//        }
//
//        byte[] sig = signer.getSignature();
//        DERBitString sigBits = new DERBitString(sig);
//        CertificationRequest req = new CertificationRequest(reqInfo, signer.getAlgorithmIdentifier(), sigBits);
//        return new PKCS10CertificationRequest(req);
//    }
//
//    public static byte[] createCertsOnlyCMS(List<X509Certificate> x509CertificateChain) throws CertificateEncodingException, CMSException {
//        if (log.isDebugEnabled()) {
//            String subjectdn = x509CertificateChain != null && x509CertificateChain.size() > 0 ? ((X509Certificate)x509CertificateChain.get(0)).getSubjectDN().toString() : "null";
//            log.debug("Creating a certs-only CMS for " + subjectdn);
//        }
//
//        List<JcaX509CertificateHolder> certList = convertToX509CertificateHolder(x509CertificateChain);
//        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
//        cmsSignedDataGenerator.addCertificates(new CollectionStore(certList));
//        CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(new CMSAbsentContent(), true);
//
//        try {
//            return cmsSignedData.getEncoded();
//        } catch (IOException var5) {
//            throw new CMSException(var5.getMessage());
//        }
//    }
//
//    public static ContentVerifierProvider genContentVerifierProvider(PublicKey pubkey) throws OperatorCreationException {
//        return (new JcaContentVerifierProviderBuilder()).setProvider("BC").build(pubkey);
//    }
//
//    public static final List<X509Certificate> convertCertificateChainToX509Chain(Collection<Certificate> chain) throws ClassCastException {
//        List<X509Certificate> ret = new ArrayList();
//        Iterator var2 = chain.iterator();
//
//        while(var2.hasNext()) {
//            Certificate certificate = (Certificate)var2.next();
//            ret.add((X509Certificate)certificate);
//        }
//
//        return ret;
//    }
//
//    public static final List<Certificate> convertCertificateChainToGenericChain(Collection<X509Certificate> chain) {
//        List<Certificate> ret = new ArrayList();
//        Iterator var2 = chain.iterator();
//
//        while(var2.hasNext()) {
//            Certificate certificate = (Certificate)var2.next();
//            ret.add(certificate);
//        }
//
//        return ret;
//    }
//
//    public static final JcaX509CertificateHolder[] convertToX509CertificateHolder(X509Certificate[] certificateChain) throws CertificateEncodingException {
//        JcaX509CertificateHolder[] certificateHolderChain = new JcaX509CertificateHolder[certificateChain.length];
//
//        for(int i = 0; i < certificateChain.length; ++i) {
//            certificateHolderChain[i] = new JcaX509CertificateHolder(certificateChain[i]);
//        }
//
//        return certificateHolderChain;
//    }
//
//    public static final List<JcaX509CertificateHolder> convertToX509CertificateHolder(List<X509Certificate> certificateChain) throws CertificateEncodingException {
//        List<JcaX509CertificateHolder> certificateHolderChain = new ArrayList();
//        Iterator var2 = certificateChain.iterator();
//
//        while(var2.hasNext()) {
//            X509Certificate certificate = (X509Certificate)var2.next();
//            certificateHolderChain.add(new JcaX509CertificateHolder(certificate));
//        }
//
//        return certificateHolderChain;
//    }
//
//    public static final List<X509Certificate> convertToX509CertificateList(Collection<X509CertificateHolder> certificateHolderChain) throws CertificateException {
//        List<X509Certificate> ret = new ArrayList();
//        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
//        Iterator var3 = certificateHolderChain.iterator();
//
//        while(var3.hasNext()) {
//            X509CertificateHolder certificateHolder = (X509CertificateHolder)var3.next();
//            ret.add(jcaX509CertificateConverter.getCertificate(certificateHolder));
//        }
//
//        return ret;
//    }
//
//    public static final X509Certificate[] convertToX509CertificateArray(Collection<X509CertificateHolder> certificateHolderChain) throws CertificateException {
//        return (X509Certificate[])convertToX509CertificateList(certificateHolderChain).toArray(new X509Certificate[0]);
//    }
//
//    public static final List<X509CRL> convertToX509CRLList(Collection<X509CRLHolder> crlHolders) throws CRLException {
//        List<X509CRL> ret = new ArrayList();
//        JcaX509CRLConverter jcaX509CRLConverter = new JcaX509CRLConverter();
//        Iterator var3 = crlHolders.iterator();
//
//        while(var3.hasNext()) {
//            X509CRLHolder crlHolder = (X509CRLHolder)var3.next();
//            ret.add(jcaX509CRLConverter.getCRL(crlHolder));
//        }
//
//        return ret;
//    }
//
//    public static void checkNameConstraints(X509Certificate issuer, X500Name subjectDNName, GeneralNames subjectAltName) throws IllegalNameException {
//        byte[] ncbytes = issuer.getExtensionValue(Extension.nameConstraints.getId());
//        ASN1OctetString ncstr = ncbytes != null ? DEROctetString.getInstance(ncbytes) : null;
//        ASN1Sequence ncseq = ncbytes != null ? DERSequence.getInstance(ncstr.getOctets()) : null;
//        NameConstraints nc = ncseq != null ? NameConstraints.getInstance(ncseq) : null;
//        if (nc != null) {
//            if (subjectDNName != null) {
//                X500Name issuerDNName = X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
//                if (issuerDNName.equals(subjectDNName)) {
//                    return;
//                }
//            }
//
//            PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
//            GeneralSubtree[] permitted = nc.getPermittedSubtrees();
//            GeneralSubtree[] excluded = nc.getExcludedSubtrees();
//            if (permitted != null) {
//                validator.intersectPermittedSubtree(permitted);
//            }
//
//            int var11;
//            int var12;
//            if (excluded != null) {
//                GeneralSubtree[] var10 = excluded;
//                var11 = excluded.length;
//
//                for(var12 = 0; var12 < var11; ++var12) {
//                    GeneralSubtree subtree = var10[var12];
//                    validator.addExcludedSubtree(subtree);
//                }
//            }
//
//            if (subjectDNName != null) {
//                GeneralName dngn = new GeneralName(subjectDNName);
//
//                try {
//                    validator.checkPermitted(dngn);
//                    validator.checkExcluded(dngn);
//                } catch (PKIXNameConstraintValidatorException var17) {
//                    String dnStr = subjectDNName.toString();
//                    boolean isLdapOrder = dnHasMultipleComponents(dnStr) && !isDNReversed(dnStr);
//                    String msg;
//                    if (isLdapOrder) {
//                        msg = intres.getLocalizedMessage("nameconstraints.x500dnorderrequired", new Object[0]);
//                        throw new IllegalNameException(msg);
//                    }
//
//                    msg = intres.getLocalizedMessage("nameconstraints.forbiddensubjectdn", new Object[]{subjectDNName});
//                    throw new IllegalNameException(msg, var17);
//                }
//            }
//
//            if (subjectAltName != null) {
//                GeneralName[] var20 = subjectAltName.getNames();
//                var11 = var20.length;
//
//                for(var12 = 0; var12 < var11; ++var12) {
//                    GeneralName sangn = var20[var12];
//
//                    try {
//                        validator.checkPermitted(sangn);
//                        validator.checkExcluded(sangn);
//                    } catch (PKIXNameConstraintValidatorException var16) {
//                        String msg = intres.getLocalizedMessage("nameconstraints.forbiddensubjectaltname", new Object[]{sangn});
//                        throw new IllegalNameException(msg, var16);
//                    }
//                }
//            }
//        }
//
//    }
//
//    public static final String createPublicKeyFingerprint(PublicKey publicKey, String algorithm) {
//        try {
//            MessageDigest digest = MessageDigest.getInstance(algorithm);
//            digest.reset();
//            digest.update(publicKey.getEncoded());
//            String result = Hex.toHexString(digest.digest());
//            if (log.isDebugEnabled()) {
//                log.debug("Fingerprint " + result + " created for public key: " + new String(Base64.encode(publicKey.getEncoded())));
//            }
//
//            return result;
//        } catch (NoSuchAlgorithmException var4) {
//            log.warn("Could not create fingerprint for public key ", var4);
//            return null;
//        }
//    }
//
//    static {
//        DnComponents.getDnObjects(true);
//        EMAILIDS = new String[]{"rfc822name", "email", "EmailAddress", "E"};
//    }
//
//    private static class BasicX509NameTokenizer {
//        private final String oid;
//        private int index = -1;
//        private StringBuilder buf = new StringBuilder();
//
//        public BasicX509NameTokenizer(String oid) {
//            this.oid = oid;
//        }
//
//        public boolean hasMoreTokens() {
//            return this.index != this.oid.length();
//        }
//
//        public String nextToken() {
//            if (this.index == this.oid.length()) {
//                return null;
//            } else {
//                int end = this.index + 1;
//                boolean quoted = false;
//                boolean escaped = false;
//                this.buf.setLength(0);
//
//                for(; end != this.oid.length(); ++end) {
//                    char c = this.oid.charAt(end);
//                    if (c == '"') {
//                        if (!escaped) {
//                            this.buf.append(c);
//                            quoted ^= true;
//                        } else {
//                            this.buf.append(c);
//                        }
//
//                        escaped = false;
//                    } else if (!escaped && !quoted) {
//                        if (c == '\\') {
//                            this.buf.append(c);
//                            escaped = true;
//                        } else {
//                            if (c == ',' && !escaped) {
//                                break;
//                            }
//
//                            this.buf.append(c);
//                        }
//                    } else {
//                        this.buf.append(c);
//                        escaped = false;
//                    }
//                }
//
//                this.index = end;
//                return this.buf.toString().trim();
//            }
//        }
//    }
//
//    private static class X509NameTokenizer {
//        private String value;
//        private int index;
//        private char separator;
//        private StringBuffer buf;
//
//        public X509NameTokenizer(String oid) {
//            this(oid, ',');
//        }
//
//        public X509NameTokenizer(String oid, char separator) {
//            this.buf = new StringBuffer();
//            this.value = oid;
//            this.index = -1;
//            this.separator = separator;
//        }
//
//        public boolean hasMoreTokens() {
//            return this.index != this.value.length();
//        }
//
//        public String nextToken() {
//            if (this.index == this.value.length()) {
//                return null;
//            } else {
//                int end = this.index + 1;
//                boolean quoted = false;
//                boolean escaped = false;
//                this.buf.setLength(0);
//
//                for(; end != this.value.length(); ++end) {
//                    char c = this.value.charAt(end);
//                    if (c == '"') {
//                        if (!escaped) {
//                            quoted = !quoted;
//                        } else {
//                            if (c == '#' && this.buf.charAt(this.buf.length() - 1) == '=') {
//                                this.buf.append('\\');
//                            } else if (c == '+' && this.separator != '+') {
//                                this.buf.append('\\');
//                            }
//
//                            this.buf.append(c);
//                        }
//
//                        escaped = false;
//                    } else if (!escaped && !quoted) {
//                        if (c == '\\') {
//                            escaped = true;
//                        } else {
//                            if (c == this.separator) {
//                                break;
//                            }
//
//                            this.buf.append(c);
//                        }
//                    } else {
//                        if (c == '#' && this.buf.charAt(this.buf.length() - 1) == '=') {
//                            this.buf.append('\\');
//                        } else if (c == '+' && this.separator != '+') {
//                            this.buf.append('\\');
//                        }
//
//                        this.buf.append(c);
//                        escaped = false;
//                    }
//                }
//
//                this.index = end;
//                return this.buf.toString().trim();
//            }
//        }
//
//        String getRemainingString() {
//            return this.index + 1 < this.value.length() ? this.value.substring(this.index + 1) : "";
//        }
//    }
//}
//

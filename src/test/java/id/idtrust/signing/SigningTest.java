package id.idtrust.signing;


import id.idtrust.signing.core.LTV.AddValidationInformation;
import id.idtrust.signing.core.signDoc;
import id.idtrust.signing.model.signer.KeySigner;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.awt.geom.Rectangle2D;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.UUID;

@SpringBootTest
class SigningTest {
    ClassLoader classLoader = getClass().getClassLoader();

    @Test
    public void singleSealTest() throws Exception {
        String[] certSeal = "-----BEGIN CERTIFICATE-----\\nMIIGSDCCBDCgAwIBAgIRAJ8neEe0myca8qhjUOG5nrMwDQYJKoZIhvcNAQELBQAw\\nOzETMBEGA1UEChMKaWR0cnVzdC5pZDELMAkGA1UEBhMCSUQxFzAVBgNVBAMTDlMw\\nMDMgREVWIENBIEMxMB4XDTIzMTExMDA2MjIxOFoXDTI0MTEwOTE2NTk1OVowNDEN\\nMAsGA1UECxMEc2VhbDELMAkGA1UEBhMCSUQxFjAUBgNVBAMTDVBUIEthbmcgQmFr\\nc28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCksiEWBj0WVR9MgO\\/i\\nes88qbIHrsL5cZjJSCsoG6k\\/+3gREidafUam2Sa7HPy+rKazP7LTlq2P4JoF5axf\\nRNJ2tm024PQ6ZNQbIO1ODTFXHmO79qSvHUFbnBx1PpBlq6zy+HBVfeb47OkJe1jI\\nUlEaBpA1Tg185bXO4+9Bw2htahi0jQ\\/jA34Q0pkaxYuK6fLh3UNElQ9cpnwuWK6C\\n6Oom\\/VFXrF4TTKfgoE\\/Jp6Y3\\/Qqf8gzZ+6Jo5HQBGNa4kSBfl9DR0F937gN+nnjY\\n5mDSnJwIo+ThKZXVpdfkpNCVejzsJRk8doRd44BrpF\\/BmGQ2greihuw9o\\/rwj1ig\\nuERLAgMBAAGjggJMMIICSDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB\\/wQEAwIGwDAf\\nBgNVHSMEGDAWgBRtWvb5a4KkNKCzgEiDZZy4j9qJvzAdBgNVHQ4EFgQU1GzstIUw\\ny1CYJ14msXkjPdPWdgYwgZ0GCCsGAQUFBwEBBIGQMIGNMEsGCCsGAQUFBzAChj9o\\ndHRwczovL2RldnJlcG9zaXRvcnkuaWR0cnVzdC5pZC9yZXBvc2l0b3J5L2Nlci9p\\nZHRydXN0aWRjMS5jcnQwPgYIKwYBBQUHMAGGMmh0dHBzOi8vZGV2cmVwb3NpdG9y\\neS5pZHRydXN0LmlkL29jc3ByZXNwb25kZXJjb3JlMFAGA1UdHwRJMEcwRaBDoEGG\\nP2h0dHBzOi8vZGV2cmVwb3NpdG9yeS5pZHRydXN0LmlkL3JlcG9zaXRvcnkvY3Js\\nL2lkdHJ1c3RpZEMxLmNybDCB9QYDVR0gBIHtMIHqMDEGCWCCaAEBAQMMYzAkMCIG\\nCCsGAQUFBwICMBYeFABpAGQAdAByAHUAcwB0AC4AaQBkMF8GC2CCaAEBAQMMYwIB\\nMFAwTgYIKwYBBQUHAgIwQh5AAGgAdAB0AHAAcwA6AC8ALwBkAGUAdgByAGUAcABv\\nAHMAaQB0AG8AcgB5AC4AaQBkAHQAcgB1AHMAdAAuAGkAZDBUBghggmgBAQEIATBI\\nMEYGCCsGAQUFBwICMDoeOABzAGUAZwBlAGwALQBlAGwAZQBrAHQAcgBvAG4AaQBr\\nACAAYgBhAGQAYQBuAC0AdQBzAGEAaABhMA0GCSqGSIb3DQEBCwUAA4ICAQBSEylc\\nhyI2qxdjlRdEQMC49PbvYwzHSn7v1lCi4607E09SmEkgAFYotKHuffUklhHndTaQ\\nhYJwy3qM7+TNdrOyL7CILWbNXEwMPwMytXexrsjAypaPCZj7RhqlYWYRnveuffmB\\ncmYpKnzkNDpPSeGKdJqmPTMLQEmL2YJJPli40X9AoZjyzV6qHVGhWBciwLE7ah29\\ndIrPUmXvvdq8KMFcgyo+Ax7U9s4SxE3l1SIvbF0Utxfeaa1+h+60fFfYY9WGDG3X\\n0m0tA6fW0eu+ZN43b7lUvoL57KAy706PHQ33A6D7NQkeqPcHtnrkuV+jPOry2XRh\\nLCuLvDJPhLc9RpHA6tFZfDyCioSo+deGeHqepreeiQGIfohU0acg4NbsrV7C\\/J2M\\nBGfPvv6L9829XpyCDXg8C4ZZnftOSdLgsCKIQ+O4yb2kmMsTiXDp07t+mYyVH1FD\\nHA66Cx7ZmLhhf8v\\/Zy22c8nP4Kdt22F0SwVbe2LhNh8DXLzT2KQaIloSgToFHr0f\\nECasUXo3R5lsT13y\\/LSIouO1xPDkYS9aQa70cXtTOoQf0S7AVWd3Eq63aHqaEj5Q\\n33S4BNJheoVbdWofaZRZJGmN5ZGTcKD8YzA2ZNHFAnbCzJ6HUZsjaVKRO9cts+iQ\\nCgthYezCgXhYc4rmqVROPBxN0Unogkjeyr4ULA==\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIGlDCCBHygAwIBAgIQR40GDBEETAc3RD1flKDBvjANBgkqhkiG9w0BAQsFADA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwHhcNMjMxMDE3MDQ0NDAzWhcNMzMwODI1MDQ0NDAzWjA7\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEXMBUGA1UEAxMOUzAw\\nMyBERVYgQ0EgQzEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQClUzoe\\nUo3iCw0laovONMAfBImalKmU+1I6o2mcPkEd3mWnTjePL11wpINUXgU8AcVdoO9f\\nVOKB7qhayas8bkWCtPg9LQMdsRV68Z+7+PxhxiqAep\\/qTO1gfz0SWk4zVQiRH9wn\\nCfJ+fUxmboTOT+wuWrrbSBLMPqt9pIbSzt\\/oaFWRYaUxadBzSsyus3qnZUrBd8UJ\\nqpIVxEBiuPIoPZpiWpCb5afIvAKrAdEolBa13e3h82qqlWMa\\/zGFKgp7oSqIzx+X\\n9flffcFTknKDFXVYEmEKUrC9NnF9a3EKbdHJxlWQjw1jtdMT0rJyUOEjuwPXA6rL\\nMOyxUkHbsP9VwK8BQ1Dt9d3nCO93HzK0Wg7YOcNCnxRUHlk1jlyjjjaVzuNtWPHl\\n0mEkEi2ug\\/NE2xq1lxN6LjlSAEFoTr3dyzPEnV6BLZHcQ7e5tqIHh8GArirvNeYF\\n59ubxMv0wUD2pQGPk1xgNp4f9jebKIyTqEd1UEUkBjfJSYRb4dxiclQT0NhGJoUa\\n3MH3NnQleGm6JwlNJnEvs+ycw1401jqA\\/Gw9vbLM9AGfxXJWlGc0cgbvNhw3W2hq\\nxTixYuairvAmQNMKmtLPq7Kvu+rha0yHu8sqnLNQHodnlw8OrgvRm9vz0Bl7AzaH\\nmYoAYMFTqVno7LxAdXqD4L\\/XJT0tH9XmDZVQxQIDAQABo4IBjzCCAYswEgYDVR0T\\nAQH\\/BAgwBgEB\\/wIBADAOBgNVHQ8BAf8EBAMCAQYwHwYDVR0jBBgwFoAUR1a0R7KZ\\nsgHa5CssxwWNriuO+u0wHQYDVR0OBBYEFG1a9vlrgqQ0oLOASINlnLiP2om\\/MC4G\\nA1UdIAQnMCUwIwYLYIJoAQEBAwxjAQIwFDASBggrBgEFBQcCAjAGHgQAQwBBMIGd\\nBggrBgEFBQcBAQSBkDCBjTBMBggrBgEFBQcwAoZAaHR0cDovL2RldnJlcG9zaXRv\\ncnkuaWR0cnVzdC5pZC9yZXBvc2l0b3J5L2Nlci9TMDAzUk9PVERFVkNBLmNydDA9\\nBggrBgEFBQcwAYYxaHR0cDovL2RldnJlcG9zaXRvcnkuaWR0cnVzdC5pZC9vY3Nw\\ncmVzcG9uZGVyY29yZTBVBgNVHR8ETjBMMEqgSKBGhkRodHRwOi8vZGV2cmVwb3Np\\ndG9yeS5pZHRydXN0LmlkL3JlcG9zaXRvcnkvY3JsL2NybF9TMDAzUk9PVERFVkNB\\nLmNybDANBgkqhkiG9w0BAQsFAAOCAgEAELNo\\/2wVlc7hkcWkGnsfF84ZS7gMlINk\\nunBnCJJ9w41EwQsnXTqTIl9tYYGF6jCJ1YBcDAZhYP6qs0\\/UvZL44jxRng6VZsvT\\n2MtfsNPBPpiUkxXX\\/6jYBUbvSdm1SEBhmd+tB0s6ZV58JKduQoqChFR5F1DUzRQ5\\nfO4qyy7kRTSyjw6nwmJYDKJzJXAK8daXOqOeu34wbOnQK7mO+fu1PGD4cozLgygT\\nyomY9gtbXQD4YC56eAC+iKqZexWJFNiAkdjwyISL0OgmeVC\\/zJo\\/QuNie0hq0dYY\\nKAwxqOlvGVPhEjvmxHkat7MAGe2QJQPC+VISjzq8Zavxs6QZyyT+7n1oqIuE4xWY\\nXJA41Gskp2vYMD3ZZ69y+43OcT5PE1sJEcbG0o372odw7bibywbmMhgJ94qR4QIF\\ngEQOh6D6cy3xAg2wGvAs+wVE622Bg2pBZUNRKjeJATaX9CeYkk7rKjR2uViT8FMw\\nVbRnlrdnpEypA07H48tJP8bEwL7dTkxYHyxxjTJzL7eRroErLtr5FVWjbllkCYE2\\nFNpAn3WIJJAuP90G5YHtBzmIU\\/HEd78sKJH00zhXcPrhckBbx2Zs8Gzq9Ws\\/7+Bz\\nUuIIruHwPa+cfsu+JHF0n\\/raoqoKkxc4ZFHaxMKZSPdvExKrBLtH7N62HNH04Mhw\\n\\/eLTRN0TTpM=\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIFpTCCA42gAwIBAgIQdbmXQifBsO+jOZ3RdjcIlDANBgkqhkiG9w0BAQsFADA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwHhcNMjMxMDE3MDQzODE1WhcNNDMxMDEyMDQzODE1WjA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC8\\nbJl0hhXoKLWm9xw\\/ZPJxgXNIavLpahIpcJodJ\\/rYaWB2pYCn+m4Hni04X5\\/L4IYy\\nEBDJpdzjx4+Zk9bVPEI8V0k9Aip1afQGpSq+CnAd0FcIv3U6g4ZbMYyYck0Upo1S\\nYn04qcu9JzfvRy0Mlz7jqDd1deCgQzShcqg3y4tPd2pJwqjHuRPFdIwBJGoU2fTW\\nuFP3XWrfnc8BUvgN\\/G\\/sBQJLdTNWsbD3qHD\\/rxxJDf3xfnoY1P8BW6hYKxiOf90W\\nn4DVSSEAFcjVrbryVigzT0MBXoBcRYyS0Lag07MKE3zOtXX+zjxoPvjU7oEbAHjG\\n7wWMBPMPytKev+7XWEpsfnsyAUBxAeUnJ5P7uSBDwRx+kwnCJGmNw9BaAnSrqTfQ\\nZwoPYXV5f+PWsjJo\\/tYxdGhxGVpKzCG9H5s8LPhjBcV0ELYfq+9Vi9NG0HeAKBlx\\n4QggjPjcSRti2xBmN1M6TUEoQh7s+6xUaHm3nd0wCTSOxd7oLCT8DmIKEOE\\/Zy40\\n9fUxKo7WWqZdMDKicgbhHk96fE0qlmUtKar6+OM9c4dC1aGksITg+dP41TsF8N4D\\nSTRPwutR\\/d5Aud4WHGJY0JyB7TGlMMB5uxs81K\\/qWXeJJ6dnbwZ1YDpaXe6nulqI\\nqs2VJv2vNKsfTfdNWI1DhTp83xn+8Vu1xjjDYfcwswIDAQABo4GeMIGbMA8GA1Ud\\nEwEB\\/wQFMAMBAf8wDgYDVR0PAQH\\/BAQDAgEGMB8GA1UdIwQYMBaAFEdWtEeymbIB\\n2uQrLMcFja4rjvrtMB0GA1UdDgQWBBRHVrRHspmyAdrkKyzHBY2uK4767TA4BgNV\\nHSAEMTAvMC0GC2CCaAEBAQMMYwEBMB4wHAYIKwYBBQUHAgIwEB4OAFIATwBPAFQA\\nIABDAEEwDQYJKoZIhvcNAQELBQADggIBACt+RUUU0zbKtFPyIyBRzYDwes77C4u2\\nRGLCW5WB9BUmFPG5cjx4ctozzaU2AaphWCsPjDTFANe1hDVpwIT1x\\/SBOvscabtb\\nY6k3ZzXRSLt8qnL0QmWgOrZIjN+I+eVElGAhEeisw7\\/kLIysO0imPG9kGrUd16vG\\n6h3NL6PAhXnlAvIFEbJVuC3lZm9QmOLxyWBFJdxU1GtNY\\/JOHNZR1kppwcRtnW7B\\nT8S1iDbRet3aSOyFGPWG4SlhayylwljAd0U8Q4GMqSNvekBfNGjeIF0KX6EGusVG\\nb+woUt94nNzBl1Kv2vVWI0KfVzTtabG5pk1y92tg55QQLgEUfogT6DdnKrOaMIre\\nvP\\/BawLdHLxw241qdz4W9W2Oz+e0e1Zk2NjiTpBp\\/xUjkw53okulFvoBOROaJfjR\\n6dUDZMCLrVe31C4okTDntWtUgQZPKACiAcUQ26WCKexd79fwoS0JyKGOseuCppW4\\ncOQzw4vcEhzCUcc9VqkZPWhsEbrRcKh6JK+9Sxda4A4EHD1G+GHhuSBBi7gei4Rc\\nLAAWG4GpXQr3deWqzJVaJqlnW1SQs2F3bcHmUyyJ5mPkUVw1vRDjs\\/Rh9dN6sc7M\\nJQHD0RcWiVEg7mFWep6F9XSumSoox7hE\\/ffWKPg95bsG56WCKMiopx8Kn+w71U+P\\nw+wYw5bM1fAR\\n-----END CERTIFICATE-----\\n".replace("\n", "").replace("\\n", "").replace("\\", "").replace("-----BEGIN CERTIFICATE-----", "").split("-----END CERTIFICATE-----");
        Certificate[] certificatesSeal = null;
        KeySigner keySigner = new KeySigner();
        certificatesSeal =  keySigner.getCert2(certSeal);
        signDoc signingSeal = new signDoc(certificatesSeal, "654dc71d897c806af8f98bcf-20231110");

        signingSeal.setExternalSigning(true);
        signingSeal.setTsaURL("http://192.168.16.22:18080/eTSA/etsa");
        signingSeal.setReason("Seal");
        signingSeal.setLocation("Biznet");
        signingSeal.setAccessPermissions(1);
        signingSeal.setImageFile(new File("src/test/resources/qr.png"));

        float lx = 0;
        float ly = 0;
        float rx = 0;
        float ry = 0;
        int page = 0;

        lx = 461;
        ly = 771;
        rx = 594;
        ry = 841;

        float width = rx - lx;
        float height = ry - ly;

        Rectangle2D humanRect = new Rectangle2D.Float(lx, ry, width, height);

        signingSeal.signPDF(new File("src/test/resources/initfile.pdf"), new File("src/test/resources/sealed.pdf"), humanRect, "http://192.168.16.22:18080/eTSA/etsa",UUID.randomUUID().toString() , page);
    }
    @Test
    public void signTest() throws Exception {
        String[] certSign = "-----BEGIN CERTIFICATE-----\\nMIIGdzCCBF+gAwIBAgIRAP0RizKh7OF4pwwifHQbUhYwDQYJKoZIhvcNAQELBQAw\\nOzETMBEGA1UEChMKaWR0cnVzdC5pZDELMAkGA1UEBhMCSUQxFzAVBgNVBAMTDlMw\\nMDMgREVWIENBIEMxMB4XDTIzMTExMzAyMzk0M1oXDTI0MTExMjE2NTk1OVowZTEW\\nMBQGA1UEChMNUFQgS2FuZyBCYWtzbzERMA8GA1UECxMIUGVyc29uYWwxFzAVBgoJ\\nkiaJk\\/IsZAEBEwdOQVMwMDA0MQswCQYDVQQGEwJJRDESMBAGA1UEAxMJTnVyIEFz\\naWFoMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwMb21vX1QqkVoZHL\\npgy\\/E+q5pE6UhGYwUxADA9WiAMfDiCQBXpqrePg0yWUb5Z0Wu+oy2ZXDX3UwCoxn\\nYRPMnKatotNMlOpDUX\\/KHd4HAYCpwNY\\/1pdjKf7gy0GuZo78UKXHoL19sV7kNkIT\\nC90YTEN+ica+v8Uup9ZRCcTKZ20GbxvLkEawQ4U0McQHMnj7lGSs8KRGBCvkK+5p\\njOJuX0bZKlRvieS6ZNhveFNL5FymdwIcj+OADawNQz3B9ga2MnubqeT8PcN07Epi\\nOhNKffo9YhYGYfhMWIr16xgaXy0zjlgTNwh0F2U1x2XBzASQQVWBS\\/GB1TOieijM\\nol7MgwIDAQABo4ICSjCCAkYwDAYDVR0TAQH\\/BAIwADAOBgNVHQ8BAf8EBAMCBsAw\\nHwYDVR0jBBgwFoAUbVr2+WuCpDSgs4BIg2WcuI\\/aib8wHQYDVR0OBBYEFHp+t4mf\\n0xC+1jfQ\\/OGoSbiLauwWMIGdBggrBgEFBQcBAQSBkDCBjTBLBggrBgEFBQcwAoY\\/\\naHR0cHM6Ly9kZXZyZXBvc2l0b3J5LmlkdHJ1c3QuaWQvcmVwb3NpdG9yeS9jZXIv\\naWR0cnVzdGlkYzEuY3J0MD4GCCsGAQUFBzABhjJodHRwczovL2RldnJlcG9zaXRv\\ncnkuaWR0cnVzdC5pZC9vY3NwcmVzcG9uZGVyY29yZTBQBgNVHR8ESTBHMEWgQ6BB\\nhj9odHRwczovL2RldnJlcG9zaXRvcnkuaWR0cnVzdC5pZC9yZXBvc2l0b3J5L2Ny\\nbC9pZHRydXN0aWRDMS5jcmwwgfMGA1UdIASB6zCB6DAxBglggmgBAQEDDGMwJDAi\\nBggrBgEFBQcCAjAWHhQAaQBkAHQAcgB1AHMAdAAuAGkAZDBfBgtggmgBAQEDDGMC\\nATBQME4GCCsGAQUFBwICMEIeQABoAHQAdABwAHMAOgAvAC8AZABlAHYAcgBlAHAA\\nbwBzAGkAdABvAHIAeQAuAGkAZAB0AHIAdQBzAHQALgBpAGQwUgYKYIJoAQEBBQEC\\nAjBEMEIGCCsGAQUFBwICMDYeNABpAG4AZABpAHYAaQBkAHUALQB3AG4AaQAgAG8A\\nbgBsAGkAbgBlACAAbABlAHYAZQBsADIwDQYJKoZIhvcNAQELBQADggIBAB+5l9hU\\nBCzRE0NE8HptnTzIJgbtPiac4abds56ObhnEqg\\/I6Dlz5vl\\/BmPNApihfeSvLx6T\\ntB1js\\/p7WY5AQ3dUvfwXM52OFgkLvBAdM++UZwKmHBMjbSfdwK0NHr8f\\/N+pLxr+\\nyUwA7SdIclyQXNrnb78zVXKMnD7p8f+iIO70k3KzYksBaEuV\\/KqRahatG\\/8SK8nh\\nj7EQRvXaNIZUjTvttXkIf\\/DWfDHp4wFHXkrC\\/Ojv35cGz2ZddPSMe\\/VxoBzC+mSc\\nKt6mPTyq68Joqn88+X89zy4uqxJ6EglMf0EA5jKEgpqoV4grFLcm9z2cmH38AOF8\\nBmBdxZ8vSKnCEZsO5NGbEel2KNrknB1Ga8PfX4o4Ldw\\/ZdMSNUHS5JM+dGkTQKnZ\\nDkx6Agz1u6xuwW1Qan1Cjd4SLOlY\\/A2Bb3A5csZyG0Y0A6K9m\\/XEU14CgzpRmJd2\\nr9AFulEANESpJC4COw48bo82dRyF\\/yGQ6G6JVl9OMOp6wOI4cDNlfLKLRUtKKXIz\\ngFBfqAx0xFswn6wINUJHbZ4a5DLBQFlynAp3pNeoov8AnSDoUmK8BvzWGXmR9ZaK\\nrQlspddFW8bxx3LZ3Xbo9FCi9rF1rs+2KEQNtYPn7EADRwNXFVd2XNaDiJs+eTsK\\n16Keyr5sS+0FaTxBvHBHqPTNNRVkkXzPWQ3b\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIGlDCCBHygAwIBAgIQR40GDBEETAc3RD1flKDBvjANBgkqhkiG9w0BAQsFADA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwHhcNMjMxMDE3MDQ0NDAzWhcNMzMwODI1MDQ0NDAzWjA7\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEXMBUGA1UEAxMOUzAw\\nMyBERVYgQ0EgQzEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQClUzoe\\nUo3iCw0laovONMAfBImalKmU+1I6o2mcPkEd3mWnTjePL11wpINUXgU8AcVdoO9f\\nVOKB7qhayas8bkWCtPg9LQMdsRV68Z+7+PxhxiqAep\\/qTO1gfz0SWk4zVQiRH9wn\\nCfJ+fUxmboTOT+wuWrrbSBLMPqt9pIbSzt\\/oaFWRYaUxadBzSsyus3qnZUrBd8UJ\\nqpIVxEBiuPIoPZpiWpCb5afIvAKrAdEolBa13e3h82qqlWMa\\/zGFKgp7oSqIzx+X\\n9flffcFTknKDFXVYEmEKUrC9NnF9a3EKbdHJxlWQjw1jtdMT0rJyUOEjuwPXA6rL\\nMOyxUkHbsP9VwK8BQ1Dt9d3nCO93HzK0Wg7YOcNCnxRUHlk1jlyjjjaVzuNtWPHl\\n0mEkEi2ug\\/NE2xq1lxN6LjlSAEFoTr3dyzPEnV6BLZHcQ7e5tqIHh8GArirvNeYF\\n59ubxMv0wUD2pQGPk1xgNp4f9jebKIyTqEd1UEUkBjfJSYRb4dxiclQT0NhGJoUa\\n3MH3NnQleGm6JwlNJnEvs+ycw1401jqA\\/Gw9vbLM9AGfxXJWlGc0cgbvNhw3W2hq\\nxTixYuairvAmQNMKmtLPq7Kvu+rha0yHu8sqnLNQHodnlw8OrgvRm9vz0Bl7AzaH\\nmYoAYMFTqVno7LxAdXqD4L\\/XJT0tH9XmDZVQxQIDAQABo4IBjzCCAYswEgYDVR0T\\nAQH\\/BAgwBgEB\\/wIBADAOBgNVHQ8BAf8EBAMCAQYwHwYDVR0jBBgwFoAUR1a0R7KZ\\nsgHa5CssxwWNriuO+u0wHQYDVR0OBBYEFG1a9vlrgqQ0oLOASINlnLiP2om\\/MC4G\\nA1UdIAQnMCUwIwYLYIJoAQEBAwxjAQIwFDASBggrBgEFBQcCAjAGHgQAQwBBMIGd\\nBggrBgEFBQcBAQSBkDCBjTBMBggrBgEFBQcwAoZAaHR0cDovL2RldnJlcG9zaXRv\\ncnkuaWR0cnVzdC5pZC9yZXBvc2l0b3J5L2Nlci9TMDAzUk9PVERFVkNBLmNydDA9\\nBggrBgEFBQcwAYYxaHR0cDovL2RldnJlcG9zaXRvcnkuaWR0cnVzdC5pZC9vY3Nw\\ncmVzcG9uZGVyY29yZTBVBgNVHR8ETjBMMEqgSKBGhkRodHRwOi8vZGV2cmVwb3Np\\ndG9yeS5pZHRydXN0LmlkL3JlcG9zaXRvcnkvY3JsL2NybF9TMDAzUk9PVERFVkNB\\nLmNybDANBgkqhkiG9w0BAQsFAAOCAgEAELNo\\/2wVlc7hkcWkGnsfF84ZS7gMlINk\\nunBnCJJ9w41EwQsnXTqTIl9tYYGF6jCJ1YBcDAZhYP6qs0\\/UvZL44jxRng6VZsvT\\n2MtfsNPBPpiUkxXX\\/6jYBUbvSdm1SEBhmd+tB0s6ZV58JKduQoqChFR5F1DUzRQ5\\nfO4qyy7kRTSyjw6nwmJYDKJzJXAK8daXOqOeu34wbOnQK7mO+fu1PGD4cozLgygT\\nyomY9gtbXQD4YC56eAC+iKqZexWJFNiAkdjwyISL0OgmeVC\\/zJo\\/QuNie0hq0dYY\\nKAwxqOlvGVPhEjvmxHkat7MAGe2QJQPC+VISjzq8Zavxs6QZyyT+7n1oqIuE4xWY\\nXJA41Gskp2vYMD3ZZ69y+43OcT5PE1sJEcbG0o372odw7bibywbmMhgJ94qR4QIF\\ngEQOh6D6cy3xAg2wGvAs+wVE622Bg2pBZUNRKjeJATaX9CeYkk7rKjR2uViT8FMw\\nVbRnlrdnpEypA07H48tJP8bEwL7dTkxYHyxxjTJzL7eRroErLtr5FVWjbllkCYE2\\nFNpAn3WIJJAuP90G5YHtBzmIU\\/HEd78sKJH00zhXcPrhckBbx2Zs8Gzq9Ws\\/7+Bz\\nUuIIruHwPa+cfsu+JHF0n\\/raoqoKkxc4ZFHaxMKZSPdvExKrBLtH7N62HNH04Mhw\\n\\/eLTRN0TTpM=\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIFpTCCA42gAwIBAgIQdbmXQifBsO+jOZ3RdjcIlDANBgkqhkiG9w0BAQsFADA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwHhcNMjMxMDE3MDQzODE1WhcNNDMxMDEyMDQzODE1WjA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC8\\nbJl0hhXoKLWm9xw\\/ZPJxgXNIavLpahIpcJodJ\\/rYaWB2pYCn+m4Hni04X5\\/L4IYy\\nEBDJpdzjx4+Zk9bVPEI8V0k9Aip1afQGpSq+CnAd0FcIv3U6g4ZbMYyYck0Upo1S\\nYn04qcu9JzfvRy0Mlz7jqDd1deCgQzShcqg3y4tPd2pJwqjHuRPFdIwBJGoU2fTW\\nuFP3XWrfnc8BUvgN\\/G\\/sBQJLdTNWsbD3qHD\\/rxxJDf3xfnoY1P8BW6hYKxiOf90W\\nn4DVSSEAFcjVrbryVigzT0MBXoBcRYyS0Lag07MKE3zOtXX+zjxoPvjU7oEbAHjG\\n7wWMBPMPytKev+7XWEpsfnsyAUBxAeUnJ5P7uSBDwRx+kwnCJGmNw9BaAnSrqTfQ\\nZwoPYXV5f+PWsjJo\\/tYxdGhxGVpKzCG9H5s8LPhjBcV0ELYfq+9Vi9NG0HeAKBlx\\n4QggjPjcSRti2xBmN1M6TUEoQh7s+6xUaHm3nd0wCTSOxd7oLCT8DmIKEOE\\/Zy40\\n9fUxKo7WWqZdMDKicgbhHk96fE0qlmUtKar6+OM9c4dC1aGksITg+dP41TsF8N4D\\nSTRPwutR\\/d5Aud4WHGJY0JyB7TGlMMB5uxs81K\\/qWXeJJ6dnbwZ1YDpaXe6nulqI\\nqs2VJv2vNKsfTfdNWI1DhTp83xn+8Vu1xjjDYfcwswIDAQABo4GeMIGbMA8GA1Ud\\nEwEB\\/wQFMAMBAf8wDgYDVR0PAQH\\/BAQDAgEGMB8GA1UdIwQYMBaAFEdWtEeymbIB\\n2uQrLMcFja4rjvrtMB0GA1UdDgQWBBRHVrRHspmyAdrkKyzHBY2uK4767TA4BgNV\\nHSAEMTAvMC0GC2CCaAEBAQMMYwEBMB4wHAYIKwYBBQUHAgIwEB4OAFIATwBPAFQA\\nIABDAEEwDQYJKoZIhvcNAQELBQADggIBACt+RUUU0zbKtFPyIyBRzYDwes77C4u2\\nRGLCW5WB9BUmFPG5cjx4ctozzaU2AaphWCsPjDTFANe1hDVpwIT1x\\/SBOvscabtb\\nY6k3ZzXRSLt8qnL0QmWgOrZIjN+I+eVElGAhEeisw7\\/kLIysO0imPG9kGrUd16vG\\n6h3NL6PAhXnlAvIFEbJVuC3lZm9QmOLxyWBFJdxU1GtNY\\/JOHNZR1kppwcRtnW7B\\nT8S1iDbRet3aSOyFGPWG4SlhayylwljAd0U8Q4GMqSNvekBfNGjeIF0KX6EGusVG\\nb+woUt94nNzBl1Kv2vVWI0KfVzTtabG5pk1y92tg55QQLgEUfogT6DdnKrOaMIre\\nvP\\/BawLdHLxw241qdz4W9W2Oz+e0e1Zk2NjiTpBp\\/xUjkw53okulFvoBOROaJfjR\\n6dUDZMCLrVe31C4okTDntWtUgQZPKACiAcUQ26WCKexd79fwoS0JyKGOseuCppW4\\ncOQzw4vcEhzCUcc9VqkZPWhsEbrRcKh6JK+9Sxda4A4EHD1G+GHhuSBBi7gei4Rc\\nLAAWG4GpXQr3deWqzJVaJqlnW1SQs2F3bcHmUyyJ5mPkUVw1vRDjs\\/Rh9dN6sc7M\\nJQHD0RcWiVEg7mFWep6F9XSumSoox7hE\\/ffWKPg95bsG56WCKMiopx8Kn+w71U+P\\nw+wYw5bM1fAR\\n-----END CERTIFICATE-----\\n".replace("\n", "").replace("\\n", "").replace("\\", "").replace("-----BEGIN CERTIFICATE-----", "").split("-----END CERTIFICATE-----");
        String[] certSeal = "-----BEGIN CERTIFICATE-----\\nMIIGSDCCBDCgAwIBAgIRAJ8neEe0myca8qhjUOG5nrMwDQYJKoZIhvcNAQELBQAw\\nOzETMBEGA1UEChMKaWR0cnVzdC5pZDELMAkGA1UEBhMCSUQxFzAVBgNVBAMTDlMw\\nMDMgREVWIENBIEMxMB4XDTIzMTExMDA2MjIxOFoXDTI0MTEwOTE2NTk1OVowNDEN\\nMAsGA1UECxMEc2VhbDELMAkGA1UEBhMCSUQxFjAUBgNVBAMTDVBUIEthbmcgQmFr\\nc28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCksiEWBj0WVR9MgO\\/i\\nes88qbIHrsL5cZjJSCsoG6k\\/+3gREidafUam2Sa7HPy+rKazP7LTlq2P4JoF5axf\\nRNJ2tm024PQ6ZNQbIO1ODTFXHmO79qSvHUFbnBx1PpBlq6zy+HBVfeb47OkJe1jI\\nUlEaBpA1Tg185bXO4+9Bw2htahi0jQ\\/jA34Q0pkaxYuK6fLh3UNElQ9cpnwuWK6C\\n6Oom\\/VFXrF4TTKfgoE\\/Jp6Y3\\/Qqf8gzZ+6Jo5HQBGNa4kSBfl9DR0F937gN+nnjY\\n5mDSnJwIo+ThKZXVpdfkpNCVejzsJRk8doRd44BrpF\\/BmGQ2greihuw9o\\/rwj1ig\\nuERLAgMBAAGjggJMMIICSDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB\\/wQEAwIGwDAf\\nBgNVHSMEGDAWgBRtWvb5a4KkNKCzgEiDZZy4j9qJvzAdBgNVHQ4EFgQU1GzstIUw\\ny1CYJ14msXkjPdPWdgYwgZ0GCCsGAQUFBwEBBIGQMIGNMEsGCCsGAQUFBzAChj9o\\ndHRwczovL2RldnJlcG9zaXRvcnkuaWR0cnVzdC5pZC9yZXBvc2l0b3J5L2Nlci9p\\nZHRydXN0aWRjMS5jcnQwPgYIKwYBBQUHMAGGMmh0dHBzOi8vZGV2cmVwb3NpdG9y\\neS5pZHRydXN0LmlkL29jc3ByZXNwb25kZXJjb3JlMFAGA1UdHwRJMEcwRaBDoEGG\\nP2h0dHBzOi8vZGV2cmVwb3NpdG9yeS5pZHRydXN0LmlkL3JlcG9zaXRvcnkvY3Js\\nL2lkdHJ1c3RpZEMxLmNybDCB9QYDVR0gBIHtMIHqMDEGCWCCaAEBAQMMYzAkMCIG\\nCCsGAQUFBwICMBYeFABpAGQAdAByAHUAcwB0AC4AaQBkMF8GC2CCaAEBAQMMYwIB\\nMFAwTgYIKwYBBQUHAgIwQh5AAGgAdAB0AHAAcwA6AC8ALwBkAGUAdgByAGUAcABv\\nAHMAaQB0AG8AcgB5AC4AaQBkAHQAcgB1AHMAdAAuAGkAZDBUBghggmgBAQEIATBI\\nMEYGCCsGAQUFBwICMDoeOABzAGUAZwBlAGwALQBlAGwAZQBrAHQAcgBvAG4AaQBr\\nACAAYgBhAGQAYQBuAC0AdQBzAGEAaABhMA0GCSqGSIb3DQEBCwUAA4ICAQBSEylc\\nhyI2qxdjlRdEQMC49PbvYwzHSn7v1lCi4607E09SmEkgAFYotKHuffUklhHndTaQ\\nhYJwy3qM7+TNdrOyL7CILWbNXEwMPwMytXexrsjAypaPCZj7RhqlYWYRnveuffmB\\ncmYpKnzkNDpPSeGKdJqmPTMLQEmL2YJJPli40X9AoZjyzV6qHVGhWBciwLE7ah29\\ndIrPUmXvvdq8KMFcgyo+Ax7U9s4SxE3l1SIvbF0Utxfeaa1+h+60fFfYY9WGDG3X\\n0m0tA6fW0eu+ZN43b7lUvoL57KAy706PHQ33A6D7NQkeqPcHtnrkuV+jPOry2XRh\\nLCuLvDJPhLc9RpHA6tFZfDyCioSo+deGeHqepreeiQGIfohU0acg4NbsrV7C\\/J2M\\nBGfPvv6L9829XpyCDXg8C4ZZnftOSdLgsCKIQ+O4yb2kmMsTiXDp07t+mYyVH1FD\\nHA66Cx7ZmLhhf8v\\/Zy22c8nP4Kdt22F0SwVbe2LhNh8DXLzT2KQaIloSgToFHr0f\\nECasUXo3R5lsT13y\\/LSIouO1xPDkYS9aQa70cXtTOoQf0S7AVWd3Eq63aHqaEj5Q\\n33S4BNJheoVbdWofaZRZJGmN5ZGTcKD8YzA2ZNHFAnbCzJ6HUZsjaVKRO9cts+iQ\\nCgthYezCgXhYc4rmqVROPBxN0Unogkjeyr4ULA==\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIGlDCCBHygAwIBAgIQR40GDBEETAc3RD1flKDBvjANBgkqhkiG9w0BAQsFADA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwHhcNMjMxMDE3MDQ0NDAzWhcNMzMwODI1MDQ0NDAzWjA7\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEXMBUGA1UEAxMOUzAw\\nMyBERVYgQ0EgQzEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQClUzoe\\nUo3iCw0laovONMAfBImalKmU+1I6o2mcPkEd3mWnTjePL11wpINUXgU8AcVdoO9f\\nVOKB7qhayas8bkWCtPg9LQMdsRV68Z+7+PxhxiqAep\\/qTO1gfz0SWk4zVQiRH9wn\\nCfJ+fUxmboTOT+wuWrrbSBLMPqt9pIbSzt\\/oaFWRYaUxadBzSsyus3qnZUrBd8UJ\\nqpIVxEBiuPIoPZpiWpCb5afIvAKrAdEolBa13e3h82qqlWMa\\/zGFKgp7oSqIzx+X\\n9flffcFTknKDFXVYEmEKUrC9NnF9a3EKbdHJxlWQjw1jtdMT0rJyUOEjuwPXA6rL\\nMOyxUkHbsP9VwK8BQ1Dt9d3nCO93HzK0Wg7YOcNCnxRUHlk1jlyjjjaVzuNtWPHl\\n0mEkEi2ug\\/NE2xq1lxN6LjlSAEFoTr3dyzPEnV6BLZHcQ7e5tqIHh8GArirvNeYF\\n59ubxMv0wUD2pQGPk1xgNp4f9jebKIyTqEd1UEUkBjfJSYRb4dxiclQT0NhGJoUa\\n3MH3NnQleGm6JwlNJnEvs+ycw1401jqA\\/Gw9vbLM9AGfxXJWlGc0cgbvNhw3W2hq\\nxTixYuairvAmQNMKmtLPq7Kvu+rha0yHu8sqnLNQHodnlw8OrgvRm9vz0Bl7AzaH\\nmYoAYMFTqVno7LxAdXqD4L\\/XJT0tH9XmDZVQxQIDAQABo4IBjzCCAYswEgYDVR0T\\nAQH\\/BAgwBgEB\\/wIBADAOBgNVHQ8BAf8EBAMCAQYwHwYDVR0jBBgwFoAUR1a0R7KZ\\nsgHa5CssxwWNriuO+u0wHQYDVR0OBBYEFG1a9vlrgqQ0oLOASINlnLiP2om\\/MC4G\\nA1UdIAQnMCUwIwYLYIJoAQEBAwxjAQIwFDASBggrBgEFBQcCAjAGHgQAQwBBMIGd\\nBggrBgEFBQcBAQSBkDCBjTBMBggrBgEFBQcwAoZAaHR0cDovL2RldnJlcG9zaXRv\\ncnkuaWR0cnVzdC5pZC9yZXBvc2l0b3J5L2Nlci9TMDAzUk9PVERFVkNBLmNydDA9\\nBggrBgEFBQcwAYYxaHR0cDovL2RldnJlcG9zaXRvcnkuaWR0cnVzdC5pZC9vY3Nw\\ncmVzcG9uZGVyY29yZTBVBgNVHR8ETjBMMEqgSKBGhkRodHRwOi8vZGV2cmVwb3Np\\ndG9yeS5pZHRydXN0LmlkL3JlcG9zaXRvcnkvY3JsL2NybF9TMDAzUk9PVERFVkNB\\nLmNybDANBgkqhkiG9w0BAQsFAAOCAgEAELNo\\/2wVlc7hkcWkGnsfF84ZS7gMlINk\\nunBnCJJ9w41EwQsnXTqTIl9tYYGF6jCJ1YBcDAZhYP6qs0\\/UvZL44jxRng6VZsvT\\n2MtfsNPBPpiUkxXX\\/6jYBUbvSdm1SEBhmd+tB0s6ZV58JKduQoqChFR5F1DUzRQ5\\nfO4qyy7kRTSyjw6nwmJYDKJzJXAK8daXOqOeu34wbOnQK7mO+fu1PGD4cozLgygT\\nyomY9gtbXQD4YC56eAC+iKqZexWJFNiAkdjwyISL0OgmeVC\\/zJo\\/QuNie0hq0dYY\\nKAwxqOlvGVPhEjvmxHkat7MAGe2QJQPC+VISjzq8Zavxs6QZyyT+7n1oqIuE4xWY\\nXJA41Gskp2vYMD3ZZ69y+43OcT5PE1sJEcbG0o372odw7bibywbmMhgJ94qR4QIF\\ngEQOh6D6cy3xAg2wGvAs+wVE622Bg2pBZUNRKjeJATaX9CeYkk7rKjR2uViT8FMw\\nVbRnlrdnpEypA07H48tJP8bEwL7dTkxYHyxxjTJzL7eRroErLtr5FVWjbllkCYE2\\nFNpAn3WIJJAuP90G5YHtBzmIU\\/HEd78sKJH00zhXcPrhckBbx2Zs8Gzq9Ws\\/7+Bz\\nUuIIruHwPa+cfsu+JHF0n\\/raoqoKkxc4ZFHaxMKZSPdvExKrBLtH7N62HNH04Mhw\\n\\/eLTRN0TTpM=\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIFpTCCA42gAwIBAgIQdbmXQifBsO+jOZ3RdjcIlDANBgkqhkiG9w0BAQsFADA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwHhcNMjMxMDE3MDQzODE1WhcNNDMxMDEyMDQzODE1WjA+\\nMRMwEQYDVQQKEwppZHRydXN0LmlkMQswCQYDVQQGEwJJRDEaMBgGA1UEAxMRUzAw\\nMyBST09UIERFViBDQSAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC8\\nbJl0hhXoKLWm9xw\\/ZPJxgXNIavLpahIpcJodJ\\/rYaWB2pYCn+m4Hni04X5\\/L4IYy\\nEBDJpdzjx4+Zk9bVPEI8V0k9Aip1afQGpSq+CnAd0FcIv3U6g4ZbMYyYck0Upo1S\\nYn04qcu9JzfvRy0Mlz7jqDd1deCgQzShcqg3y4tPd2pJwqjHuRPFdIwBJGoU2fTW\\nuFP3XWrfnc8BUvgN\\/G\\/sBQJLdTNWsbD3qHD\\/rxxJDf3xfnoY1P8BW6hYKxiOf90W\\nn4DVSSEAFcjVrbryVigzT0MBXoBcRYyS0Lag07MKE3zOtXX+zjxoPvjU7oEbAHjG\\n7wWMBPMPytKev+7XWEpsfnsyAUBxAeUnJ5P7uSBDwRx+kwnCJGmNw9BaAnSrqTfQ\\nZwoPYXV5f+PWsjJo\\/tYxdGhxGVpKzCG9H5s8LPhjBcV0ELYfq+9Vi9NG0HeAKBlx\\n4QggjPjcSRti2xBmN1M6TUEoQh7s+6xUaHm3nd0wCTSOxd7oLCT8DmIKEOE\\/Zy40\\n9fUxKo7WWqZdMDKicgbhHk96fE0qlmUtKar6+OM9c4dC1aGksITg+dP41TsF8N4D\\nSTRPwutR\\/d5Aud4WHGJY0JyB7TGlMMB5uxs81K\\/qWXeJJ6dnbwZ1YDpaXe6nulqI\\nqs2VJv2vNKsfTfdNWI1DhTp83xn+8Vu1xjjDYfcwswIDAQABo4GeMIGbMA8GA1Ud\\nEwEB\\/wQFMAMBAf8wDgYDVR0PAQH\\/BAQDAgEGMB8GA1UdIwQYMBaAFEdWtEeymbIB\\n2uQrLMcFja4rjvrtMB0GA1UdDgQWBBRHVrRHspmyAdrkKyzHBY2uK4767TA4BgNV\\nHSAEMTAvMC0GC2CCaAEBAQMMYwEBMB4wHAYIKwYBBQUHAgIwEB4OAFIATwBPAFQA\\nIABDAEEwDQYJKoZIhvcNAQELBQADggIBACt+RUUU0zbKtFPyIyBRzYDwes77C4u2\\nRGLCW5WB9BUmFPG5cjx4ctozzaU2AaphWCsPjDTFANe1hDVpwIT1x\\/SBOvscabtb\\nY6k3ZzXRSLt8qnL0QmWgOrZIjN+I+eVElGAhEeisw7\\/kLIysO0imPG9kGrUd16vG\\n6h3NL6PAhXnlAvIFEbJVuC3lZm9QmOLxyWBFJdxU1GtNY\\/JOHNZR1kppwcRtnW7B\\nT8S1iDbRet3aSOyFGPWG4SlhayylwljAd0U8Q4GMqSNvekBfNGjeIF0KX6EGusVG\\nb+woUt94nNzBl1Kv2vVWI0KfVzTtabG5pk1y92tg55QQLgEUfogT6DdnKrOaMIre\\nvP\\/BawLdHLxw241qdz4W9W2Oz+e0e1Zk2NjiTpBp\\/xUjkw53okulFvoBOROaJfjR\\n6dUDZMCLrVe31C4okTDntWtUgQZPKACiAcUQ26WCKexd79fwoS0JyKGOseuCppW4\\ncOQzw4vcEhzCUcc9VqkZPWhsEbrRcKh6JK+9Sxda4A4EHD1G+GHhuSBBi7gei4Rc\\nLAAWG4GpXQr3deWqzJVaJqlnW1SQs2F3bcHmUyyJ5mPkUVw1vRDjs\\/Rh9dN6sc7M\\nJQHD0RcWiVEg7mFWep6F9XSumSoox7hE\\/ffWKPg95bsG56WCKMiopx8Kn+w71U+P\\nw+wYw5bM1fAR\\n-----END CERTIFICATE-----\\n".replace("\n", "").replace("\\n", "").replace("\\", "").replace("-----BEGIN CERTIFICATE-----", "").split("-----END CERTIFICATE-----");
        Certificate[] certificates = null;
        Certificate[] certificatesSeal = null;
        KeySigner keySigner = new KeySigner();
        certificates =  keySigner.getCert2(certSign);
        certificatesSeal =  keySigner.getCert2(certSeal);
        signDoc signing = new signDoc(certificates, "65518bb8b93ccea138144b60-20231113");
        signDoc signingSeal = new signDoc(certificatesSeal, "654dc71d897c806af8f98bcf-20231110");
        signDoc signingSeal2 = new signDoc(certificatesSeal, "654dc71d897c806af8f98bcf-20231110");

        signing.setExternalSigning(true);
        signing.setTsaURL("http://192.168.16.22:18080/eTSA/etsa");
        signing.setReason("TTD biasa");
        signing.setLocation("Biznet");
        signing.setAccessPermissions(0);
        signing.setImageFile(new File("src/test/resources/qr.png"));

        signingSeal.setExternalSigning(true);
        signingSeal.setTsaURL("http://192.168.16.22:18080/eTSA/etsa");
        signingSeal.setReason("Seal");
        signingSeal.setLocation("Biznet");
        signingSeal.setAccessPermissions(1);
        signingSeal.setImageFile(new File("src/test/resources/qr.png"));

        signingSeal2.setExternalSigning(true);
        signingSeal2.setTsaURL("http://192.168.16.22:18080/eTSA/etsa");
        signingSeal2.setReason("Seal");
        signingSeal2.setLocation("Biznet");
        signingSeal2.setAccessPermissions(1);
        signingSeal2.setImageFile(new File("src/test/resources/qr.png"));

        File infile = new File("src/test/resources/initfile.pdf");
        File outFile = new File("src/test/resources/signedfile.pdf");

        float lx = 0;
        float ly = 0;
        float rx = 0;
        float ry = 0;
        int page = 0;

        lx = 461;
        ly = 771;
        rx = 594;
        ry = 841;

        float width = rx - lx;
        float height = ry - ly;

        Rectangle2D humanRect = new Rectangle2D.Float(lx, ry, width, height);

        signing.signPDF(infile, outFile, humanRect, "http://192.168.16.22:18080/eTSA/etsa", UUID.randomUUID().toString(), page);

        //LTV
        AddValidationInformation ltv = new AddValidationInformation();

        ltv.validateSignature(outFile, new File("src/test/resources/signedfile_ltv.pdf"));

        File outFile2 = new File("src/test/resources/sealfile.pdf");

        String signNAme=UUID.randomUUID().toString();
        signingSeal.signPDF(new File("src/test/resources/signedfile_ltv.pdf"), outFile2, humanRect, "http://192.168.16.22:18080/eTSA/etsa",signNAme , page);

        ltv = new AddValidationInformation();

        File fileSeal = new File("src/test/resources/sealfile.pdf");
        ltv.validateSignature(fileSeal, new File("src/test/resources/sealfile_ltv.pdf"));

        //Test existing lock dictionary
        signingSeal2.signPDF(new File("src/test/resources/sealfile_ltv.pdf"), new File("src/test/resources/o.pdf"), humanRect, "http://192.168.16.22:18080/eTSA/etsa",signNAme+"1" , page);
    }
    @Test
    public void checkExistingSignature() throws IOException {
        int sizeSignature = 0;



        File file = new File(classLoader.getResource("docTest/signed.pdf").getFile());
        PDDocument doc = PDDocument.load(file);
        PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm(null);
        sizeSignature = isAnySignature(acroForm);

        System.out.println("Size : " + sizeSignature);
    }

    private int isAnySignature(PDAcroForm acroForm)
    {
        int sizeSignature = 0;
        if (acroForm != null)
        {
            sizeSignature = acroForm.getFields().size();
        }
        return sizeSignature;
    }
}

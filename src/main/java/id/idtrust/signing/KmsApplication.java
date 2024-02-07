package id.idtrust.signing;

import id.idtrust.signing.core.pdf.QRCode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;
import java.util.Date;

@SpringBootApplication
public class KmsApplication {

    public static void main(String[] args) throws Exception
	{
//		QRCode qr = new QRCode();
//		qr.generateImageSignNoQr("String nama", "signature.png", "new.png", new Date());
		SpringApplication.run(KmsApplication.class, args);

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
}
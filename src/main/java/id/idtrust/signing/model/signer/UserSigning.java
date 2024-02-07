package id.idtrust.signing.model.signer;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserSigning {

    private String document;
    private String private_key_alias;
    private String signer_certificate_chain;
    private SigningProperties signingProperties;
    private String signerName;
    private String signatureImage;
    private String initialImage;


}

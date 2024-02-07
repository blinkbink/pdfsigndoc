package id.idtrust.signing.model.signer;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SigningProperties {

    private String location;
    private String reason;
    private String signature_id;
    private List<SigningLocation> signingLocationList;

    private List<InitialLocation> initialLocationList;
    private int type_signature;

}

package id.idtrust.signing.model.signer;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SigningLocation {

    private int page;
    private float llx;
    private float lly;
    private float urx;
    private float ury;
}

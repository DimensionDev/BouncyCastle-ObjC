package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *       TaggedCertificationRequest ::= SEQUENCE {
 *                  bodyPartID            BodyPartID,
 *                  certificationRequest  CmcCertificationRequest
 *       }
 * </pre>
 */
public class TaggedCertificationRequest
    extends ASN1Object
{
    private final BodyPartID bodyPartID;
    private final CmcCertificationRequest certificationRequest;

    public TaggedCertificationRequest(BodyPartID bodyPartID, CmcCertificationRequest certificationRequest)
    {
        this.bodyPartID = bodyPartID;
        this.certificationRequest = certificationRequest;
    }

    private TaggedCertificationRequest(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
        this.certificationRequest = CmcCertificationRequest.getInstance(seq.getObjectAt(1));
    }

    public static TaggedCertificationRequest getInstance(Object o)
    {
        if (o instanceof TaggedCertificationRequest)
        {
            return (TaggedCertificationRequest)o;
        }

        if (o != null)
        {
            return new TaggedCertificationRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static TaggedCertificationRequest getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(bodyPartID);
        v.add(certificationRequest);

        return new DERSequence(v);
    }
}

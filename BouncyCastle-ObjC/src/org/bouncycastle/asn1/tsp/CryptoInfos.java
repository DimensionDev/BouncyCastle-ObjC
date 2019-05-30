package org.bouncycastle.asn1.tsp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.CmsAttribute;

/**
 * Implementation of the CryptoInfos element defined in RFC 4998:
 * <p>
 * CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF CmsAttribute
 */
public class CryptoInfos
    extends ASN1Object
{
    private ASN1Sequence attributes;

    public static CryptoInfos getInstance(final Object obj)
    {
        if (obj instanceof CryptoInfos)
        {
            return (CryptoInfos)obj;
        }
        else if (obj != null)
        {
            return new CryptoInfos(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static CryptoInfos getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private CryptoInfos(final ASN1Sequence attributes)
    {
        this.attributes = attributes;
    }

    public CryptoInfos(CmsAttribute[] attrs)
    {
        attributes = new DERSequence(attrs);
    }

    public CmsAttribute[] getAttributes()
    {
        CmsAttribute[] rv = new CmsAttribute[attributes.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = CmsAttribute.getInstance(attributes.getObjectAt(i));
        }

        return rv;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return attributes;
    }
}

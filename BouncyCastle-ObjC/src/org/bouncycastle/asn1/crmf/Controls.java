package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class Controls
    extends ASN1Object
{
    private ASN1Sequence content;

    private Controls(ASN1Sequence seq)
    {
        content = seq;
    }

    public static Controls getInstance(Object o)
    {
        if (o instanceof Controls)
        {
            return (Controls)o;
        }

        if (o != null)
        {
            return new Controls(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Controls(CrmfAttributeTypeAndValue atv)
    {
        content = new DERSequence(atv);
    }

    public Controls(CrmfAttributeTypeAndValue[] atvs)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < atvs.length; i++)
        {
            v.add(atvs[i]);
        }
        content = new DERSequence(v);
    }

    public CrmfAttributeTypeAndValue[] toAttributeTypeAndValueArray()
    {
        CrmfAttributeTypeAndValue[] result = new CrmfAttributeTypeAndValue[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = CrmfAttributeTypeAndValue.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * Controls  ::= SEQUENCE SIZE(1..MAX) OF CrmfAttributeTypeAndValue
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}

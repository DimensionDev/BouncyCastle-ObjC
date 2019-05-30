package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class CrmfAttributeTypeAndValue
    extends ASN1Object
{
    private ASN1ObjectIdentifier type;
    private ASN1Encodable       value;

    private CrmfAttributeTypeAndValue(ASN1Sequence seq)
    {
        type = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        value = (ASN1Encodable)seq.getObjectAt(1);
    }

    public static CrmfAttributeTypeAndValue getInstance(Object o)
    {
        if (o instanceof CrmfAttributeTypeAndValue)
        {
            return (CrmfAttributeTypeAndValue)o;
        }

        if (o != null)
        {
            return new CrmfAttributeTypeAndValue(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CrmfAttributeTypeAndValue(
        String oid,
        ASN1Encodable value)
    {
        this(new ASN1ObjectIdentifier(oid), value);
    }

    public CrmfAttributeTypeAndValue(
        ASN1ObjectIdentifier type,
        ASN1Encodable value)
    {
        this.type = type;
        this.value = value;
    }

    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    /**
     * <pre>
     * CrmfAttributeTypeAndValue ::= SEQUENCE {
     *           type         OBJECT IDENTIFIER,
     *           value        ANY DEFINED BY type }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(type);
        v.add(value);

        return new DERSequence(v);
    }
}

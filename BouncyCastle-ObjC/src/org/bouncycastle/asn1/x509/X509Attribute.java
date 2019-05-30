package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;

public class X509Attribute
    extends ASN1Object
{
    private ASN1ObjectIdentifier attrType;
    private ASN1Set             attrValues;

    /**
     * return an CmsAttribute object from the given object.
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static X509Attribute getInstance(
        Object o)
    {
        if (o instanceof X509Attribute)
        {
            return (X509Attribute)o;
        }
        
        if (o != null)
        {
            return new X509Attribute(ASN1Sequence.getInstance(o));
        }

        return null;
    }
    
    private X509Attribute(
        ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        attrType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        attrValues = ASN1Set.getInstance(seq.getObjectAt(1));
    }

    public X509Attribute(
        ASN1ObjectIdentifier attrType,
        ASN1Set             attrValues)
    {
        this.attrType = attrType;
        this.attrValues = attrValues;
    }

    public ASN1ObjectIdentifier getAttrType()
    {
        return new ASN1ObjectIdentifier(attrType.getId());
    }

    public ASN1Encodable[] getAttributeValues()
    {
        return attrValues.toArray();
    }

    public ASN1Set getAttrValues()
    {
        return attrValues;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * CmsAttribute ::= SEQUENCE {
     *     attrType OBJECT IDENTIFIER,
     *     attrValues SET OF AttributeValue
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attrType);
        v.add(attrValues);

        return new DERSequence(v);
    }
}

package org.bouncycastle.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;

/**
 * Class for carrying the values in an X.509 CmsAttribute.
 * @deprecated see X509CertificateHolder class in the PKIX package.
 */
public class X509X509Attribute
    extends ASN1Object
{
    org.bouncycastle.asn1.x509.X509Attribute attr;
    
    /**
     * @param at an object representing an attribute.
     */
    X509X509Attribute(
        ASN1Encodable   at)
    {
        this.attr = org.bouncycastle.asn1.x509.X509Attribute.getInstance(at);
    }

    /**
     * Create an X.509 CmsAttribute with the type given by the passed in oid and
     * the value represented by an ASN.1 Set containing value.
     * 
     * @param oid type of the attribute
     * @param value value object to go into the atribute's value set.
     */
    public X509X509Attribute(
        String          oid,
        ASN1Encodable   value)
    {
        this.attr = new org.bouncycastle.asn1.x509.X509Attribute(new ASN1ObjectIdentifier(oid), new DERSet(value));
    }
    
    /**
     * Create an X.59 CmsAttribute with the type given by the passed in oid and the
     * value represented by an ASN.1 Set containing the objects in value.
     * 
     * @param oid type of the attribute
     * @param value vector of values to go in the attribute's value set.
     */
    public X509X509Attribute(
        String              oid,
        ASN1EncodableVector value)
    {
        this.attr = new org.bouncycastle.asn1.x509.X509Attribute(new ASN1ObjectIdentifier(oid), new DERSet(value));
    }
    
    public String getOID()
    {
        return attr.getAttrType().getId();
    }
    
    public ASN1Encodable[] getValues()
    {
        ASN1Set         s = attr.getAttrValues();
        ASN1Encodable[] values = new ASN1Encodable[s.size()];
        
        for (int i = 0; i != s.size(); i++)
        {
            values[i] = (ASN1Encodable)s.getObjectAt(i);
        }
        
        return values;
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        return attr.toASN1Primitive();
    }
}

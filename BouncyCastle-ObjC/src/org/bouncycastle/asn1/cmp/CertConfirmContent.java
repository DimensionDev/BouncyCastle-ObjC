package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

public class CertConfirmContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private CertConfirmContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static CertConfirmContent getInstance(Object o)
    {
        if (o instanceof CertConfirmContent)
        {
            return (CertConfirmContent)o;
        }

        if (o != null)
        {
            return new CertConfirmContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Asn1CmpCertStatus[] toCertStatusArray()
    {
        Asn1CmpCertStatus[] result = new Asn1CmpCertStatus[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = Asn1CmpCertStatus.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * CertConfirmContent ::= SEQUENCE OF Asn1CmpCertStatus
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}

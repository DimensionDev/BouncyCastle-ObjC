package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * <a href="http://tools.ietf.org/html/rfc5084">RFC 5084</a>: CmsCCMParameters object.
 * <p>
 * <pre>
 CmsCCMParameters ::= SEQUENCE {
   aes-nonce        OCTET STRING, -- recommended size is 12 octets
   aes-ICVlen       AES-CCM-ICVlen DEFAULT 12 }
 * </pre>
 */
public class CmsCCMParameters
    extends ASN1Object
{
    private byte[] nonce;
    private int icvLen;

    /**
     * Return an CmsCCMParameters object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link CmsCCMParameters} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with CmsCCMParameters structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static CmsCCMParameters getInstance(
        Object  obj)
    {
        if (obj instanceof CmsCCMParameters)
        {
            return (CmsCCMParameters)obj;
        }
        else if (obj != null)
        {
            return new CmsCCMParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private CmsCCMParameters(
        ASN1Sequence seq)
    {
        this.nonce = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();

        if (seq.size() == 2)
        {
            this.icvLen = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().intValue();
        }
        else
        {
            this.icvLen = 12;
        }
    }

    public CmsCCMParameters(
        byte[] nonce,
        int icvLen)
    {
        this.nonce = Arrays.clone(nonce);
        this.icvLen = icvLen;
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    public int getIcvLen()
    {
        return icvLen;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(new DEROctetString(nonce));

        if (icvLen != 12)
        {
            v.add(new ASN1Integer(icvLen));
        }

        return new DERSequence(v);
    }
}

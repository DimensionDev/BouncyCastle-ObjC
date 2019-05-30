package org.bouncycastle.asn1.cmp;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

public class Asn1CmpCertStatus
    extends ASN1Object
{
    private ASN1OctetString certHash;
    private ASN1Integer certReqId;
    private PKIStatusInfo statusInfo;

    private Asn1CmpCertStatus(ASN1Sequence seq)
    {
        certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        certReqId = ASN1Integer.getInstance(seq.getObjectAt(1));

        if (seq.size() > 2)
        {
            statusInfo = PKIStatusInfo.getInstance(seq.getObjectAt(2));
        }
    }

    public Asn1CmpCertStatus(byte[] certHash, BigInteger certReqId)
    {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new ASN1Integer(certReqId);
    }

    public Asn1CmpCertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo)
    {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new ASN1Integer(certReqId);
        this.statusInfo = statusInfo;
    }

    public static Asn1CmpCertStatus getInstance(Object o)
    {
        if (o instanceof Asn1CmpCertStatus)
        {
            return (Asn1CmpCertStatus)o;
        }

        if (o != null)
        {
            return new Asn1CmpCertStatus(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1OctetString getCertHash()
    {
        return certHash;
    }

    public ASN1Integer getCertReqId()
    {
        return certReqId;
    }

    public PKIStatusInfo getStatusInfo()
    {
        return statusInfo;
    }

    /**
     * <pre>
     * Asn1CmpCertStatus ::= SEQUENCE {
     *                   certHash    OCTET STRING,
     *                   -- the hash of the certificate, using the same hash algorithm
     *                   -- as is used to create and verify the certificate signature
     *                   certReqId   INTEGER,
     *                   -- to match this confirmation with the corresponding req/rep
     *                   statusInfo  PKIStatusInfo OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certHash);
        v.add(certReqId);

        if (statusInfo != null)
        {
            v.add(statusInfo);
        }

        return new DERSequence(v);
    }
}

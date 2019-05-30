package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> Asn1CmsContentInfo, and
 * <a href="http://tools.ietf.org/html/rfc5652#section-5.2">RFC 5652</a> EncapsulatedContentInfo objects.
 *
 * <pre>
 * Asn1CmsContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * EncapsulatedContentInfo ::= SEQUENCE {
 *     eContentType ContentType,
 *     eContent [0] EXPLICIT OCTET STRING OPTIONAL
 * }
 * </pre>
 */
public class Asn1CmsContentInfo
    extends ASN1Object
    implements CMSObjectIdentifiers
{
    private ASN1ObjectIdentifier contentType;
    private ASN1Encodable        content;

    /**
     * Return an Asn1CmsContentInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link Asn1CmsContentInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with Asn1CmsContentInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static Asn1CmsContentInfo getInstance(
        Object  obj)
    {
        if (obj instanceof Asn1CmsContentInfo)
        {
            return (Asn1CmsContentInfo)obj;
        }
        else if (obj != null)
        {
            return new Asn1CmsContentInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static Asn1CmsContentInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * @deprecated use getInstance()
     */
    public Asn1CmsContentInfo(
        ASN1Sequence  seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);

        if (seq.size() > 1)
        {
            ASN1TaggedObject tagged = (ASN1TaggedObject)seq.getObjectAt(1);
            if (!tagged.isExplicit() || tagged.getTagNo() != 0)
            {
                throw new IllegalArgumentException("Bad tag for 'content'");
            }

            content = tagged.getObject();
        }
    }

    public Asn1CmsContentInfo(
        ASN1ObjectIdentifier contentType,
        ASN1Encodable        content)
    {
        this.contentType = contentType;
        this.content = content;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(contentType);

        if (content != null)
        {
            v.add(new BERTaggedObject(0, content));
        }

        return new BERSequence(v);
    }
}

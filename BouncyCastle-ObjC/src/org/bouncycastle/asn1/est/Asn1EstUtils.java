package org.bouncycastle.asn1.est;

class Asn1EstUtils
{
    static AttrOrOID[] clone(AttrOrOID[] ids)
    {
        AttrOrOID[] tmp = new AttrOrOID[ids.length];

        System.arraycopy(ids, 0, tmp, 0, ids.length);

        return tmp;
    }
}

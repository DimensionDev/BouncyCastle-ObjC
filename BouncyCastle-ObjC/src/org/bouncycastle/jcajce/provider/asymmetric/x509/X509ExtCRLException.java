package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.CRLException;

class X509ExtCRLException
    extends CRLException
{
    Throwable cause;

    X509ExtCRLException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}

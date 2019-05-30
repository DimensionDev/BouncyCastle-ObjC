package org.bouncycastle.jce.exception;

import java.security.cert.CertificateEncodingException;

public class JceExtCertificateEncodingException
    extends CertificateEncodingException
    implements ExtException
{
    private Throwable cause;

    public JceExtCertificateEncodingException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}

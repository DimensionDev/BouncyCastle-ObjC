package org.bouncycastle.x509.util;

public class X509StreamParsingException
    extends Exception
{
    Throwable _e;

    public X509StreamParsingException(String message, Throwable e)
    {
        super(message);
        _e = e;
    }

    public Throwable getCause()
    {
        return _e;
    }
}

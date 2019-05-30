package org.bouncycastle.x509.util;

import java.util.Collection;

public interface X509UtilX509StreamParser
{
    Object read() throws X509StreamParsingException;

    Collection readAll() throws X509StreamParsingException;
}

package org.bouncycastle.jcajce.provider.config;

import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;

/**
 * @deprecated use org.bouncycastle.jcajce.JcajceConfigPKCS12StoreParameter
 */
public class JcajceConfigPKCS12StoreParameter
    extends org.bouncycastle.jcajce.PKCS12StoreParameter
{
    public JcajceConfigPKCS12StoreParameter(OutputStream out, char[] password)
    {
        super(out, password, false);
    }

    public JcajceConfigPKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter)
    {
        super(out, protectionParameter, false);
    }

    public JcajceConfigPKCS12StoreParameter(OutputStream out, char[] password, boolean forDEREncoding)
    {
        super(out, new KeyStore.PasswordProtection(password), forDEREncoding);
    }

    public JcajceConfigPKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter, boolean forDEREncoding)
    {
        super(out, protectionParameter, forDEREncoding);
    }
}

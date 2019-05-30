package org.bouncycastle.jce.spec;

import org.bouncycastle.jcajce.spec.JcajceRepeatedSecretKeySpec;

/**
 * A simple object to indicate that a symmetric cipher should reuse the
 * last key provided.
 * @deprecated use super class org.bouncycastle.jcajce.spec.JcajceRepeatedSecretKeySpec
 */
public class RepeatedSecretKeySpec
    extends JcajceRepeatedSecretKeySpec
{
    private String algorithm;

    public RepeatedSecretKeySpec(String algorithm)
    {
        super(algorithm);
    }
}

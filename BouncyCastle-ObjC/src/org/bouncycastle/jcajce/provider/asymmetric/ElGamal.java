package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.JcajceElgamalKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class ElGamal
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".elgamal.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }
        
        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameterGenerator.ELGAMAL", PREFIX + "ElgamalAlgorithmParameterGeneratorSpi");
            provider.addAlgorithm("AlgorithmParameterGenerator.ElGamal", PREFIX + "ElgamalAlgorithmParameterGeneratorSpi");
            provider.addAlgorithm("AlgorithmParameters.ELGAMAL", PREFIX + "ElgamalAlgorithmParametersSpi");
            provider.addAlgorithm("AlgorithmParameters.ElGamal", PREFIX + "ElgamalAlgorithmParametersSpi");

            provider.addAlgorithm("Cipher.ELGAMAL", PREFIX + "CipherSpi$NoPadding");
            provider.addAlgorithm("Cipher.ElGamal", PREFIX + "CipherSpi$NoPadding");
            provider.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/ECB/PKCS1PADDING", "ELGAMAL/PKCS1");
            provider.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/NONE/PKCS1PADDING", "ELGAMAL/PKCS1");
            provider.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/NONE/NOPADDING", "ELGAMAL");

            provider.addAlgorithm("Cipher.ELGAMAL/PKCS1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
            provider.addAlgorithm("KeyFactory.ELGAMAL", PREFIX + "JcajceElgamalKeyFactorySpi");
            provider.addAlgorithm("KeyFactory.ElGamal", PREFIX + "JcajceElgamalKeyFactorySpi");

            provider.addAlgorithm("KeyPairGenerator.ELGAMAL", PREFIX + "JcajceElgamalKeyPairGeneratorSpi");
            provider.addAlgorithm("KeyPairGenerator.ElGamal", PREFIX + "JcajceElgamalKeyPairGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new JcajceElgamalKeyFactorySpi();

            registerOid(provider, OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL", keyFact);
            registerOidAlgorithmParameterGenerator(provider, OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL");
        }
    }
}

package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.dstu.JcajceDstuKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class DSTU4145 
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dstu.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }
        
        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.DSTU4145", PREFIX + "JcajceDstuKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.DSTU-4145-2002", "DSTU4145");
            provider.addAlgorithm("Alg.Alias.KeyFactory.DSTU4145-3410", "DSTU4145");

            registerOid(provider, UAObjectIdentifiers.dstu4145le, "DSTU4145", new JcajceDstuKeyFactorySpi());
            registerOidAlgorithmParameters(provider, UAObjectIdentifiers.dstu4145le, "DSTU4145");
            registerOid(provider, UAObjectIdentifiers.dstu4145be, "DSTU4145", new JcajceDstuKeyFactorySpi());
            registerOidAlgorithmParameters(provider, UAObjectIdentifiers.dstu4145be, "DSTU4145");

            provider.addAlgorithm("KeyPairGenerator.DSTU4145", PREFIX + "JcajceDstuKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.DSTU-4145", "DSTU4145");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.DSTU-4145-2002", "DSTU4145");

            provider.addAlgorithm("Signature.DSTU4145", PREFIX + "JcajceDstuSignatureSpi");
            provider.addAlgorithm("Alg.Alias.Signature.DSTU-4145", "DSTU4145");
            provider.addAlgorithm("Alg.Alias.Signature.DSTU-4145-2002", "DSTU4145");

            addSignatureAlgorithm(provider, "GOST3411", "DSTU4145LE", PREFIX + "SignatureSpiLe", UAObjectIdentifiers.dstu4145le);
            addSignatureAlgorithm(provider, "GOST3411", "DSTU4145", PREFIX + "JcajceDstuSignatureSpi", UAObjectIdentifiers.dstu4145be);
        }
    }
}

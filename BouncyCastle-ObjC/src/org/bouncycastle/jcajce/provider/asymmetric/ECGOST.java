package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.JcajceEcgostKeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.JcajceEcgost12KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class ECGOST
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".ecgost.";
    private static final String PREFIX_GOST_2012 = "org.bouncycastle.jcajce.provider.asymmetric" + ".ecgost12.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }
        
        public void configure(ConfigurableProvider provider)
        {

            // ========= GOST34.10 2001
            provider.addAlgorithm("KeyFactory.ECGOST3410", PREFIX + "JcajceEcgostKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.GOST-3410-2001", "ECGOST3410");
            provider.addAlgorithm("Alg.Alias.KeyFactory.ECGOST-3410", "ECGOST3410");

            registerOid(provider, CryptoProObjectIdentifiers.gostR3410_2001,
                    "ECGOST3410", new JcajceEcgostKeyFactorySpi());
            registerOid(provider, CryptoProObjectIdentifiers.gostR3410_2001DH,
                    "ECGOST3410", new JcajceEcgostKeyFactorySpi());
            registerOidAlgorithmParameters(provider, CryptoProObjectIdentifiers.gostR3410_2001,
                    "ECGOST3410");

            provider.addAlgorithm("KeyPairGenerator.ECGOST3410", PREFIX + "JcajceEcgostKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.ECGOST-3410", "ECGOST3410");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.GOST-3410-2001", "ECGOST3410");

            provider.addAlgorithm("Signature.ECGOST3410", PREFIX + "JcajceEcgostSignatureSpi");
            provider.addAlgorithm("Alg.Alias.Signature.ECGOST-3410", "ECGOST3410");
            provider.addAlgorithm("Alg.Alias.Signature.GOST-3410-2001", "ECGOST3410");

            provider.addAlgorithm("KeyAgreement.ECGOST3410", PREFIX + "JcajceEcgostKeyAgreementSpi$ECVKO");
            provider.addAlgorithm("Alg.Alias.KeyAgreement." + CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410");
            provider.addAlgorithm("Alg.Alias.KeyAgreement.GOST-3410-2001", "ECGOST3410");

            provider.addAlgorithm("Alg.Alias.KeyAgreement." + CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH, "ECGOST3410");
            
            provider.addAlgorithm("AlgorithmParameters.ECGOST3410", PREFIX + "AlgorithmParametersSpi");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.GOST-3410-2001", "ECGOST3410");

            addSignatureAlgorithm(provider, "GOST3411",
                    "ECGOST3410", PREFIX + "JcajceEcgostSignatureSpi",
                    CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);

            // ========= GOST34.10 2012 256|512

            provider.addAlgorithm("KeyFactory.ECGOST3410-2012", PREFIX_GOST_2012 + "JcajceEcgostKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.GOST-3410-2012", "ECGOST3410-2012");
            provider.addAlgorithm("Alg.Alias.KeyFactory.ECGOST-3410-2012", "ECGOST3410-2012");

            registerOid(provider, RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                    "ECGOST3410-2012",
                    new JcajceEcgost12KeyFactorySpi());
            registerOid(provider, RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256,
                             "ECGOST3410-2012",
                             new JcajceEcgost12KeyFactorySpi());
            registerOidAlgorithmParameters(provider,
                    RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, "ECGOST3410-2012");

            registerOid(provider, RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                    "ECGOST3410-2012",
                    new JcajceEcgost12KeyFactorySpi());
            registerOid(provider, RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512,
                    "ECGOST3410-2012",
                    new JcajceEcgost12KeyFactorySpi());
            registerOidAlgorithmParameters(provider,
                    RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, "ECGOST3410-2012");

            provider.addAlgorithm("KeyPairGenerator.ECGOST3410-2012",
                    PREFIX_GOST_2012 + "JcajceEcgostKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.ECGOST3410-2012",
                    "ECGOST3410-2012");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.GOST-3410-2012",
                    "ECGOST3410-2012");

            // 256 signature

            provider.addAlgorithm("Signature.ECGOST3410-2012-256",
                    PREFIX_GOST_2012 + "ECGOST2012SignatureSpi256");
            provider.addAlgorithm("Alg.Alias.Signature.ECGOST3410-2012-256",
                    "ECGOST3410-2012-256");
            provider.addAlgorithm("Alg.Alias.Signature.GOST-3410-2012-256",
                    "ECGOST3410-2012-256");


            addSignatureAlgorithm(provider, "GOST3411-2012-256", "ECGOST3410-2012-256",
                    PREFIX_GOST_2012 + "ECGOST2012SignatureSpi256",
                    RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);

            // 512 signature


            provider.addAlgorithm("Signature.ECGOST3410-2012-512",
                    PREFIX_GOST_2012 + "ECGOST2012SignatureSpi512");
            provider.addAlgorithm("Alg.Alias.Signature.ECGOST3410-2012-512",
                    "ECGOST3410-2012-512");
            provider.addAlgorithm("Alg.Alias.Signature.GOST-3410-2012-512",
                    "ECGOST3410-2012-512");

            addSignatureAlgorithm(provider, "GOST3411-2012-512", "ECGOST3410-2012-512",
                    PREFIX_GOST_2012 + "ECGOST2012SignatureSpi512",
                    RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

            provider.addAlgorithm("KeyAgreement.ECGOST3410-2012-256", PREFIX_GOST_2012 + "JcajceEcgostKeyAgreementSpi$ECVKO256");
            provider.addAlgorithm("KeyAgreement.ECGOST3410-2012-512", PREFIX_GOST_2012 + "JcajceEcgostKeyAgreementSpi$ECVKO512");

            provider.addAlgorithm("Alg.Alias.KeyAgreement." + RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256, "ECGOST3410-2012-256");
            provider.addAlgorithm("Alg.Alias.KeyAgreement." + RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512, "ECGOST3410-2012-512");
            provider.addAlgorithm("Alg.Alias.KeyAgreement." + RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, "ECGOST3410-2012-256");
            provider.addAlgorithm("Alg.Alias.KeyAgreement." + RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, "ECGOST3410-2012-512");
        }
    }
}

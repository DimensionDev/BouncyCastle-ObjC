package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.JcajceDsaKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class JcajceDSA
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dsa.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }
        
        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.DSA", PREFIX + "DsaAlgorithmParametersSpi");

            provider.addAlgorithm("AlgorithmParameterGenerator.DSA", PREFIX + "DsaAlgorithmParameterGeneratorSpi");

            provider.addAlgorithm("KeyPairGenerator.DSA", PREFIX + "JcajceDsaKeyPairGeneratorSpi");
            provider.addAlgorithm("KeyFactory.DSA", PREFIX + "JcajceDsaKeyFactorySpi");

            provider.addAlgorithm("Signature.DSA", PREFIX + "JcajceDSASigner$stdDSA");
            provider.addAlgorithm("Signature.NONEWITHDSA", PREFIX + "JcajceDSASigner$noneDSA");

            provider.addAlgorithm("Alg.Alias.Signature.RAWDSA", "NONEWITHDSA");

            provider.addAlgorithm("Signature.DETDSA", PREFIX + "JcajceDSASigner$detDSA");
            provider.addAlgorithm("Signature.SHA1WITHDETDSA", PREFIX + "JcajceDSASigner$detDSA");
            provider.addAlgorithm("Signature.SHA224WITHDETDSA", PREFIX + "JcajceDSASigner$detDSA224");
            provider.addAlgorithm("Signature.SHA256WITHDETDSA", PREFIX + "JcajceDSASigner$detDSA256");
            provider.addAlgorithm("Signature.SHA384WITHDETDSA", PREFIX + "JcajceDSASigner$detDSA384");
            provider.addAlgorithm("Signature.SHA512WITHDETDSA", PREFIX + "JcajceDSASigner$detDSA512");

            provider.addAlgorithm("Signature.DDSA", PREFIX + "JcajceDSASigner$detDSA");
            provider.addAlgorithm("Signature.SHA1WITHDDSA", PREFIX + "JcajceDSASigner$detDSA");
            provider.addAlgorithm("Signature.SHA224WITHDDSA", PREFIX + "JcajceDSASigner$detDSA224");
            provider.addAlgorithm("Signature.SHA256WITHDDSA", PREFIX + "JcajceDSASigner$detDSA256");
            provider.addAlgorithm("Signature.SHA384WITHDDSA", PREFIX + "JcajceDSASigner$detDSA384");
            provider.addAlgorithm("Signature.SHA512WITHDDSA", PREFIX + "JcajceDSASigner$detDSA512");
            provider.addAlgorithm("Signature.SHA3-224WITHDDSA", PREFIX + "JcajceDSASigner$detDSASha3_224");
            provider.addAlgorithm("Signature.SHA3-256WITHDDSA", PREFIX + "JcajceDSASigner$detDSASha3_256");
            provider.addAlgorithm("Signature.SHA3-384WITHDDSA", PREFIX + "JcajceDSASigner$detDSASha3_384");
            provider.addAlgorithm("Signature.SHA3-512WITHDDSA", PREFIX + "JcajceDSASigner$detDSASha3_512");

            addSignatureAlgorithm(provider, "SHA224", "DSA", PREFIX + "JcajceDSASigner$dsa224", NISTObjectIdentifiers.dsa_with_sha224);
            addSignatureAlgorithm(provider, "SHA256", "DSA", PREFIX + "JcajceDSASigner$dsa256", NISTObjectIdentifiers.dsa_with_sha256);
            addSignatureAlgorithm(provider, "SHA384", "DSA", PREFIX + "JcajceDSASigner$dsa384", NISTObjectIdentifiers.dsa_with_sha384);
            addSignatureAlgorithm(provider, "SHA512", "DSA", PREFIX + "JcajceDSASigner$dsa512", NISTObjectIdentifiers.dsa_with_sha512);

            addSignatureAlgorithm(provider, "SHA3-224", "DSA", PREFIX + "JcajceDSASigner$dsaSha3_224", NISTObjectIdentifiers.id_dsa_with_sha3_224);
            addSignatureAlgorithm(provider, "SHA3-256", "DSA", PREFIX + "JcajceDSASigner$dsaSha3_256", NISTObjectIdentifiers.id_dsa_with_sha3_256);
            addSignatureAlgorithm(provider, "SHA3-384", "DSA", PREFIX + "JcajceDSASigner$dsaSha3_384", NISTObjectIdentifiers.id_dsa_with_sha3_384);
            addSignatureAlgorithm(provider, "SHA3-512", "DSA", PREFIX + "JcajceDSASigner$dsaSha3_512", NISTObjectIdentifiers.id_dsa_with_sha3_512);

            provider.addAlgorithm("Alg.Alias.Signature.SHA/DSA", "JcajceDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1withDSA", "JcajceDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WITHDSA", "JcajceDSA");
            provider.addAlgorithm("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.1", "JcajceDSA");
            provider.addAlgorithm("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.3", "JcajceDSA");
            provider.addAlgorithm("Alg.Alias.Signature.DSAwithSHA1", "JcajceDSA");
            provider.addAlgorithm("Alg.Alias.Signature.DSAWITHSHA1", "JcajceDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WithDSA", "JcajceDSA");
            provider.addAlgorithm("Alg.Alias.Signature.DSAWithSHA1", "JcajceDSA");

            AsymmetricKeyInfoConverter keyFact = new JcajceDsaKeyFactorySpi();

            for (int i = 0; i != DSAUtil.dsaOids.length; i++)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + DSAUtil.dsaOids[i], "JcajceDSA");

                registerOid(provider, DSAUtil.dsaOids[i], "JcajceDSA", keyFact);
                registerOidAlgorithmParameterGenerator(provider, DSAUtil.dsaOids[i], "JcajceDSA");
            }
        }
    }
}

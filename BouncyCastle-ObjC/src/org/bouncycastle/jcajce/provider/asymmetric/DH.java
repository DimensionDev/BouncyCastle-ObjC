package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.dh.JcajceDhKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class DH
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dh.";

    private static final Map<String, String> generalDhAttributes = new HashMap<String, String>();

    static
    {
        generalDhAttributes.put("SupportedKeyClasses", "javax.crypto.interfaces.DHPublicKey|javax.crypto.interfaces.DHPrivateKey");
        generalDhAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyPairGenerator.DH", PREFIX + "JcajceDhKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.DIFFIEHELLMAN", "DH");

            provider.addAttributes("KeyAgreement.DH", generalDhAttributes);
            provider.addAlgorithm("KeyAgreement.DH", PREFIX + "JcajceDhKeyAgreementSpi");
            provider.addAlgorithm("Alg.Alias.KeyAgreement.DIFFIEHELLMAN", "DH");
            provider.addAlgorithm("KeyAgreement", PKCSObjectIdentifiers.id_alg_ESDH, PREFIX + "JcajceDhKeyAgreementSpi$DHwithRFC2631KDF");
            provider.addAlgorithm("KeyAgreement", PKCSObjectIdentifiers.id_alg_SSDH, PREFIX + "JcajceDhKeyAgreementSpi$DHwithRFC2631KDF");

            provider.addAlgorithm("KeyFactory.DH", PREFIX + "JcajceDhKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("AlgorithmParameters.DH", PREFIX + "AlgorithmParametersSpi");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("AlgorithmParameterGenerator.DH", PREFIX + "DhAlgorithmParameterGeneratorSpi");

            provider.addAlgorithm("Cipher.IES", PREFIX + "JcajceDhIESCipher$IES");
            provider.addAlgorithm("Cipher.IESwithAES-CBC", PREFIX + "JcajceDhIESCipher$IESwithAESCBC");
            provider.addAlgorithm("Cipher.IESWITHAES-CBC", PREFIX + "JcajceDhIESCipher$IESwithAESCBC");
            provider.addAlgorithm("Cipher.IESWITHDESEDE-CBC", PREFIX + "JcajceDhIESCipher$IESwithDESedeCBC");

            provider.addAlgorithm("Cipher.DHIES", PREFIX + "JcajceDhIESCipher$IES");
            provider.addAlgorithm("Cipher.DHIESwithAES-CBC", PREFIX + "JcajceDhIESCipher$IESwithAESCBC");
            provider.addAlgorithm("Cipher.DHIESWITHAES-CBC", PREFIX + "JcajceDhIESCipher$IESwithAESCBC");
            provider.addAlgorithm("Cipher.DHIESWITHDESEDE-CBC", PREFIX + "JcajceDhIESCipher$IESwithDESedeCBC");

            provider.addAlgorithm("KeyAgreement.DHWITHSHA1KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.DHWITHSHA224KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.DHWITHSHA256KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.DHWITHSHA384KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.DHWITHSHA512KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement.DHUWITHSHA1KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.DHUWITHSHA224KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.DHUWITHSHA256KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.DHUWITHSHA384KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.DHUWITHSHA512KDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement.DHUWITHSHA1CKDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA1CKDF");
            provider.addAlgorithm("KeyAgreement.DHUWITHSHA224CKDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA224CKDF");
            provider.addAlgorithm("KeyAgreement.DHUWITHSHA256CKDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.DHUWITHSHA384CKDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.DHUWITHSHA512CKDF", PREFIX + "JcajceDhKeyAgreementSpi$DHUwithSHA512CKDF");

            provider.addAlgorithm("KeyAgreement.MQVWITHSHA1KDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.MQVWITHSHA224KDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.MQVWITHSHA256KDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.MQVWITHSHA384KDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.MQVWITHSHA512KDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement.MQVWITHSHA1CKDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA1CKDF");
            provider.addAlgorithm("KeyAgreement.MQVWITHSHA224CKDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA224CKDF");
            provider.addAlgorithm("KeyAgreement.MQVWITHSHA256CKDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.MQVWITHSHA384CKDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.MQVWITHSHA512CKDF", PREFIX + "JcajceDhKeyAgreementSpi$MQVwithSHA512CKDF");

            registerOid(provider, PKCSObjectIdentifiers.dhKeyAgreement, "DH", new JcajceDhKeyFactorySpi());
            registerOid(provider, X9ObjectIdentifiers.dhpublicnumber, "DH", new JcajceDhKeyFactorySpi());
        }
    }
}

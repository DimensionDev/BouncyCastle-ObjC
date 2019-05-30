package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.JcajceEcKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Properties;

public class EC
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".ec.";

    private static final Map<String, String> generalEcAttributes = new HashMap<String, String>();

    static
    {
        generalEcAttributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        generalEcAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.EC", PREFIX + "EcAlgorithmParametersSpi");

            provider.addAttributes("KeyAgreement.ECDH", generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECDH", PREFIX + "JcajceEcKeyAgreementSpi$DH");
            provider.addAttributes("KeyAgreement.ECDHC", generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECDHC", PREFIX + "JcajceEcKeyAgreementSpi$DHC");
            provider.addAttributes("KeyAgreement.ECCDH", generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECCDH", PREFIX + "JcajceEcKeyAgreementSpi$DHC");

            provider.addAttributes("KeyAgreement.ECCDHU", generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECCDHU", PREFIX + "JcajceEcKeyAgreementSpi$DHUC");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA1KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA1KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA1KDF", PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA1KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA224KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA224KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA224KDF", PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA224KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA256KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA256KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA256KDF", PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA256KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA384KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA384KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA384KDF", PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA384KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA512KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA512KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA512KDF", PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA512KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA1KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA1KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA224KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA224KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA256KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA256KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA384KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA384KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA512KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$CDHwithSHA512KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA1CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA1CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA256CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA384CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA512CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHwithSHA512CKDF");

            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA1CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA1CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA224CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA224CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA256CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA384CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA512CKDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA512CKDF");

            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA1KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA224KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA256KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA384KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA512KDF", PREFIX + "JcajceEcKeyAgreementSpi$DHUwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA1KDF", PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA224KDF", PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA256KDF", PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA384KDF", PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA512KDF", PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA1, PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA224, PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA256, PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA384, PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA512, PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_RIPEMD160, PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithRIPEMD160KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHRIPEMD160KDF", PREFIX + "JcajceEcKeyAgreementSpi$ECKAEGwithRIPEMD160KDF");

            registerOid(provider, X9ObjectIdentifiers.id_ecPublicKey, "EC", new JcajceEcKeyFactorySpi.EC());

            registerOid(provider, X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());
            registerOid(provider, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "ECMQV", new JcajceEcKeyFactorySpi.ECMQV());

            registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());
            registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());

            registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());
            registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());

            registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());
            registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());

            registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());
            registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());

            registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.id_ecPublicKey, "EC");

            registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, "EC");

            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, "EC");

            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, "EC");

            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, "EC");

            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, "EC");

            if (!Properties.isOverrideSet("org.bouncycastle.ec.disable_mqv"))
            {
                provider.addAlgorithm("KeyAgreement.ECMQV", PREFIX + "JcajceEcKeyAgreementSpi$MQV");

                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA1CKDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA1CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA224CKDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA224CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA256CKDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA256CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA384CKDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA384CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA512CKDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA512CKDF");

                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA1KDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA1KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA224KDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA224KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA256KDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA256KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA384KDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA384KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA512KDF", PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA512KDF");

                provider.addAlgorithm("KeyAgreement." + X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA1KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA224KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA256KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA384KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, PREFIX + "JcajceEcKeyAgreementSpi$MQVwithSHA512KDFAndSharedInfo");

                registerOid(provider, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC", new JcajceEcKeyFactorySpi.EC());
                registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "EC");

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, "ECMQV", new JcajceEcKeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, "EC");

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, "ECMQV", new JcajceEcKeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, "EC");

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, "ECMQV", new JcajceEcKeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, "EC");

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "ECMQV", new JcajceEcKeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "EC");

                provider.addAlgorithm("KeyFactory.ECMQV", PREFIX + "JcajceEcKeyFactorySpi$ECMQV");
                provider.addAlgorithm("KeyPairGenerator.ECMQV", PREFIX + "JcajceEcKeyPairGeneratorSpi$ECMQV");
            }

            provider.addAlgorithm("KeyFactory.EC", PREFIX + "JcajceEcKeyFactorySpi$EC");
            provider.addAlgorithm("KeyFactory.ECDSA", PREFIX + "JcajceEcKeyFactorySpi$ECDSA");
            provider.addAlgorithm("KeyFactory.ECDH", PREFIX + "JcajceEcKeyFactorySpi$ECDH");
            provider.addAlgorithm("KeyFactory.ECDHC", PREFIX + "JcajceEcKeyFactorySpi$ECDHC");

            provider.addAlgorithm("KeyPairGenerator.EC", PREFIX + "JcajceEcKeyPairGeneratorSpi$EC");
            provider.addAlgorithm("KeyPairGenerator.ECDSA", PREFIX + "JcajceEcKeyPairGeneratorSpi$ECDSA");
            provider.addAlgorithm("KeyPairGenerator.ECDH", PREFIX + "JcajceEcKeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("KeyPairGenerator.ECDHWITHSHA1KDF", PREFIX + "JcajceEcKeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("KeyPairGenerator.ECDHC", PREFIX + "JcajceEcKeyPairGeneratorSpi$ECDHC");
            provider.addAlgorithm("KeyPairGenerator.ECIES", PREFIX + "JcajceEcKeyPairGeneratorSpi$ECDH");

            provider.addAlgorithm("Cipher.ECIES", PREFIX + "JcajceDhIESCipher$ECIES");

            provider.addAlgorithm("Cipher.ECIESwithAES-CBC", PREFIX + "JcajceDhIESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESWITHAES-CBC", PREFIX + "JcajceDhIESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESwithDESEDE-CBC", PREFIX + "JcajceDhIESCipher$ECIESwithDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESWITHDESEDE-CBC", PREFIX + "JcajceDhIESCipher$ECIESwithDESedeCBC");

            provider.addAlgorithm("Signature.ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSA");
            provider.addAlgorithm("Signature.NONEwithECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSAnone");

            provider.addAlgorithm("Alg.Alias.Signature.SHA1withECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAwithSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WITHECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAWITHSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WithECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAWithSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.1.2.840.10045.4.1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature." + TeleTrusTObjectIdentifiers.ecSignWithSha1, "ECDSA");

            provider.addAlgorithm("Signature.ECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSA");
            provider.addAlgorithm("Signature.SHA1WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSA");
            provider.addAlgorithm("Signature.SHA224WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSA224");
            provider.addAlgorithm("Signature.SHA256WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSA256");
            provider.addAlgorithm("Signature.SHA384WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSA384");
            provider.addAlgorithm("Signature.SHA512WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSA512");
            provider.addAlgorithm("Signature.SHA3-224WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSASha3_224");
            provider.addAlgorithm("Signature.SHA3-256WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSASha3_256");
            provider.addAlgorithm("Signature.SHA3-384WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSASha3_384");
            provider.addAlgorithm("Signature.SHA3-512WITHECDDSA", PREFIX + "JcajceEcSignatureSpi$ecDetDSASha3_512");

            provider.addAlgorithm("Alg.Alias.Signature.DETECDSA", "ECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WITHDETECDSA", "SHA1WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA224WITHDETECDSA", "SHA224WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHDETECDSA", "SHA256WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA384WITHDETECDSA", "SHA384WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHDETECDSA", "SHA512WITHECDDSA");

            addSignatureAlgorithm(provider, "SHA224", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSA224", X9ObjectIdentifiers.ecdsa_with_SHA224);
            addSignatureAlgorithm(provider, "SHA256", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSA256", X9ObjectIdentifiers.ecdsa_with_SHA256);
            addSignatureAlgorithm(provider, "SHA384", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSA384", X9ObjectIdentifiers.ecdsa_with_SHA384);
            addSignatureAlgorithm(provider, "SHA512", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSA512", X9ObjectIdentifiers.ecdsa_with_SHA512);
            addSignatureAlgorithm(provider, "SHA3-224", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSASha3_224", NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
            addSignatureAlgorithm(provider, "SHA3-256", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSASha3_256", NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
            addSignatureAlgorithm(provider, "SHA3-384", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSASha3_384", NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
            addSignatureAlgorithm(provider, "SHA3-512", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSASha3_512", NISTObjectIdentifiers.id_ecdsa_with_sha3_512);

            addSignatureAlgorithm(provider, "RIPEMD160", "ECDSA", PREFIX + "JcajceEcSignatureSpi$ecDSARipeMD160",TeleTrusTObjectIdentifiers.ecSignWithRipemd160);

            provider.addAlgorithm("Signature.SHA1WITHECNR", PREFIX + "JcajceEcSignatureSpi$ecNR");
            provider.addAlgorithm("Signature.SHA224WITHECNR", PREFIX + "JcajceEcSignatureSpi$ecNR224");
            provider.addAlgorithm("Signature.SHA256WITHECNR", PREFIX + "JcajceEcSignatureSpi$ecNR256");
            provider.addAlgorithm("Signature.SHA384WITHECNR", PREFIX + "JcajceEcSignatureSpi$ecNR384");
            provider.addAlgorithm("Signature.SHA512WITHECNR", PREFIX + "JcajceEcSignatureSpi$ecNR512");

            addSignatureAlgorithm(provider, "SHA1", "CVC-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
            addSignatureAlgorithm(provider, "SHA224", "CVC-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA224", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
            addSignatureAlgorithm(provider, "SHA256", "CVC-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA256", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
            addSignatureAlgorithm(provider, "SHA384", "CVC-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA384", EACObjectIdentifiers.id_TA_ECDSA_SHA_384);
            addSignatureAlgorithm(provider, "SHA512", "CVC-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA512", EACObjectIdentifiers.id_TA_ECDSA_SHA_512);

            addSignatureAlgorithm(provider, "SHA1", "PLAIN-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA", BSIObjectIdentifiers.ecdsa_plain_SHA1);
            addSignatureAlgorithm(provider, "SHA224", "PLAIN-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA224", BSIObjectIdentifiers.ecdsa_plain_SHA224);
            addSignatureAlgorithm(provider, "SHA256", "PLAIN-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA256", BSIObjectIdentifiers.ecdsa_plain_SHA256);
            addSignatureAlgorithm(provider, "SHA384", "PLAIN-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA384", BSIObjectIdentifiers.ecdsa_plain_SHA384);
            addSignatureAlgorithm(provider, "SHA512", "PLAIN-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecCVCDSA512", BSIObjectIdentifiers.ecdsa_plain_SHA512);
            addSignatureAlgorithm(provider, "RIPEMD160", "PLAIN-ECDSA", PREFIX + "JcajceEcSignatureSpi$ecPlainDSARP160", BSIObjectIdentifiers.ecdsa_plain_RIPEMD160);
        }
    }
}

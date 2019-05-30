package org.bouncycastle.example;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.CryptoRSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.examples.RSAKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Date;

public class keypairExample {

    public static byte[][] generateKeyRing(String identity, char[] passphrase) throws GeneralSecurityException, PGPException, IOException
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(1024);

        KeyPair                    rsaKp = kpg.generateKeyPair();

        KeyPairGenerator dpg = KeyPairGenerator.getInstance("DSA");

        dpg.initialize(1024);

        KeyPair                    dsaKp = dpg.generateKeyPair();



        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date()); PGPKeyPair rsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsaKp, new Date()); PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
            .build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator( PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair, identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(
                dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA384), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc)
                .setProvider("BCFIPS").build(passphrase)); keyRingGen.addSubKey(rsaKeyPair);
        // create an encoding of the secret key ring
        ByteArrayOutputStream secretOut = new ByteArrayOutputStream(); keyRingGen.generateSecretKeyRing().encode(secretOut); secretOut.close();
// create an encoding of the public key ring
        ByteArrayOutputStream publicOut = new ByteArrayOutputStream(); keyRingGen.generatePublicKeyRing().encode(publicOut); publicOut.close();
        return new byte[][] { secretOut.toByteArray(), publicOut.toByteArray() };
    }

    public static void main(String[] args) {
        try {
            String ressult = generateKeyRing("username", "password".toCharArray()).toString();

        } catch (Exception e) {
            System.out.println("sss");
        }
    }

}

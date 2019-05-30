package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Arrays;

/**
 * PqcJcajceXMSS.
 */
public class XMSS
{

    /**
     * PqcJcajceXMSS parameters.
     */
    private final XMSSParameters params;
    /**
     * WOTS+ instance.
     */
    private WOTSPlus wotsPlus;
    /**
     * PRNG.
     */
    private SecureRandom prng;

    /**
     * PqcJcajceXMSS private key.
     */
    private XMSSPrivateKeyParameters privateKey;
    /**
     * PqcJcajceXMSS public key.
     */
    private XMSSPublicKeyParameters publicKey;

    /**
     * PqcJcajceXMSS constructor...
     *
     * @param params XMSSParameters.
     */
    public XMSS(XMSSParameters params, SecureRandom prng)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        this.params = params;
        wotsPlus = params.getWOTSPlus();
        this.prng = prng;
    }

//    public void generateKeys()
//    {
//        /* generate private key */
//        privateKey = generatePrivateKey(params, prng);
//        XMSSNode root = privateKey.getBDSState().initialize(privateKey, (OTSHashAddress)new OTSHashAddress.Builder().build());
//
//        privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
//            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
//            .withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue())
//            .withBDSState(privateKey.getBDSState()).build();
//        publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root.getValue())
//            .withPublicSeed(getPublicSeed()).build();
//
//    }
//
//    /**
//     * Generate an PqcJcajceXMSS private key.
//     *
//     * @return PqcJcajceXMSS private key.
//     */
//    private XMSSPrivateKeyParameters generatePrivateKey(XMSSParameters params, SecureRandom prng)
//    {
//        int n = params.getDigestSize();
//        byte[] secretKeySeed = new byte[n];
//        prng.nextBytes(secretKeySeed);
//        byte[] secretKeyPRF = new byte[n];
//        prng.nextBytes(secretKeyPRF);
//        byte[] publicSeed = new byte[n];
//        prng.nextBytes(publicSeed);
//
//        PqcJcajceXMSS xmss = new PqcJcajceXMSS(params, prng);
//
////        this.privateKey = xmss.privateKey;
////        this.publicKey = xmss.publicKey;
////        this.wotsPlus = xmss.wotsPlus;
////        this.khf = xmss.khf;
//
//        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withSecretKeySeed(secretKeySeed)
//            .withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
//            .withBDSState(new BDS(xmss)).build();
//
//        return privateKey;
//    }

    /**
     * Generate a new PqcJcajceXMSS private key / public key pair.
     */
    public void generateKeys()
    {
        XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();

        kpGen.init(new XMSSKeyGenerationParameters(getParams(), prng));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();
        publicKey = (XMSSPublicKeyParameters)kp.getPublic();

        wotsPlus.importKeys(new byte[params.getDigestSize()], this.privateKey.getPublicSeed());
    }

    void importState(XMSSPrivateKeyParameters privateKey, XMSSPublicKeyParameters publicKey)
    {
        if (!Arrays.areEqual(privateKey.getRoot(), publicKey.getRoot()))
        {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(privateKey.getPublicSeed(), publicKey.getPublicSeed()))
        {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
        /* import */
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        wotsPlus.importKeys(new byte[params.getDigestSize()], this.privateKey.getPublicSeed());
    }

    /**
     * Import PqcJcajceXMSS private key / public key pair.
     *
     * @param privateKey PqcJcajceXMSS private key.
     * @param publicKey  PqcJcajceXMSS public key.
     */
    public void importState(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("privateKey == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
        /* import keys */
        XMSSPrivateKeyParameters tmpPrivateKey = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(privateKey, this.getParams()).build();
        XMSSPublicKeyParameters tmpPublicKey = new XMSSPublicKeyParameters.Builder(params).withPublicKey(publicKey)
            .build();
        if (!Arrays.areEqual(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot()))
        {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed()))
        {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
		/* import */
        this.privateKey = tmpPrivateKey;
        this.publicKey = tmpPublicKey;
        wotsPlus.importKeys(new byte[params.getDigestSize()], this.privateKey.getPublicSeed());
    }

    /**
     * Sign message.
     *
     * @param message Message to sign.
     * @return PqcJcajceXMSS signature on digest of message.
     */
    public byte[] sign(byte[] message)
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privateKey);

        byte[] signature = signer.generateSignature(message);

        privateKey = (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();

        importState(privateKey, publicKey);

        return signature;
    }

    /**
     * Verify an PqcJcajceXMSS signature.
     *
     * @param message   Message.
     * @param signature PqcJcajceXMSS signature.
     * @param publicKey PqcJcajceXMSS public key.
     * @return true if signature is valid false else.
     * @throws ParseException
     */
    public boolean verifySignature(byte[] message, byte[] signature, byte[] publicKey)
        throws ParseException
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }

        XMSSSigner signer = new XMSSSigner();

        signer.init(false, new XMSSPublicKeyParameters.Builder(getParams()).withPublicKey(publicKey).build());

        return signer.verifySignature(message, signature);
    }

    /**
     * Export PqcJcajceXMSS private key.
     *
     * @return PqcJcajceXMSS private key.
     */
    public byte[] exportPrivateKey()
    {
        return privateKey.toByteArray();
    }

    /**
     * Export PqcJcajceXMSS public key.
     *
     * @return PqcJcajceXMSS public key.
     */
    public byte[] exportPublicKey()
    {
        return publicKey.toByteArray();
    }

    /**
     * Generate a WOTS+ signature on a message without the corresponding
     * authentication path
     *
     * @param messageDigest  Message digest of length n.
     * @param otsHashAddress OTS hash address.
     * @return PqcJcajceXMSS signature.
     */
    protected WOTSPlusSignature wotsSign(byte[] messageDigest, OTSHashAddress otsHashAddress)
    {
        if (messageDigest.length != params.getDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
		/* (re)initialize WOTS+ instance */
        wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(privateKey.getSecretKeySeed(), otsHashAddress), getPublicSeed());
		/* create WOTS+ signature */
        return wotsPlus.sign(messageDigest, otsHashAddress);
    }

    /**
     * Getter PqcJcajceXMSS params.
     *
     * @return PqcJcajceXMSS params.
     */
    public XMSSParameters getParams()
    {
        return params;
    }

    /**
     * Getter WOTS+.
     *
     * @return WOTS+ instance.
     */
    protected WOTSPlus getWOTSPlus()
    {
        return wotsPlus;
    }

    /**
     * Getter PqcJcajceXMSS root.
     *
     * @return Root of binary tree.
     */
    public byte[] getRoot()
    {
        return privateKey.getRoot();
    }

    protected void setRoot(byte[] root)
    {
        privateKey = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(getPublicSeed()).withRoot(root).withBDSState(privateKey.getBDSState()).build();
        publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root).withPublicSeed(getPublicSeed())
            .build();
    }

    /**
     * Getter PqcJcajceXMSS index.
     *
     * @return Index.
     */
    public int getIndex()
    {
        return privateKey.getIndex();
    }

    protected void setIndex(int index)
    {
        privateKey = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(privateKey.getPublicSeed()).withRoot(privateKey.getRoot())
            .withBDSState(privateKey.getBDSState()).build();
    }

    /**
     * Getter PqcJcajceXMSS public seed.
     *
     * @return Public seed.
     */
    public byte[] getPublicSeed()
    {
        return privateKey.getPublicSeed();
    }

    protected void setPublicSeed(byte[] publicSeed)
    {
        privateKey = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
            .withPublicSeed(publicSeed).withRoot(getRoot()).withBDSState(privateKey.getBDSState()).build();
        publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(getRoot()).withPublicSeed(publicSeed)
            .build();

        wotsPlus.importKeys(new byte[params.getDigestSize()], publicSeed);
    }

    public XMSSPrivateKeyParameters getPrivateKey()
    {
        return privateKey;
    }
}

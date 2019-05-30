package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

public class JcajceEdecKeyPairGeneratorSpi
    extends java.security.KeyPairGeneratorSpi
{
    private static final int ALGORITHM_EdDSA = -1;
    private static final int ALGORITHM_XDH = -2;

    private static final int ALGORITHM_Ed448 = 0;
    private static final int ALGORITHM_Ed25519 = 1;
    private static final int ALGORITHM_X448 = 2;
    private static final int ALGORITHM_X25519 = 3;

    private int algorithm;
    private AsymmetricCipherKeyPairGenerator generator;

    private boolean initialised;
    private SecureRandom secureRandom;

    JcajceEdecKeyPairGeneratorSpi(int algorithm, AsymmetricCipherKeyPairGenerator generator)
    {
        this.algorithm = algorithm;
        this.generator = generator;
    }

    public void initialize(int strength, SecureRandom secureRandom)
    {
        this.secureRandom = secureRandom;

        switch (strength)
        {
        case 255:
        case 256:
            switch (algorithm)
            {
            case ALGORITHM_EdDSA:
            case ALGORITHM_Ed25519:
                setupGenerator(ALGORITHM_Ed25519);
                break;
            case ALGORITHM_XDH:
            case ALGORITHM_X25519:
                setupGenerator(ALGORITHM_X25519);
                break;
            default:
                throw new InvalidParameterException("key size not configurable");
            }
            break;
        case 448:
            switch (algorithm)
            {
            case ALGORITHM_EdDSA:
            case ALGORITHM_Ed448:
                setupGenerator(ALGORITHM_Ed448);
                break;
            case ALGORITHM_XDH:
            case ALGORITHM_X448:
                setupGenerator(ALGORITHM_X448);
                break;
            default:
                throw new InvalidParameterException("key size not configurable");
            }
            break;
        default:
            throw new InvalidParameterException("unknown key size");
        }
    }

    public void initialize(AlgorithmParameterSpec paramSpec, SecureRandom secureRandom)
        throws InvalidAlgorithmParameterException
    {
        this.secureRandom = secureRandom;

        if (paramSpec instanceof ECGenParameterSpec)
        {
            initializeGenerator(((ECGenParameterSpec)paramSpec).getName());
        }
        else if (paramSpec instanceof ECNamedCurveGenParameterSpec)
        {
            initializeGenerator(((ECNamedCurveGenParameterSpec)paramSpec).getName());
        }
        else if (paramSpec instanceof EdDSAParameterSpec)
        {
            initializeGenerator(((EdDSAParameterSpec)paramSpec).getCurveName());
        }
        else if (paramSpec instanceof XDHParameterSpec)
        {
            initializeGenerator(((XDHParameterSpec)paramSpec).getCurveName());
        }
        else
        {
            throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + paramSpec);
        }
    }

    private void algorithmCheck(int algorithm)
        throws InvalidAlgorithmParameterException
    {
        if (this.algorithm != algorithm)
        {
            if (this.algorithm == ALGORITHM_Ed25519 || this.algorithm == ALGORITHM_Ed448)
            {
                throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
            }
            if (this.algorithm == ALGORITHM_EdDSA && (algorithm != ALGORITHM_Ed25519 && algorithm != ALGORITHM_Ed448))
            {
                throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
            }
            if (this.algorithm == ALGORITHM_X25519 || this.algorithm == ALGORITHM_X448)
            {
                throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
            }
            if (this.algorithm == ALGORITHM_XDH && (algorithm != ALGORITHM_X25519 && algorithm != ALGORITHM_X448))
            {
                throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
            }
            this.algorithm = algorithm;
        }
    }

    private void initializeGenerator(String name)
        throws InvalidAlgorithmParameterException
    {
        if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed448) || name.equals(EdECObjectIdentifiers.id_Ed448.getId()))
        {
            algorithmCheck(ALGORITHM_Ed448);
            this.generator = new Ed448KeyPairGenerator();
            setupGenerator(ALGORITHM_Ed448);
        }
        else if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed25519) || name.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
        {
            algorithmCheck(ALGORITHM_Ed25519);
            this.generator = new Ed25519KeyPairGenerator();
            setupGenerator(ALGORITHM_Ed25519);
        }
        else if (name.equalsIgnoreCase(XDHParameterSpec.X448) || name.equals(EdECObjectIdentifiers.id_X448.getId()))
        {
            algorithmCheck(ALGORITHM_X448);
            this.generator = new X448KeyPairGenerator();
            setupGenerator(ALGORITHM_X448);
        }
        else if (name.equalsIgnoreCase(XDHParameterSpec.X25519) || name.equals(EdECObjectIdentifiers.id_X25519.getId()))
        {
            algorithmCheck(ALGORITHM_X25519);
            this.generator = new X25519KeyPairGenerator();
            setupGenerator(ALGORITHM_X25519);
        }
    }

    public KeyPair generateKeyPair()
    {
        if (generator == null)
        {
            throw new IllegalStateException("generator not correctly initialized");
        }

        if (!initialised)
        {
            setupGenerator(algorithm);
        }

        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        switch (algorithm)
        {
        case ALGORITHM_Ed448:
            return new KeyPair(new BCEdDSAPublicKey(kp.getPublic()), new BCEdDSAPrivateKey(kp.getPrivate()));
        case ALGORITHM_Ed25519:
            return new KeyPair(new BCEdDSAPublicKey(kp.getPublic()), new BCEdDSAPrivateKey(kp.getPrivate()));
        case ALGORITHM_X448:
            return new KeyPair(new BCXDHPublicKey(kp.getPublic()), new BCXDHPrivateKey(kp.getPrivate()));
        case ALGORITHM_X25519:
            return new KeyPair(new BCXDHPublicKey(kp.getPublic()), new BCXDHPrivateKey(kp.getPrivate()));
        }

        throw new IllegalStateException("generator not correctly initialized");
    }

    private void setupGenerator(int algorithm)
    {
        initialised = true;

        if (secureRandom == null)
        {
            secureRandom = new SecureRandom();
        }

        switch (algorithm)
        {
        case ALGORITHM_Ed448:
            generator.init(new Ed448KeyGenerationParameters(secureRandom));
            break;
        case ALGORITHM_EdDSA:
        case ALGORITHM_Ed25519:
            generator.init(new Ed25519KeyGenerationParameters(secureRandom));
            break;
        case ALGORITHM_X448:
            generator.init(new X448KeyGenerationParameters(secureRandom));
            break;
        case ALGORITHM_XDH:
        case ALGORITHM_X25519:
            generator.init(new X25519KeyGenerationParameters(secureRandom));
            break;
        }
    }

    public static final class EdDSA
        extends JcajceEdecKeyPairGeneratorSpi
    {
        public EdDSA()
        {
            super(ALGORITHM_EdDSA, null);
        }
    }

    public static final class Ed448
        extends JcajceEdecKeyPairGeneratorSpi
    {
        public Ed448()
        {
            super(ALGORITHM_Ed448, new Ed448KeyPairGenerator());
        }
    }

    public static final class Ed25519
        extends JcajceEdecKeyPairGeneratorSpi
    {
        public Ed25519()
        {
            super(ALGORITHM_Ed25519, new Ed25519KeyPairGenerator());
        }
    }

    public static final class XDH
        extends JcajceEdecKeyPairGeneratorSpi
    {
        public XDH()
        {
            super(ALGORITHM_XDH, null);
        }
    }

    public static final class X448
        extends JcajceEdecKeyPairGeneratorSpi
    {
        public X448()
        {
            super(ALGORITHM_X448, new X448KeyPairGenerator());
        }
    }

    public static final class X25519
        extends JcajceEdecKeyPairGeneratorSpi
    {
        public X25519()
        {
            super(ALGORITHM_X25519, new X25519KeyPairGenerator());
        }
    }
}

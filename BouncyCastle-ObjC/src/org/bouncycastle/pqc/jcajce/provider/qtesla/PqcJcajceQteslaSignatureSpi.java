package org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;

public class PqcJcajceQteslaSignatureSpi
    extends Signature
{
    protected PqcJcajceQteslaSignatureSpi(String algorithm)
    {
        super(algorithm);
    }

    private Digest digest;
    private QTESLASigner signer;
    private SecureRandom random;

    protected PqcJcajceQteslaSignatureSpi(String sigName, Digest digest, QTESLASigner signer)
    {
        super(sigName);

        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCqTESLAPublicKey)
        {
            CipherParameters param = ((BCqTESLAPublicKey)publicKey).getKeyParams();
            
            digest.reset();
            signer.init(false, param);
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to qTESLA");
        }
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (privateKey instanceof BCqTESLAPrivateKey)
        {
            CipherParameters param = ((BCqTESLAPrivateKey)privateKey).getKeyParams();

            if (random != null)
            {
                param = new ParametersWithRandom(param, random);
            }

            signer.init(true, param);
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to qTESLA");
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            byte[] hash = PqcJcajceQteslaDigestUtil.getDigestResult(digest);

            return signer.generateSignature(hash);
        }
        catch (Exception e)
        {
            if (e instanceof IllegalStateException)
            {
                throw new SignatureException(e.getMessage());
            }
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        byte[] hash = PqcJcajceQteslaDigestUtil.getDigestResult(digest);

        return signer.verifySignature(hash, sigBytes);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    static public class qTESLA
        extends PqcJcajceQteslaSignatureSpi
    {
        public qTESLA()
        {
            super("qTESLA", new NullDigest(), new QTESLASigner());
        }
    }

    static public class HeuristicI
        extends PqcJcajceQteslaSignatureSpi
    {
        public HeuristicI()
        {
            super(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_I), new NullDigest(), new QTESLASigner());
        }
    }

    static public class HeuristicIIISize
        extends PqcJcajceQteslaSignatureSpi
    {
        public HeuristicIIISize()
        {
            super(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SIZE), new NullDigest(), new QTESLASigner());
        }
    }

    static public class HeuristicIIISpeed
        extends PqcJcajceQteslaSignatureSpi
    {
        public HeuristicIIISpeed()
        {
            super(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SPEED), new NullDigest(), new QTESLASigner());
        }
    }

    static public class ProvablySecureI
        extends PqcJcajceQteslaSignatureSpi
    {
        public ProvablySecureI()
        {
            super(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_I), new NullDigest(), new QTESLASigner());
        }
    }

    static public class ProvablySecureIII
        extends PqcJcajceQteslaSignatureSpi
    {
        public ProvablySecureIII()
        {
            super(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_III), new NullDigest(), new QTESLASigner());
        }
    }
}

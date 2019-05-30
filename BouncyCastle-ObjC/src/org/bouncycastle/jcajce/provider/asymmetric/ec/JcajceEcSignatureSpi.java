package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.ECNRSigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.DSABase;
import org.bouncycastle.jcajce.provider.asymmetric.util.JcajceUtilECUtil;

public class JcajceEcSignatureSpi
    extends DSABase
{
    JcajceEcSignatureSpi(Digest digest, DSAExt signer, DSAEncoding encoding)
    {
        super(digest, signer, encoding);
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtils.generatePublicKeyParameter(publicKey);

        digest.reset();
        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        CipherParameters param = JcajceUtilECUtil.generatePrivateKeyParameter(privateKey);

        digest.reset();

        if (appRandom != null)
        {
            signer.init(true, new ParametersWithRandom(param, appRandom));
        }
        else
        {
            signer.init(true, param);
        }
    }

    static public class ecDSA
        extends JcajceEcSignatureSpi
    {
        public ecDSA()
        {
            super(DigestFactory.createSHA1(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA
        extends JcajceEcSignatureSpi
    {
        public ecDetDSA()
        {
            super(DigestFactory.createSHA1(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA1())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSAnone
        extends JcajceEcSignatureSpi
    {
        public ecDSAnone()
        {
            super(new NullDigest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA224
        extends JcajceEcSignatureSpi
    {
        public ecDSA224()
        {
            super(DigestFactory.createSHA224(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA224
        extends JcajceEcSignatureSpi
    {
        public ecDetDSA224()
        {
            super(DigestFactory.createSHA224(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA224())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA256
        extends JcajceEcSignatureSpi
    {
        public ecDSA256()
        {
            super(DigestFactory.createSHA256(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA256
        extends JcajceEcSignatureSpi
    {
        public ecDetDSA256()
        {
            super(DigestFactory.createSHA256(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA256())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA384
        extends JcajceEcSignatureSpi
    {
        public ecDSA384()
        {
            super(DigestFactory.createSHA384(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA384
        extends JcajceEcSignatureSpi
    {
        public ecDetDSA384()
        {
            super(DigestFactory.createSHA384(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA384())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA512
        extends JcajceEcSignatureSpi
    {
        public ecDSA512()
        {
            super(DigestFactory.createSHA512(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSA512
        extends JcajceEcSignatureSpi
    {
        public ecDetDSA512()
        {
            super(DigestFactory.createSHA512(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA512())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_224
        extends JcajceEcSignatureSpi
    {
        public ecDSASha3_224()
        {
            super(DigestFactory.createSHA3_224(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_224
        extends JcajceEcSignatureSpi
    {
        public ecDetDSASha3_224()
        {
            super(DigestFactory.createSHA3_224(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_224())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_256
        extends JcajceEcSignatureSpi
    {
        public ecDSASha3_256()
        {
            super(DigestFactory.createSHA3_256(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_256
        extends JcajceEcSignatureSpi
    {
        public ecDetDSASha3_256()
        {
            super(DigestFactory.createSHA3_256(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_256())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_384
        extends JcajceEcSignatureSpi
    {
        public ecDSASha3_384()
        {
            super(DigestFactory.createSHA3_384(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_384
        extends JcajceEcSignatureSpi
    {
        public ecDetDSASha3_384()
        {
            super(DigestFactory.createSHA3_384(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_384())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_512
        extends JcajceEcSignatureSpi
    {
        public ecDSASha3_512()
        {
            super(DigestFactory.createSHA3_512(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_512
        extends JcajceEcSignatureSpi
    {
        public ecDetDSASha3_512()
        {
            super(DigestFactory.createSHA3_512(), new ECDSASigner(new HMacDSAKCalculator(DigestFactory.createSHA3_512())), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSARipeMD160
        extends JcajceEcSignatureSpi
    {
        public ecDSARipeMD160()
        {
            super(new RIPEMD160Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR
        extends JcajceEcSignatureSpi
    {
        public ecNR()
        {
            super(DigestFactory.createSHA1(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR224
        extends JcajceEcSignatureSpi
    {
        public ecNR224()
        {
            super(DigestFactory.createSHA224(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR256
        extends JcajceEcSignatureSpi
    {
        public ecNR256()
        {
            super(DigestFactory.createSHA256(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR384
        extends JcajceEcSignatureSpi
    {
        public ecNR384()
        {
            super(DigestFactory.createSHA384(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR512
        extends JcajceEcSignatureSpi
    {
        public ecNR512()
        {
            super(DigestFactory.createSHA512(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA
        extends JcajceEcSignatureSpi
    {
        public ecCVCDSA()
        {
            super(DigestFactory.createSHA1(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA224
        extends JcajceEcSignatureSpi
    {
        public ecCVCDSA224()
        {
            super(DigestFactory.createSHA224(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA256
        extends JcajceEcSignatureSpi
    {
        public ecCVCDSA256()
        {
            super(DigestFactory.createSHA256(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA384
        extends JcajceEcSignatureSpi
    {
        public ecCVCDSA384()
        {
            super(DigestFactory.createSHA384(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA512
        extends JcajceEcSignatureSpi
    {
        public ecCVCDSA512()
        {
            super(DigestFactory.createSHA512(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecPlainDSARP160
        extends JcajceEcSignatureSpi
    {
        public ecPlainDSARP160()
        {
            super(new RIPEMD160Digest(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }
}

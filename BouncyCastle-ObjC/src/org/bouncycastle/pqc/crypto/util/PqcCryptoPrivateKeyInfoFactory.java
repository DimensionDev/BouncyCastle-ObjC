package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.PqcAsn1XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.PqcAsn1XMSSPrivateKey;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.Pack;

/**
 * Factory to create ASN.1 private key info objects from lightweight private keys.
 */
public class PqcCryptoPrivateKeyInfoFactory
{
    private PqcCryptoPrivateKeyInfoFactory()
    {

    }

    /**
     * Create a PrivateKeyInfo representation of a private key.
     *
     * @param privateKey the key to be encoded into the info object.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey) throws IOException
    {
        return createPrivateKeyInfo(privateKey, null);
    }

    /**
     * Create a PrivateKeyInfo representation of a private key with attributes.
     *
     * @param privateKey the key to be encoded into the info object.
     * @param attributes the set of attributes to be included.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException
    {
        if (privateKey instanceof QTESLAPrivateKeyParameters)
        {
            QTESLAPrivateKeyParameters keyParams = (QTESLAPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = PqcCryptoUtilUtils.qTeslaLookupAlgID(keyParams.getSecurityCategory());

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(keyParams.getSecret()), attributes);
        }
        else if (privateKey instanceof SPHINCSPrivateKeyParameters)
        {
            SPHINCSPrivateKeyParameters params = (SPHINCSPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                                    new SPHINCS256KeyParams(PqcCryptoUtilUtils.sphincs256LookupTreeAlgID(params.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getKeyData()));
        }
        else if (privateKey instanceof NHPrivateKeyParameters)
        {
            NHPrivateKeyParameters params = (NHPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);

            short[] privateKeyData = params.getSecData();

            byte[] octets = new byte[privateKeyData.length * 2];
            for (int i = 0; i != privateKeyData.length; i++)
            {
                Pack.shortToLittleEndian(privateKeyData[i], octets, i * 2);
            }

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(octets));
        }
        else if (privateKey instanceof XMSSPrivateKeyParameters)
        {
            XMSSPrivateKeyParameters keyParams = (XMSSPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                new XMSSKeyParams(keyParams.getParameters().getHeight(),
                    PqcCryptoUtilUtils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, xmssCreateKeyStructure(keyParams));
        }
        else if (privateKey instanceof XMSSMTPrivateKeyParameters)
        {
            XMSSMTPrivateKeyParameters keyParams = (XMSSMTPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
                new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(),
                    PqcCryptoUtilUtils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, xmssmtCreateKeyStructure(keyParams));
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }

    private static PqcAsn1XMSSPrivateKey xmssCreateKeyStructure(XMSSPrivateKeyParameters keyParams)
    {
        byte[] keyData = keyParams.toByteArray();

        int n = keyParams.getParameters().getDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int indexSize = 4;
        int secretKeySize = n;
        int secretKeyPRFSize = n;
        int publicSeedSize = n;
        int rootSize = n;

        int position = 0;
        int index = (int)XMSSUtil.bytesToXBigEndian(keyData, position, indexSize);
        if (!XMSSUtil.isIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeySize);
        position += secretKeySize;
        byte[] secretKeyPRF = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeyPRFSize);
        position += secretKeyPRFSize;
        byte[] publicSeed = XMSSUtil.extractBytesAtOffset(keyData, position, publicSeedSize);
        position += publicSeedSize;
        byte[] root = XMSSUtil.extractBytesAtOffset(keyData, position, rootSize);
        position += rootSize;
               /* import BDS state */
        byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(keyData, position, keyData.length - position);

        return new PqcAsn1XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
    }

    private static PqcAsn1XMSSMTPrivateKey xmssmtCreateKeyStructure(XMSSMTPrivateKeyParameters keyParams)
    {
        byte[] keyData = keyParams.toByteArray();

        int n = keyParams.getParameters().getDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int indexSize = (totalHeight + 7) / 8;
        int secretKeySize = n;
        int secretKeyPRFSize = n;
        int publicSeedSize = n;
        int rootSize = n;

        int position = 0;
        int index = (int)XMSSUtil.bytesToXBigEndian(keyData, position, indexSize);
        if (!XMSSUtil.isIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeySize);
        position += secretKeySize;
        byte[] secretKeyPRF = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeyPRFSize);
        position += secretKeyPRFSize;
        byte[] publicSeed = XMSSUtil.extractBytesAtOffset(keyData, position, publicSeedSize);
        position += publicSeedSize;
        byte[] root = XMSSUtil.extractBytesAtOffset(keyData, position, rootSize);
        position += rootSize;
               /* import BDS state */
        byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(keyData, position, keyData.length - position);

        return new PqcAsn1XMSSMTPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
    }
}

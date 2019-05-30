package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.util.Arrays;

public class BCXDHPublicKey
    implements XDHKey, PublicKey
{
    static final long serialVersionUID = 1L;

    private transient AsymmetricKeyParameter xdhPublicKey;

    BCXDHPublicKey(AsymmetricKeyParameter pubKey)
    {
        this.xdhPublicKey = pubKey;
    }

    BCXDHPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        populateFromPubKeyInfo(keyInfo);
    }

    BCXDHPublicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        int prefixLength = prefix.length;

        if (JcajceEdecUtils.isValidPrefix(prefix, rawData))
        {
            if ((rawData.length - prefixLength) == X448PublicKeyParameters.KEY_SIZE)
            {
                xdhPublicKey = new X448PublicKeyParameters(rawData, prefixLength);
            }
            else if ((rawData.length - prefixLength) == X25519PublicKeyParameters.KEY_SIZE)
            {
                xdhPublicKey = new X25519PublicKeyParameters(rawData, prefixLength);
            }
            else
            {
                throw new InvalidKeySpecException("raw key data not recognised");
            }
        }
        else
        {
            throw new InvalidKeySpecException("raw key data not recognised");
        }
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo keyInfo)
    {
        if (EdECObjectIdentifiers.id_X448.equals(keyInfo.getAlgorithm().getAlgorithm()))
        {
            xdhPublicKey = new X448PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
        }
        else
        {
            xdhPublicKey = new X25519PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
        }
    }

    public String getAlgorithm()
    {
        return (xdhPublicKey instanceof X448PublicKeyParameters) ? "X448" : "X25519";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        if (xdhPublicKey instanceof X448PublicKeyParameters)
        {
            byte[] encoding = new byte[JcajceEdecKeyFactorySpi.x448Prefix.length + X448PublicKeyParameters.KEY_SIZE];

            System.arraycopy(JcajceEdecKeyFactorySpi.x448Prefix, 0, encoding, 0, JcajceEdecKeyFactorySpi.x448Prefix.length);

            ((X448PublicKeyParameters)xdhPublicKey).encode(encoding, JcajceEdecKeyFactorySpi.x448Prefix.length);

            return encoding;
        }
        else
        {
            byte[] encoding = new byte[JcajceEdecKeyFactorySpi.x25519Prefix.length + X25519PublicKeyParameters.KEY_SIZE];

            System.arraycopy(JcajceEdecKeyFactorySpi.x25519Prefix, 0, encoding, 0, JcajceEdecKeyFactorySpi.x25519Prefix.length);

            ((X25519PublicKeyParameters)xdhPublicKey).encode(encoding, JcajceEdecKeyFactorySpi.x25519Prefix.length);

            return encoding;
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return xdhPublicKey;
    }

    public String toString()
    {
        return JcajceEdecUtils.keyToString("Public Key", getAlgorithm(), xdhPublicKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof BCXDHPublicKey))
        {
            return false;
        }

        BCXDHPublicKey other = (BCXDHPublicKey)o;

        return Arrays.areEqual(other.getEncoded(), this.getEncoded());
    }

    public int hashCode()
    {
        return Arrays.hashCode(this.getEncoded());
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}

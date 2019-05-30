package org.bouncycastle.pqc.crypto.qtesla;

/**
 * The qTESLA security categories.
 */
public class QTESLASecurityCategory
{
    public static final int HEURISTIC_I = 0;
    public static final int HEURISTIC_III_SIZE = 1;
    public static final int HEURISTIC_III_SPEED = 2;
    public static final int PROVABLY_SECURE_I = 3;
    public static final int PROVABLY_SECURE_III = 4;

    private QTESLASecurityCategory()
    {
    }

    static void validate(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
        case HEURISTIC_III_SIZE:
        case HEURISTIC_III_SPEED:
        case PROVABLY_SECURE_I:
        case PROVABLY_SECURE_III:
            break;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPrivateSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
            return PqcCryptoQteslaPolynomial.PRIVATE_KEY_I;
        case HEURISTIC_III_SIZE:
            return PqcCryptoQteslaPolynomial.PRIVATE_KEY_III_SIZE;
        case HEURISTIC_III_SPEED:
            return PqcCryptoQteslaPolynomial.PRIVATE_KEY_III_SPEED;
        case PROVABLY_SECURE_I:
            return PqcCryptoQteslaPolynomial.PRIVATE_KEY_I_P;
        case PROVABLY_SECURE_III:
            return PqcCryptoQteslaPolynomial.PRIVATE_KEY_III_P;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getPublicSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
            return PqcCryptoQteslaPolynomial.PUBLIC_KEY_I;
        case HEURISTIC_III_SIZE:
            return PqcCryptoQteslaPolynomial.PUBLIC_KEY_III_SIZE;
        case HEURISTIC_III_SPEED:
            return PqcCryptoQteslaPolynomial.PUBLIC_KEY_III_SPEED;
        case PROVABLY_SECURE_I:
            return PqcCryptoQteslaPolynomial.PUBLIC_KEY_I_P;
        case PROVABLY_SECURE_III:
            return PqcCryptoQteslaPolynomial.PUBLIC_KEY_III_P;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getSignatureSize(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
            return PqcCryptoQteslaPolynomial.SIGNATURE_I;
        case HEURISTIC_III_SIZE:
            return PqcCryptoQteslaPolynomial.SIGNATURE_III_SIZE;
        case HEURISTIC_III_SPEED:
            return PqcCryptoQteslaPolynomial.SIGNATURE_III_SPEED;
        case PROVABLY_SECURE_I:
            return PqcCryptoQteslaPolynomial.SIGNATURE_I_P;
        case PROVABLY_SECURE_III:
            return PqcCryptoQteslaPolynomial.SIGNATURE_III_P;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    /**
     * Return a standard name for the security category.
     *
     * @param securityCategory the category of interest.
     * @return the name for the category.
     */
    public static String getName(int securityCategory)
    {
        switch (securityCategory)
        {
        case HEURISTIC_I:
            return "qTESLA-I";
        case HEURISTIC_III_SIZE:
            return "qTESLA-III-size";
        case HEURISTIC_III_SPEED:
            return "qTESLA-III-speed";
        case PROVABLY_SECURE_I:
            return "qTESLA-p-I";
        case PROVABLY_SECURE_III:
            return "qTESLA-p-III";
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }
}

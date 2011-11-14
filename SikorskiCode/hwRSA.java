// hwRSA.java
// Houses all required RSA / 0-Knowledge code.
import java.math.*;
import java.util.*;

public class hwRSA
{
    private static final numberOfBits = 32768; // 2^15

    public BigInteger getPrime(Random random)
    {
        return BigInteger.probablePrime(numberOfBits, random);
    }
}
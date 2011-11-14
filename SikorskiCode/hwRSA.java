// hwRSA.java
// Houses all required RSA / 0-Knowledge code.
import java.math.*;
import java.util.*;

public class hwRSA
{
    private static final numberOfBits = 32768; // 2^15

    public Random savedRandom = null;
    public BigInteger p;
    public BigInteger q;
    public BigInteger n; // n = p * q
    
    public hwRSA(Random random)
    {
        savedRandom = random;
        
        p = getPrime(random);
        q = getPrime(random);
        n = p.multiply(q);
    }
    
    private BigInteger getPrime(Random random)
    {
        return BigInteger.probablePrime(numberOfBits, random);
    }
}
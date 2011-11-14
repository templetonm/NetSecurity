// hwRSA.java
// Houses all required RSA / 0-Knowledge code.
import java.math.*;
import java.util.*;

public class hwRSA
{
    private static final int numberOfBits = 32768; // 2^15
    private static final BigInteger ONE = new BigInteger("1");
    
    
    public Random savedRandom = null;
    public BigInteger p;
    public BigInteger q;
    public BigInteger n; // n = p * q
    public BigInteger phiN;
    
    public hwRSA(Random random)
    {
        savedRandom = random;
        
        p = getPrime(random);
        q = getPrime(random);
        n = p.multiply(q);
        phiN = (p.subtract(ONE)).multiply(q.subtract(ONE));
    }
    
    public void initialize(Random random)
    {
        // initialize all the variables
    }

    public void load()
    {
        // load all the variables from a saved source
    }
    
    private BigInteger getPrime(Random random)
    {
        return BigInteger.probablePrime(numberOfBits, random);
    }
}
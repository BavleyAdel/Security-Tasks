package Security;

import java.util.Arrays;
import java.util.List;

public class ElGamal {
      // Encrypts the message
    public List<Long> encrypt(int q, int alpha, int y, int k, int m) {
        long c1 = modPow(alpha, k, q);
        long s = modPow(y, k, q);          // shared secret
        long c2 = (m * s) % q;
        return Arrays.asList(c1, c2);
    }

    // Decrypts the message
    public int decrypt(int c1, int c2, int x, int q) {
        long s = modPow(c1, x, q);         // shared secret
        long sInv = modInverse(s, q);      // multiplicative inverse of s
        long m = (c2 * sInv) % q;
        return (int) m;
    }

    // Efficient modular exponentiation
    private long modPow(long base, long exp, long mod) {
        long result = 1;
        base %= mod;
        while (exp > 0) {
            if ((exp & 1) == 1)
                result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

    // Modular inverse using Extended Euclidean Algorithm
    private long modInverse(long a, long m) {
        long m0 = m, t, q;
        long x0 = 0, x1 = 1;

        if (m == 1)
            return 0;

        while (a > 1) {
            q = a / m;
            t = m;

            m = a % m;
            a = t;
            t = x0;

            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0)
            x1 += m0;

        return x1;
    }
}

package Security;

public class RSA {

    public int encrypt(int p, int q, int M, int e) {
        long n = (long)p * q;
        return (int)modPow(M, e, n);
    }

    public int decrypt(int p, int q, int C, int e) {
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        long d = modInverse(e, phi);
        return (int)modPow(C, d, n);
    }

    private long modPow(long base, long exponent, long mod) {
        long result = 1;
        base = base % mod;

        while (exponent > 0) {
            if ((exponent & 1) == 1)
                result = (result * base) % mod;

            exponent >>= 1; //exponent /= 2

            base = (base * base) % mod;
        }

        return result;
    }

    // Extended Euclidean
    private long modInverse(long a, long m) {
        long a2 = 0, a3 = m;
        long b2 = 1, b3 = a;
        long q, new_b2, new_b3;

        while (b3 > 1) {
            q = a3 / b3;

            new_b2 = a2 - q * b2;
            new_b3 = a3 - q * b3;

            a2 = b2;
            a3 = b3;

            b2 = new_b2;
            b3 = new_b3;
        }

        if (b3 != 1)
            throw new ArithmeticException("No modular inverse exists.");

        // Ensure positive result
        return (b2 + m) % m;
    }
}

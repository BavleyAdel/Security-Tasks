package Security;

import java.util.ArrayList;
import java.util.List;

public class DiffieHellman {
    public List<Integer> getKeys(int q, int alpha, int xa, int xb) {
        List<Integer> keys = new ArrayList<>();

        // Public keys
        int ya = modPow(alpha, xa, q); // A's public key
        int yb = modPow(alpha, xb, q); // B's public key

        // Shared keys
        int keyA = modPow(yb, xa, q);
        int keyB = modPow(ya, xb, q);

        // Add keys to list: keyA, keyB
        keys.add(keyA);
        keys.add(keyB);

        return keys;
    }

    private int modPow(int base, int exponent, int mod) {
        int result = 1;
        base = base % mod;

        while (exponent > 0) {
            if ((exponent & 1) == 1)
                result = (result * base) % mod;

            exponent >>= 1; //exponent /= 2

            base = (base * base) % mod;
        }

        return result;
    }
}

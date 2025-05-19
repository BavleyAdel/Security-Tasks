package Security;
import java.util.*;

public class ColumnarCipher {

    public List<Integer> analyse(String plainText, String cipherText) {
        int length = plainText.length();

        for (int keyLen = 2; keyLen <= length; keyLen++) {
            int numRows = (int) Math.ceil((double) length / keyLen);

            // Fill plaintext matrix row-wise
            char[][] plainMatrix = new char[numRows][keyLen];
            int pIndex = 0;
            for (int i = 0; i < numRows; i++) {
                for (int j = 0; j < keyLen; j++) {
                    if (pIndex < plainText.length()) {
                        plainMatrix[i][j] = plainText.charAt(pIndex++);
                    } else {
                        plainMatrix[i][j] = 'X';
                    }
                }
            }

            // Create column strings from the plaintext
            List<String> plainCols = new ArrayList<>();
            for (int col = 0; col < keyLen; col++) {
                StringBuilder colStr = new StringBuilder();
                for (int row = 0; row < numRows; row++) {
                    colStr.append(plainMatrix[row][col]);
                }
                plainCols.add(colStr.toString());
            }

            // Split ciphertext into columns based on numRows
            List<String> cipherCols = new ArrayList<>();
            int cIndex = 0;
            for (int i = 0; i < keyLen; i++) {
                StringBuilder col = new StringBuilder();
                for (int j = 0; j < numRows && cIndex < cipherText.length(); j++) {
                    col.append(cipherText.charAt(cIndex++));
                }
                cipherCols.add(col.toString());
            }

            // Build the key by matching cipher columns to plaintext columns
            int[] colOrder = new int[keyLen];
            boolean valid = true;
            for (int i = 0; i < keyLen; i++) {
                int index = plainCols.indexOf(cipherCols.get(i));
                if (index == -1) {
                    valid = false;
                    break;
                }
                colOrder[index] = i + 1; // 1-based key order
            }

            if (valid) {
                List<Integer> key = new ArrayList<>();
                for (int k : colOrder) {
                    key.add(k);
                }
                return key;
            }
        }

        return new ArrayList<>(); // No key found
    }




    public String decrypt(String cipherText, List<Integer> key) {
        int cipherSize = cipherText.length();
        int rows = (int) Math.ceil((double) cipherSize / key.size());
        char[][] grid = new char[rows][key.size()];
        int count = 0;

        Map<Integer, Integer> keyMap = new HashMap<>();
        for (int i = 0; i < key.size(); i++) {
            keyMap.put(key.get(i) - 1, i);
        }

        int remainingCols = cipherSize % key.size();
        for (int i = 0; i < key.size(); i++) {
            for (int j = 0; j < rows; j++) {
                if (remainingCols != 0 && j == rows - 1 && keyMap.get(i) >= remainingCols) continue;
                grid[j][keyMap.get(i)] = cipherText.charAt(count++);
            }
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < key.size(); j++) {
                result.append(grid[i][j]);
            }
        }
        return result.toString().toUpperCase().trim();
    }

    public String encrypt(String plainText, List<Integer> key) {
        int ptSize = plainText.length();
        int rows = (int) Math.ceil((double) ptSize / key.size());
        char[][] grid = new char[rows][key.size()];
        int count = 0;

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < key.size(); j++) {
                if (count >= ptSize) {
                    grid[i][j] = 'x';
                } else {
                    grid[i][j] = plainText.charAt(count++);
                }
            }
        }

        Map<Integer, Integer> keyMap = new HashMap<>();
        for (int i = 0; i < key.size(); i++) {
            keyMap.put(key.get(i) - 1, i);
        }

        StringBuilder cipherText = new StringBuilder();
        for (int i = 0; i < key.size(); i++) {
            for (int j = 0; j < rows; j++) {
                cipherText.append(Character.toUpperCase(grid[j][keyMap.get(i)]));
            }
        }
        return cipherText.toString();
    }
}

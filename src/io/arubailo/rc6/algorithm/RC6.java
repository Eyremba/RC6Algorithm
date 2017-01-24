package io.arubailo.rc6.algorithm;

public class RC6 {

    private static final int W_WORD_LENGTH = 32;
    private static final int R_ROUND_COUNT = 20;
    private static final int P_W = 0xb7e15163;
    private static final int Q_W = 0x9e3779b9;
    private static final int BLOCK_LENGTH = 16;

    private static int[] subKeysArray;

    public static byte[] encryptData(byte[] data, byte[] key) {

        byte[] block = new byte[16];

        key = paddingKey(key);
        subKeysArray = generateSubKeys(key);

        int length = 16 - data.length % 16;
        byte[] padding = new byte[length];
        padding[0] = (byte) 0x80;

        for (int i = 1; i < length; i++) {
            padding[i] = 0;
        }

        int count = 0;
        byte[] tempByteArray = new byte[data.length + length];

        for (int i = 0; i < data.length + length; i++) {
            if (i > 0 && i % 16 == 0) {
                block = encryptBlock(block);
                System.arraycopy(block, 0, tempByteArray, i - 16, block.length);
            }

            if (i < data.length) {
                block[i % 16] = data[i];
            } else {
                block[i % 16] = padding[count];
                count++;
                if (count > length - 1) {
                    count = 1;
                }
            }
        }

        block = encryptBlock(block);
        System.arraycopy(block, 0, tempByteArray, data.length + length - 16, block.length);
        return tempByteArray;
    }

    public static byte[] decrypt(byte[] data, byte[] key) {
        byte[] tempByreArray = new byte[data.length];
        byte[] block = new byte[BLOCK_LENGTH];

        key = paddingKey(key);
        subKeysArray = generateSubKeys(key);

        for (int i = 0; i < data.length; i++) {
            if (i > 0 && i % 16 == 0) {
                block = decryptBlock(block);
                System.arraycopy(block, 0, tempByreArray, i - 16, block.length);
            }

            if (i < data.length) {
                block[i % 16] = data[i];
            }
        }

        block = decryptBlock(block);
        System.arraycopy(block, 0, tempByreArray, data.length - 16, block.length);
        return deletePadding(tempByreArray);
    }

    /**
     * As a first step of the key schedule is preloading the user key of b byte into in array L of c words.
     */
    private static int[] convertBytesToWords(byte[] key, int c) {
        int[] tmp = new int[c];
        initByteArray(tmp);

        for (int i = 0, off = 0; i < c; i++)
            tmp[i] = ((key[off++] & 0xFF)) | ((key[off++] & 0xFF) << 8)
                    | ((key[off++] & 0xFF) << 16) | ((key[off++] & 0xFF) << 24);

        return tmp;
    }

    private static int[] generateSubKeys(byte[] key) {

        int u = W_WORD_LENGTH / 8;
        int c = key.length / u;
        int t = 2 * R_ROUND_COUNT + 4;

        int[] L = convertBytesToWords(key, c);


        int[] subKeys = new int[t];
        subKeys[0] = P_W;
        for (int i = 1; i < t; i++) {
            subKeys[i] = subKeys[i - 1] + Q_W;
        }

        int A = 0;
        int B = 0;
        int k = 0;
        int j = 0;

        int v = 3 * Math.max(c, t);

        for (int i = 0; i < v; i++) {
            A = subKeys[k] = rotateLeft((subKeys[k] + A + B), 3);
            B = L[j] = rotateLeft(L[j] + A + B, A + B);
            k = (k + 1) % t;
            j = (j + 1) % c;
        }

        return subKeys;
    }

    private static int rotateLeft(int val, int pas) {
        return (val << pas) | (val >>> (32 - pas));
    }

    private static int rotateRight(int val, int pas) {
        return (val >>> pas) | (val << (32 - pas));
    }

    private static byte[] decryptBlock(byte[] input) {
        byte[] tmp = new byte[input.length];
        int t, u;
        int aux;
        int[] data = new int[input.length / 4];
        initByteArray(data);
        int off = 0;
        for (int i = 0; i < data.length; i++) {
            data[i] = ((input[off++] & 0xff)) |
                    ((input[off++] & 0xff) << 8) |
                    ((input[off++] & 0xff) << 16) |
                    ((input[off++] & 0xff) << 24);
        }


        int A = data[0], B = data[1], C = data[2], D = data[3];

        C = C - subKeysArray[2 * R_ROUND_COUNT + 3];
        A = A - subKeysArray[2 * R_ROUND_COUNT + 2];
        for (int i = R_ROUND_COUNT; i >= 1; i--) {
            aux = D;
            D = C;
            C = B;
            B = A;
            A = aux;

            u = rotateLeft(D * (2 * D + 1), 5);
            t = rotateLeft(B * (2 * B + 1), 5);
            C = rotateRight(C - subKeysArray[2 * i + 1], t) ^ u;
            A = rotateRight(A - subKeysArray[2 * i], u) ^ t;
        }
        D = D - subKeysArray[1];
        B = B - subKeysArray[0];

        data[0] = A;
        data[1] = B;
        data[2] = C;
        data[3] = D;


        for (int i = 0; i < tmp.length; i++) {
            tmp[i] = (byte) ((data[i / 4] >>> (i % 4) * 8) & 0xff);
        }

        return tmp;
    }

    /**
     * Function encryptBlock contains the actual algorithm for encryption.
     * We take the input and split it up in 4 pieces of 32 bits, storing them in the 4 registers.
     * Next is the actual implementation of the algorithm as described in the official document(see pseudocode).
     * Function rotateLeft is a rotation to left of the first param with second param steps.
     * The number 5 for rotation in the first two is the value given by lgw = lg 32 = 5.
     * Array S holds the w bit round keys as described in the key scheduling process.
    **/
    private static byte[] encryptBlock(byte[] input) {

        int t;
        int u;
        int aux;
        int off = 0;

        byte[] tempByteArray = new byte[input.length];
        int[] data = new int[input.length / 4];

        initByteArray(data);

        for (int i = 0; i < data.length; i++) {
            data[i] = ((input[off++] & 0xff)) |
                    ((input[off++] & 0xff) << 8) |
                    ((input[off++] & 0xff) << 16) |
                    ((input[off++] & 0xff) << 24);
        }

        int A = data[0];
        int B = data[1];
        int C = data[2];
        int D = data[3];

        B = B + subKeysArray[0];
        D = D + subKeysArray[1];

        for (int i = 1; i <= R_ROUND_COUNT; i++) {
            t = rotateLeft(B * (2 * B + 1), 5);
            u = rotateLeft(D * (2 * D + 1), 5);
            A = rotateLeft(A ^ t, u) + subKeysArray[2 * i];
            C = rotateLeft(C ^ u, t) + subKeysArray[2 * i + 1];

            aux = A;
            A = B;
            B = C;
            C = D;
            D = aux;
        }
        A = A + subKeysArray[2 * R_ROUND_COUNT + 2];
        C = C + subKeysArray[2 * R_ROUND_COUNT + 3];

        data[0] = A;
        data[1] = B;
        data[2] = C;
        data[3] = D;

        for (int i = 0; i < tempByteArray.length; i++) {
            tempByteArray[i] = (byte) ((data[i / 4] >>> (i % 4) * 8) & 0xff);
        }

        return tempByteArray;
    }

    private static void initByteArray(int[] data) {
        for (int i = 0; i < data.length; i++) {
            data[i] = 0;
        }
    }

    private static byte[] paddingKey(byte[] key) {
        for (int i = 0; i < key.length % 4; i++) {
            key[key.length + i] = 0;
        }
        return key;
    }

    private static byte[] deletePadding(byte[] input) {
        int count = 0;
        int i = input.length - 1;

        while (input[i] == 0) {
            count++;
            i--;
        }

        byte[] trimmedArray = new byte[input.length - count - 1];
        System.arraycopy(input, 0, trimmedArray, 0, trimmedArray.length);
        return trimmedArray;
    }
}

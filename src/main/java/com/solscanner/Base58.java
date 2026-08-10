package com.solscanner;

public final class Base58 {
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int BASE_58 = ALPHABET.length;

    public static String encode(byte[] input) {
        if (input.length == 0) return "";
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) zeros++;

        int size = (int) (input.length * 1.5) + 1;
        int[] b58 = new int[size];

        for (int i = zeros; i < input.length; i++) {
            int carry = input[i] & 0xFF;
            for (int j = size - 1; j >= 0; j--) {
                carry += (b58[j] << 8);
                b58[j] = carry % BASE_58;
                carry /= BASE_58;
            }
        }

        int j = 0;
        while (j < size && b58[j] == 0) j++;

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < zeros; i++) sb.append('1');
        for (; j < size; j++) sb.append(ALPHABET[b58[j]]);
        return sb.toString();
    }
}

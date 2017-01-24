package io.arubailo.rc6;

import io.arubailo.rc6.algorithm.RC6;

import java.util.Arrays;

public class Main {

    private static final byte[] KEY = "suchKeySoVeryKey".getBytes();
    private static final byte[] DATA = "Such sample data, much text, wow!".getBytes();

    public static void main(String[] args) {
        byte[] encryptedText = RC6.encryptData(DATA, KEY);

        System.out.println(Arrays.toString(encryptedText));
        System.out.println(new String(RC6.decrypt(encryptedText, KEY)));
    }
}

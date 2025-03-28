package com.trilead.ssh2.crypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

/**
 * AES-256-GCM implementation for Java 1.4.
 * This requires manual IV and tag handling, as GCM is not supported in Java 1.4 by default.
 */
public class AESGCM implements BlockCipher {

    private static final int GCM_TAG_LENGTH = 16; // 16 bytes (128 bits) for authentication tag
    private static final int GCM_IV_LENGTH = 12; // 12 bytes (96 bits) for IV
    private static final int AES_BLOCK_SIZE = 16; // AES block size is always 16 bytes

    private boolean encrypting;
    private Key aesKey;
    private byte[] iv;
    private byte[] gcmTag;

    private Cipher aesCipher;

    /**
     * Initialize AES-GCM with encryption/decryption mode and a key.
     *
     * @param forEncryption true for encryption, false for decryption.
     * @param key           256-bit AES key.
     */
    public void init(boolean forEncryption, byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException("AES requires a 256-bit key.");
        }
        this.encrypting = forEncryption;
        this.aesKey = new SecretKeySpec(key, "AES");
        this.iv = generateDefaultIV();
        this.gcmTag = new byte[GCM_TAG_LENGTH]; // Placeholder for GCM tag

        this.aesCipher = Cipher.getInstance("AES/ECB/NoPadding"); // AES core cipher (ECB mode for manual operation)
    }

    /**
     * Sets the IV (Initialization Vector) for AES-GCM manually.
     *
     * @param iv the initialization vector. Must be 12 bytes (96 bits) for GCM.
     */
    public void setIV(byte[] iv) {
        if (iv.length != GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid IV length. AES-GCM requires a 12-byte IV.");
        }
        this.iv = iv;
    }

    /**
     * Encrypts or decrypts a block of input data using AES-GCM.
     *
     * @param src     The input data.
     * @param srcOff  The offset in the input data.
     * @param dst     The output buffer.
     * @param dstOff  The offset in the output buffer.
     */
    public void transformBlock(byte[] src, int srcOff, byte[] dst, int dstOff) throws GeneralSecurityException {
        byte[] counterBlock = new byte[AES_BLOCK_SIZE];
        System.arraycopy(iv, 0, counterBlock, 0, GCM_IV_LENGTH);

        // Process each AES block
        for (int i = 0; i < src.length / AES_BLOCK_SIZE; i++) {
            incrementCounter(counterBlock); // Increment the counter for GCM
            byte[] aesResult = processAESBlock(counterBlock); // Encrypt the counter
            xorBlock(src, srcOff + (i * AES_BLOCK_SIZE), aesResult, dst, dstOff + (i * AES_BLOCK_SIZE));
        }

        // Generate GCM Tag (Simplified, real applications require full authentication)
        generateAuthenticationTag(src, srcOff, src.length);
    }

    public int getOutputSize(int inputLen) {
        return inputLen + GCM_TAG_LENGTH;
    }

    public int getBlockSize() {
        return GCM_IV_LENGTH;
    }

    /**
     * Returns the GCM authentication tag.
     *
     * @return The GCM tag.
     */
    public byte[] getAuthenticationTag() {
        return gcmTag;
    }

    /**
     * Generate a default IV for AES-GCM.
     *
     * @return A generated IV of 12 bytes.
     */
    private byte[] generateDefaultIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(iv);
        return iv;
    }

    /**
     * Encrypts or decrypts a single AES block using the AES cipher in ECB mode.
     *
     * @param input The input block (16 bytes).
     * @return The processed AES block (16 bytes).
     */
    private byte[] processAESBlock(byte[] input) throws GeneralSecurityException {
        aesCipher.init(encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, aesKey);
        return aesCipher.doFinal(input);
    }

/**
 * XOR a block of data with another block.
 *
 * @param src     The source block.
 * @param srcOff  Offset in the source block.
 * @param aes
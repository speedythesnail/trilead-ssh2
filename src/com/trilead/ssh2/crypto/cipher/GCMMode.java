package com.trilead.ssh2.crypto.cipher;

import com.trilead.ssh2.log.Logger;

import java.security.Key;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * GCMMode.
 *
 * @author Steven Jubb
 * @version $Id: GCMMode.java,v 1.1 2025/03/16 13:28:00 speedythesnail Exp $
 */
public class GCMMode implements BlockCipher {

    private static final Logger log = Logger.getLogger(GCMMode.class);

    private static final int BLOCK_SIZE = 16; // Block size for AES in bytes
    private static final String AES_ECB_NOPADDING = "AES/ECB/NoPadding";

    private final Cipher aesCipher;
    private final byte[] counter;
    private final byte[] authenticationTag;

    public GCMMode(BlockCipher bc, byte[] iv, boolean encrypt) {
        this.aesCipher = initializeAESCipher(bc);
        this.counter = new byte[BLOCK_SIZE];
        System.arraycopy(iv, 0, this.counter, 0, iv.length);
        this.authenticationTag = new byte[BLOCK_SIZE];
    }

    private Cipher initializeAESCipher(byte[] key) throws Exception {
        Key secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance(AES_ECB_NOPADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
    }

    @Override
    public void transformBlock(byte[] src, int srcoff, byte[] dest, int destoff) {
        try {
            byte[] keystream = aesCipher.doFinal(counter);
            incrementCounterBlock();
            for (int i = 0; i < src.length; i++) {
                dest[destoff + i] = (byte) (src[srcoff + i] ^ keystream[i]);
            }
            // Dummy authentication tag calculation (can be replaced with actual GCM logic)
            for (int i = 0; i < src.length; i++) {
                authenticationTag[i % BLOCK_SIZE] ^= src[srcoff + i];
            }
        } catch (Exception e) {
            log.log(1, "Failed to encrypt GCM block", e);
        }
    }

    private void incrementCounterBlock() {
        for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
            if (++counter[i] != 0) {
                break;
            }
        }
    }

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    public byte[] getAuthTag() {
        return Arrays.copyOf(authenticationTag, authenticationTag.length);
    }
}
package com.github.vkennke.jpgp2fa;

public class JPGP2FAException extends RuntimeException {

    public JPGP2FAException(Throwable cause) {
        super(cause);
    }

    public JPGP2FAException(String message) {
        super(message);
    }
}

package com.blackducksoftware.integration.fortify.parser;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.io.InputStream;

/**
 * Common utilities class.
 */
public final class BlackDuckUtils {

    private BlackDuckUtils() {
    }

    public static String cleanName(String name) {
        return (name == null) ? null : name.replace(" ", "");
    }

    public static String getMD5ForStream(final InputStream is) throws IOException {
        try {
            return DigestUtils.md5Hex(is);
        } catch (IOException e) {
            throw new IOException("Unable to generate MD5 for stream!", e);
        }
    }
}

package com.blackducksoftware.integration.fortify.parser;

import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Common utilities class.
 */
public final class BlackDuckUtils {
    private static Logger LOG = LoggerFactory.getLogger(BlackDuckUtils.class);

    private BlackDuckUtils() {
    }

    public static String cleanName(final String name) {
        return name == null ? null : name.replace(" ", "");
    }

    public static String getMD5ForStream(final InputStream is) throws IOException {
        try {
            return DigestUtils.md5Hex(is);
        } catch (final IOException e) {
            throw new IOException("Unable to generate MD5 for stream!", e);
        }
    }

    public static Date convertToDate(final String strDateValue) {
        if (strDateValue == null) {
            return null;
        }
        final String trimmedDate = strDateValue.trim();
        if (trimmedDate.isEmpty()) {
            return null;
        }
        // final DateTimeFormatter dateTimeFormatter = getDateFormat(trimmedDate);
        try {
            final LocalDate localDate = LocalDate.parse(trimmedDate, DateTimeFormatter.ofPattern("yyyy-MM-dd"));
            return Date.from(localDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
        } catch (final Exception e) {
            LOG.error(
                    String.format("Date string %s cannot be parsed to date and value will be ignored. Please make sure date format is yyyy-MM-dd", trimmedDate),
                    e);
            return null;
        }
    }

    public static Date convertToDateTime(final String strDateValue) {
        if (strDateValue == null) {
            return null;
        }
        final String trimmedDate = strDateValue.trim();
        if (trimmedDate.isEmpty()) {
            return null;
        }

        try {
            final LocalDateTime localDateTime = LocalDateTime.parse(trimmedDate.substring(1, trimmedDate.length() - 1),
                    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
            return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        } catch (final Exception e) {
            LOG.error(
                    String.format("Date string %s cannot be parsed to date and value will be ignored. Please make sure date format is yyyy-MM-dd HH:mm:ss.SSS",
                            trimmedDate),
                    e);
            return null;
        }
    }
}

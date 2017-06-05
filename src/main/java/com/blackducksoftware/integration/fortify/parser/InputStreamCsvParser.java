package com.blackducksoftware.integration.fortify.parser;

import com.fortify.plugin.api.ScanParsingException;
import com.univocity.parsers.common.TextParsingException;
import com.univocity.parsers.csv.CsvParser;
import com.univocity.parsers.csv.CsvParserSettings;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

/**
 * Makes univocity CSV parser closeable.
 */
class InputStreamCsvParser extends CsvParser implements AutoCloseable {
    private final InputStream inputStream;

    public InputStreamCsvParser(final CsvParserSettings settings, final InputStream inputStream) {
        super(settings);
        this.inputStream = inputStream;
    }

    void parse() throws ScanParsingException, IOException {
        try (
            final InputStreamReader reader = new InputStreamReader(inputStream, "UTF-8");
            final BufferedReader bufferedReader = new BufferedReader(reader);
        ) {
            parse(bufferedReader);
        } catch (final UnsupportedEncodingException e) {
            final String message = "Unable to create buffered reader from stream!";
            throw new ScanParsingException(message, e);
        } catch (TextParsingException e) {
            final String message = "CSV parsing error: " + e.getCause().getMessage();
            throw new ScanParsingException(message, e);
        }
    }

    @Override
    public void close() {
        stopParsing();
    }
}

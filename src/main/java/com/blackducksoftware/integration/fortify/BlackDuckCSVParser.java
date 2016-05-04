/**
 * 
 */
package com.blackducksoftware.integration.fortify;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.List;

import org.springframework.util.DigestUtils;

import com.univocity.parsers.common.TextParsingException;
import com.univocity.parsers.common.processor.BeanListProcessor;
import com.univocity.parsers.csv.CsvParser;
import com.univocity.parsers.csv.CsvParserSettings;

/**
 * Uses univocity to parse a stream of CSV data.
 * 
 * 
 * @author akamen
 * 
 */
public class BlackDuckCSVParser {

    private CsvParser csvParser;

    private BeanListProcessor<BlackDuckIssue> rowProcessor;

    private BufferedReader br;

    public BlackDuckCSVParser(InputStream is) throws Exception
    {
        init(is);
    }

    /**
     * Sets up the Univocity parser, perform a parse of the first row to determine if this is a valid file
     * if not, throws an exception.
     * 
     * @param is
     * @throws Exception
     */
    private void init(InputStream is) throws Exception {
        // Create the Black Duck Row Processor
        rowProcessor =
                new BeanListProcessor<BlackDuckIssue>(BlackDuckIssue.class);

        // Hub dates follow a particular pattern, set that here
        // rowProcessor.convertFields(Conversions.toDate("dd/MM/yyyy"));

        CsvParserSettings parserSettings = new CsvParserSettings();
        parserSettings.setRowProcessor(rowProcessor);
        parserSettings.setHeaderExtractionEnabled(true);

        csvParser = new CsvParser(parserSettings);

        try {
            br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            csvParser.parse(br);

            String[] headers = rowProcessor.getHeaders();

            validateHeaders(headers);

        } catch (UnsupportedEncodingException e) {
            throw new Exception("Unable to create buffered reader from stream!");
        } catch (TextParsingException tpe)
        {

            BlackDuckLogger.logError("CSV parsing error: " + tpe.getCause().getMessage());
        }

    }

    /**
     * Gets an MD5 for the file. Deliberately using Spring's built-in library
     * over Apache for reduced classpath complexity.
     * 
     * @param is
     * @return
     * @throws Exception
     */
    public static String getMD5ForStream(InputStream is) throws Exception
    {
        String sha1code;
        try
        {
            sha1code = DigestUtils.md5DigestAsHex(is);
            if (sha1code == null) {
                throw new Exception("DigestUtils was unable to generate MD5");
            }
        } catch (Exception e)
        {
            throw new Exception("Unable to generate MD5 for stream!", e);
        }

        return sha1code;
    }

    /**
     * Validates headers, this is the only way we can really tell if a file is legitimate.
     * Otherwise anything could realistically pass for a CSV file.
     * 
     * We check to see how many headers we get.
     * 
     * @param headers
     * @throws Exception
     */
    private void validateHeaders(String[] headers) throws Exception {
        if (headers == null) {
            BlackDuckLogger.logError("Empty headers");
            throw new Exception(BlackDuckConstants.BLACKDUCK_INVALID_CSV);
        }
        if (headers.length != BlackDuckConstants.BLACKDUCK_HEADER_COUNT) {
            BlackDuckLogger.logError("Header count mismatch, header count: " + headers.length);
            throw new Exception(BlackDuckConstants.BLACKDUCK_INVALID_CSV);
        }
    }

    /**
     * Parses the file and returns a list of beans.
     * This ends all the parsing operations.
     * 
     * @return
     * @throws Exception
     */
    public List<BlackDuckIssue> getRows() throws Exception
    {
        if (rowProcessor == null) {
            throw new Exception("No row processor detected.");
        }
        List<BlackDuckIssue> beans = rowProcessor.getBeans();
        closeDown();

        return beans;
    }

    private void closeDown()
    {
        csvParser.stopParsing();
        try {
            br.close();
        } catch (IOException e) {
        }
    }
}

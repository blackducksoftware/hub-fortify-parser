package com.blackducksoftware.integration.fortify.parser;

import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.univocity.parsers.common.ParsingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;

/**
 * Custom version of BeanProcessor to handle black duck scan results.
 */
public class BlackDuckCsvRowProcessor extends BlackDuckBeanProcessor {

    private static Logger LOG = LoggerFactory.getLogger(BlackDuckCsvRowProcessor.class);

    private final VulnerabilityHandler vulnerabilityHandler;

    private int rowsProcessed;

    /**
     * Constructor.
     * @param vulnerabilityHandler VulnerabilityHandler implementation to provide processor the way to pass parsed
     * vulnerabilities from parser to SSC.
     */
    public BlackDuckCsvRowProcessor(VulnerabilityHandler vulnerabilityHandler) {
        super();
        this.vulnerabilityHandler = vulnerabilityHandler;
    }

    /**
     * Method is called by framework when new scan file parsing session
     * @param context com.univocity.parsers.common.ParsingContext instanse
     */
    @Override
    public void processStarted(ParsingContext context) {
        super.processStarted(context);
        rowsProcessed = 0;
    }

    /**
     *
     * @param blackDuckIssue
     * @param context
     */
    @Override
    public void beanProcessed(BlackDuckIssue blackDuckIssue, ParsingContext context) {
        if (rowsProcessed == 0) {
            validateHeaders(context.headers());
        }
        buildVulnerability(blackDuckIssue, vulnerabilityHandler);
        rowsProcessed++;
    }

    private void validateHeaders(String[] headers) {
        if (headers == null) {
            LOG.error("Empty headers");
            throw new BlackDuckParsingException(BlackDuckConstants.BLACKDUCK_INVALID_CSV);
        }
        if (headers.length != BlackDuckConstants.BLACKDUCK_HEADER_COUNT) {
            LOG.error("Header count mismatch, header count: " + headers.length);
            throw new BlackDuckParsingException(BlackDuckConstants.BLACKDUCK_INVALID_CSV);
        }
    }

    private void buildVulnerability(BlackDuckIssue blackDuckIssue, VulnerabilityHandler vulnerabilityHandler) {
        // Start building new vulnerability and obtain builder object
        final StaticVulnerabilityBuilder vulnerabilityBuilder = vulnerabilityHandler.startStaticVulnerability(blackDuckIssue.getId());

        // Standard attributes values
        vulnerabilityBuilder.setAnalyzer(BlackDuckConstants.PENTEST_ANALYZER_TYPE);
        vulnerabilityBuilder.setCategory(BlackDuckConstants.ISSUE_CATEGORY);
        vulnerabilityBuilder.setSubCategory("");
        vulnerabilityBuilder.setFileName(blackDuckIssue.getProjectName() + ":" + blackDuckIssue.getVersion());
        vulnerabilityBuilder.setConfidence((blackDuckIssue.getBaseScore() == null) ? 0 : blackDuckIssue.getBaseScore().floatValue());
        vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Critical);
        vulnerabilityBuilder.setLikelihood(BlackDuckConstants.HIGH_LIKELIHOOD);
        vulnerabilityBuilder.setAccuracy(BlackDuckConstants.HIGH_ACCURACY);
        vulnerabilityBuilder.setEngineType(BlackDuckConstants.BLACKDUCK_ENGINE_TYPE);
        vulnerabilityBuilder.setImpact((blackDuckIssue.getImpact() == null) ? 0 : blackDuckIssue.getImpact().floatValue());
        vulnerabilityBuilder.setSeverity((blackDuckIssue.getExploitability() == null) ? 0 : blackDuckIssue.getExploitability().floatValue());
        // Blackduck specific attributes values
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.PROJECT_ID, blackDuckIssue.getProjectId());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.PROJECT_NAME, blackDuckIssue.getProjectName());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.VERSION_ID, blackDuckIssue.getVersionId());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.PROJECT_VERSION, blackDuckIssue.getVersion());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.CHANNEL_VERSION_ID, blackDuckIssue.getChannelVersionId());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.CHANNEL_VERSION_ORIGIN, blackDuckIssue.getChannelVersionOrigin());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.CHANNEL_VERSION_ORIGIN_ID, blackDuckIssue.getChannelVersionOriginId());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.CHANNEL_VERSION_ORIGIN_NAME, blackDuckIssue.getChannelVersionOriginName());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.VULNERABILITY_ID, blackDuckIssue.getVulnerabilityId());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.DESCRIPTION, blackDuckIssue.getDescription());
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.PUBLISHED_ON, convertToDate(blackDuckIssue.getPublishedOn()));
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.UPDATED_ON, convertToDate(blackDuckIssue.getUpdatedOn()));
        vulnerabilityBuilder.setDecimalCustomAttributeValue(BlackDuckVulnerabilityAttribute.BASE_SCORE, blackDuckIssue.getBaseScore());
        vulnerabilityBuilder.setDecimalCustomAttributeValue(BlackDuckVulnerabilityAttribute.EXPLOITABILITY, blackDuckIssue.getExploitability());
        vulnerabilityBuilder.setDecimalCustomAttributeValue(BlackDuckVulnerabilityAttribute.IMPACT, blackDuckIssue.getImpact());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.VULNERABILITY_SOURCE, blackDuckIssue.getVulnerabilitySource());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.REMEDIATION_STATUS, blackDuckIssue.getRemediationStatus());
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.REMEDIATION_TARGET_DATE, convertToDate(blackDuckIssue.getRemediationTargetDate()));
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.REMEDIATION_ACTUAL_DATE, convertToDate(blackDuckIssue.getRemediationActualDate()));
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.REMEDIATION_COMMENT, blackDuckIssue.getRemediationComment());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.URL, blackDuckIssue.getURL());

        vulnerabilityBuilder.completeVulnerability();
    }

    private Date convertToDate(String strDateValue) {
        if (strDateValue == null) {
            return null;
        }
        final String trimmedDate = strDateValue.trim();
        if (trimmedDate.isEmpty()) {
            return null;
        }
        final DateTimeFormatter dateTimeFormatter = getDateFormat(trimmedDate);
        try {
            final LocalDate localDate = LocalDate.parse(trimmedDate, dateTimeFormatter);
            return Date.from(localDate.atStartOfDay(ZoneId. systemDefault()).toInstant());
        } catch (Exception e) {
            LOG.error(String.format("Date string %s cannot be parsed to date and value will be ignored. Please make sure date format is either M/d/yy or M/d/yyyy", trimmedDate), e);
            return null;
        }
    }

    private DateTimeFormatter getDateFormat(String dateStr) {
        /*
        Date parsing logic is quite simple here. Date are expected either in M/d/yyyy or M/d/yy format.
        Dates in all other formats will be parsed
         */
        int lastSlashPos = dateStr.lastIndexOf("/");
        if (dateStr.length() - lastSlashPos - 1 > 2) {
            return DateTimeFormatter.ofPattern("M/d/yyyy");
        } else {
            return DateTimeFormatter.ofPattern("M/d/yy");
        }
    }

    @Override
    public void processEnded(ParsingContext context) {
        super.processEnded(context);
    }


    private static class BlackDuckParsingException extends RuntimeException {

        public BlackDuckParsingException(String message) {
            super(message);
        }

    }
}

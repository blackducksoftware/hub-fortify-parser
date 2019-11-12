package com.blackducksoftware.integration.fortify.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.univocity.parsers.common.ParsingContext;

/**
 * Custom version of BeanProcessor to handle black duck scan results.
 */
public class BlackDuckCsvRowProcessor extends BlackDuckBeanProcessor {

    private static Logger LOG = LoggerFactory.getLogger(BlackDuckCsvRowProcessor.class);

    private final VulnerabilityHandler vulnerabilityHandler;

    private int rowsProcessed;

    /**
     * Constructor.
     *
     * @param vulnerabilityHandler
     *            VulnerabilityHandler implementation to provide processor the way to pass parsed
     *            vulnerabilities from parser to SSC.
     */
    public BlackDuckCsvRowProcessor(final VulnerabilityHandler vulnerabilityHandler) {
        super();
        this.vulnerabilityHandler = vulnerabilityHandler;
    }

    /**
     * Method is called by framework when new scan file parsing session
     *
     * @param context
     *            com.univocity.parsers.common.ParsingContext instanse
     */
    @Override
    public void processStarted(final ParsingContext context) {
        super.processStarted(context);
        rowsProcessed = 0;
    }

    /**
     *
     * @param blackDuckIssue
     * @param context
     */
    @Override
    public void beanProcessed(final BlackDuckIssue blackDuckIssue, final ParsingContext context) {
        if (rowsProcessed == 0) {
            validateHeaders(context.headers());
        }
        buildVulnerability(blackDuckIssue, vulnerabilityHandler);
        rowsProcessed++;
    }

    private void validateHeaders(final String[] headers) {
        if (headers == null) {
            LOG.error("Empty headers");
            throw new BlackDuckParsingException(BlackDuckConstants.BLACKDUCK_INVALID_CSV);
        }
        if (headers.length != BlackDuckConstants.BLACKDUCK_HEADER_COUNT) {
            LOG.error("Header count mismatch, header count: " + headers.length);
            throw new BlackDuckParsingException(BlackDuckConstants.BLACKDUCK_INVALID_CSV);
        }
    }

    private void buildVulnerability(final BlackDuckIssue blackDuckIssue, final VulnerabilityHandler vulnerabilityHandler) {
        // Start building new vulnerability and obtain builder object
        final StaticVulnerabilityBuilder vulnerabilityBuilder = vulnerabilityHandler.startStaticVulnerability(blackDuckIssue.getId());

        // Standard attributes values
        vulnerabilityBuilder.setAnalyzer(BlackDuckConstants.PENTEST_ANALYZER_TYPE);
        vulnerabilityBuilder.setCategory(BlackDuckConstants.ISSUE_CATEGORY);
        vulnerabilityBuilder.setSubCategory("");
        vulnerabilityBuilder.setFileName(blackDuckIssue.getComponentName() + ":" + blackDuckIssue.getVersion());
        vulnerabilityBuilder.setConfidence((blackDuckIssue.getBaseScore() == null) ? 0 : blackDuckIssue.getBaseScore().floatValue());
        switch (blackDuckIssue.getSeverity()) {
        case "HIGH":
            vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.High);
            break;
        case "MEDIUM":
            vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Medium);
            break;
        case "LOW":
            vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Low);
            break;
        default:
            vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Critical);
            break;
        }
        vulnerabilityBuilder.setLikelihood(BlackDuckConstants.HIGH_LIKELIHOOD);
        vulnerabilityBuilder.setAccuracy(BlackDuckConstants.HIGH_ACCURACY);
        vulnerabilityBuilder.setEngineType(BlackDuckConstants.BLACKDUCK_ENGINE_TYPE);
        vulnerabilityBuilder.setImpact((blackDuckIssue.getImpact() == null) ? 0 : blackDuckIssue.getImpact().floatValue());
        vulnerabilityBuilder.setSeverity((blackDuckIssue.getExploitability() == null) ? 0 : blackDuckIssue.getExploitability().floatValue());
        // Blackduck specific attributes values
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.PROJECT_NAME, blackDuckIssue.getProjectName());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.PROJECT_VERSION, blackDuckIssue.getProjectVersion());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.CHANNEL_VERSION_ORIGIN, blackDuckIssue.getChannelVersionOrigin());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.CHANNEL_VERSION_ORIGIN_ID,
                blackDuckIssue.getChannelVersionOriginId());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.CHANNEL_VERSION_ORIGIN_NAME,
                blackDuckIssue.getChannelVersionOriginName());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.VULNERABILITY_ID, blackDuckIssue.getVulnerabilityId());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.DESCRIPTION, blackDuckIssue.getDescription());
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.PUBLISHED_ON,
                BlackDuckUtils.convertToDate(blackDuckIssue.getPublishedOn()));
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.UPDATED_ON,
                BlackDuckUtils.convertToDate(blackDuckIssue.getUpdatedOn()));
        vulnerabilityBuilder.setDecimalCustomAttributeValue(BlackDuckVulnerabilityAttribute.BASE_SCORE, blackDuckIssue.getBaseScore());
        vulnerabilityBuilder.setDecimalCustomAttributeValue(BlackDuckVulnerabilityAttribute.EXPLOITABILITY, blackDuckIssue.getExploitability());
        vulnerabilityBuilder.setDecimalCustomAttributeValue(BlackDuckVulnerabilityAttribute.IMPACT, blackDuckIssue.getImpact());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.VULNERABILITY_SOURCE, blackDuckIssue.getVulnerabilitySource());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.HUB_VULNERABILITY_URL, blackDuckIssue.getHubVulnerabilityUrl());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.REMEDIATION_STATUS, blackDuckIssue.getRemediationStatus());
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.REMEDIATION_TARGET_DATE,
                BlackDuckUtils.convertToDate(blackDuckIssue.getRemediationTargetDate()));
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.REMEDIATION_ACTUAL_DATE,
                BlackDuckUtils.convertToDate(blackDuckIssue.getRemediationActualDate()));
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.REMEDIATION_COMMENT, blackDuckIssue.getRemediationComment());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.URL, blackDuckIssue.getURL());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.COMPONENT_NAME, blackDuckIssue.getComponentName());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.COMPONENT_VERSION, blackDuckIssue.getVersion());
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.UPGRADE_VERSION, blackDuckIssue.getUpgradeVersion());
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.UPGRADE_RELEASED_ON,
                BlackDuckUtils.convertToDate(blackDuckIssue.getUpgradeVersionReleasedOn()));
        vulnerabilityBuilder.setStringCustomAttributeValue(BlackDuckVulnerabilityAttribute.LATEST_VERSION, blackDuckIssue.getLatestVersion());
        vulnerabilityBuilder.setDateCustomAttributeValue(BlackDuckVulnerabilityAttribute.LATEST_RELEASED_ON,
                BlackDuckUtils.convertToDate(blackDuckIssue.getLatestVersionReleasedOn()));
        vulnerabilityBuilder.completeVulnerability();
    }

    @Override
    public void processEnded(final ParsingContext context) {
        super.processEnded(context);
    }

    private static class BlackDuckParsingException extends RuntimeException {

        public BlackDuckParsingException(final String message) {
            super(message);
        }

    }
}

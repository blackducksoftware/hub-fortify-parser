/**
 * 
 */
package com.blackducksoftware.integration.fortify;

/**
 * This is just a wrapper around the System out for now.
 * Not sure yet how Fortify handles logging.
 * 
 * @author akamen
 * 
 */
public class BlackDuckLogger {

    public static void logInfo(String msg)
    {
        System.out.println(msg);
    }

    public static void logError(String msg)
    {
        System.err.println(msg);
    }

    public static void logError(String msg, Exception e)
    {
        System.err.println(msg + ":" + e.getMessage());
    }

}

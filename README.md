# Hub Fortify integration

Simple parser for Hub Fortify 4.40 

# Deployment and Build

1.  Please update the pom file to point to an internal repo containing the provided dependencies
2.  Run mvn package
3.  Copy the /target/ jar file and the target/lib/compile contents into the fortify /WEB-INF/lib directory.
4.  Restart Fortify SSC


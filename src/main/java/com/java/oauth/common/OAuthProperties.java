package com.java.oauth.common;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class OAuthProperties {

  public static final String DEFAULT_OAUTH_PROPERTIES_FILE_NAME = "oauth.properties";

  /** The OAuth 2.0 Client ID */
  private String clientId;

  /** The OAuth 2.0 Client Secret */
  private String clientSecret;

  /** The Google APIs scopes to access */
  private String scopes;

  public OAuthProperties() throws IOException {
    this(OAuthProperties.class.getResourceAsStream(DEFAULT_OAUTH_PROPERTIES_FILE_NAME));
  }

  public OAuthProperties(InputStream propertiesFile) throws IOException {
    Properties oauthProperties = new Properties();
    oauthProperties.load(propertiesFile);
    clientId = oauthProperties.getProperty("clientId");
    clientSecret = oauthProperties.getProperty("clientSecret");
    scopes = oauthProperties.getProperty("scopes");
    if ((clientId == null) || (clientSecret == null) || (scopes == null)) {
      throw new OAuthPropertiesFormatException();
    }
  }

  public String getClientId() {
    return clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public String getScopesAsString() {
    return scopes;
  }

  @SuppressWarnings("serial")
  public class OAuthPropertiesFormatException extends RuntimeException {
  }

}

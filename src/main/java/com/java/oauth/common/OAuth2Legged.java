package com.java.oauth.common;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.analytics.AnalyticsScopes;


public class OAuth2Legged {
	
	private static final Logger logger = Logger.getLogger(OAuth2Legged.class);
	
	private static final String REDIRECT_URI = "/dashboard";
	private static final String DEFAULT_CREDENTIALS_PROPERTIES_FILE_NAME = "/properties/token.properties";
	private static final String DATA_STORE_DIR = "/properties";
	private static final String CLIENT_SECRET_FILE = "/properties/client-secrets.json";

	/**
	 * Exchanges the given code for an exchange and a refresh token.
	 *
	 * @param code
	 *            The code gotten back from the authorization service
	 * @param currentUrl
	 *            The URL of the callback
	 * @param oauthProperties
	 *            The object containing the OAuth configuration
	 * @return The object containing both an access and refresh token
	 * @throws IOException
	 */
	public Credential exchangeCodeForAccessAndRefreshTokens(String code,
			String currentUrl) throws IOException {
		
		OAuthProperties oauthProperties = new OAuthProperties();

		HttpTransport netTransport = new NetHttpTransport();
		JsonFactory jsonFactory = new JacksonFactory();

		TokenResponse savedTokenResponse = getSavedTokenResponse();
		
		if (savedTokenResponse == null) {
			
			//get the access token and refresh token using the authorization code
			GoogleTokenResponse token = new GoogleAuthorizationCodeTokenRequest(
					netTransport, jsonFactory, oauthProperties.getClientId(),
					oauthProperties.getClientSecret(), code, currentUrl).execute();
			
			//save it to property file
			saveToPropertyFile(token);
		}
		
		savedTokenResponse = getSavedTokenResponse();
		Credential credential = buildCredentialFromSavedToken(savedTokenResponse);

		//save the newly created token
		TokenResponse newGeneratedToken = new TokenResponse();
		String accessToken = credential.getAccessToken();
		String refreshToken = credential.getRefreshToken();
		newGeneratedToken.setAccessToken(accessToken);
		newGeneratedToken.setRefreshToken(refreshToken);
		saveToPropertyFile(newGeneratedToken);
		
		logger.info("exchangeCodeForAccessAndRefreshTokens(): Request for credential completed. ");
		
		return credential;
	}
	
	/**
	 * Construct the OAuth code callback handler URL.
	 *
	 * @param req
	 *            the HttpRequest object
	 * @return The constructed request's URL
	 */
	public String getOAuthCodeCallbackHandlerUrl(HttpServletRequest request) {
		String scheme = request.getScheme() + "://";
		String serverName = request.getServerName();
		String serverPort = (request.getServerPort() == 80) ? "" : ":"
				+ request.getServerPort();
		String contextPath = request.getContextPath();
		String servletPath = REDIRECT_URI;
		String pathInfo = (request.getPathInfo() == null) ? "" : request.getPathInfo();

		String callBackUrl = scheme + serverName + serverPort + contextPath + servletPath
				+ pathInfo;
		
		logger.info("getOAuthCodeCallbackHandlerUrl(): Callback URL:" + callBackUrl);
		
		return callBackUrl;
		
	}
	
	public String getAuthenticationUrl(HttpServletRequest request) throws IOException, GeneralSecurityException {
		
		InputStream dataStoreResource = OAuth2Legged.class.getResourceAsStream(DATA_STORE_DIR);
		File dataStoreDir = new File(DATA_STORE_DIR);
		FileUtils.copyInputStreamToFile(dataStoreResource, dataStoreDir);
		
		FileDataStoreFactory dataStoreFactory = new FileDataStoreFactory(dataStoreDir);
		HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
		JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
		
		InputStream inputStreamClientResource = OAuth2Legged.class.getResourceAsStream(CLIENT_SECRET_FILE);
		
		GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(
				JSON_FACTORY,
				new InputStreamReader(inputStreamClientResource));

		// set up authorization code flow
		GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
				httpTransport, JSON_FACTORY, clientSecrets,
				Collections.singleton(AnalyticsScopes.ANALYTICS_READONLY))
				.setDataStoreFactory(dataStoreFactory).setAccessType("offline").setApprovalPrompt("force").build();

		String redirectUri = getOAuthCodeCallbackHandlerUrl(request);

		String url = flow.newAuthorizationUrl().setRedirectUri(redirectUri)
				.build();

		logger.info("getAuthenticationUrl(): Authentication URL:" + url);
		
		return url;
	}
	
	public void saveToPropertyFile(TokenResponse token) {
		Properties prop = new Properties();
		OutputStream output = null;
		
		try {
			
			InputStream inputStream = OAuth2Legged.class.getResourceAsStream(DEFAULT_CREDENTIALS_PROPERTIES_FILE_NAME);
			File file = new File(DEFAULT_CREDENTIALS_PROPERTIES_FILE_NAME);
			FileUtils.copyInputStreamToFile(inputStream, file);
			
			output = new FileOutputStream(file);
			 
			// set the properties value
			prop.setProperty("accessToken", token.getAccessToken());
			prop.setProperty("refreshToken", token.getRefreshToken());
	 
			// save properties to project root folder
			prop.store(output, null);
			
		} catch (FileNotFoundException e) {
			logger.error("saveToPropertyFile(): " + e.fillInStackTrace());
		} catch (IOException e) {
			logger.error("saveToPropertyFile(): " + e.fillInStackTrace());
		}
		
		logger.info("saveToPropertyFile(): Token saved in property file.");
	}
	
	public TokenResponse getSavedTokenResponse() {
		
		TokenResponse token = null;
		Properties prop = new Properties();
		InputStream input = null;
		
		try {
			input = OAuth2Legged.class.getResourceAsStream(DEFAULT_CREDENTIALS_PROPERTIES_FILE_NAME);
		
			// load a properties file
			prop.load(input);
			
			String refreshToken = prop.getProperty("refreshToken");
			String accessToken = prop.getProperty("accessToken");
			token = new TokenResponse();
			token.setRefreshToken(refreshToken);
			token.setAccessToken(accessToken);
			
		} catch (FileNotFoundException e) {
			logger.error("getSavedTokenResponse(): " + e.fillInStackTrace());
		} catch (IOException e) {
			logger.error("getSavedTokenResponse(): " + e.fillInStackTrace());
		}
		
		logger.info("getSavedTokenResponse(): Success request of saved token.");
		 
		return token;
	}
	
	public Credential buildCredentialFromSavedToken(TokenResponse tokenResponse) throws IOException {
		
		InputStream inputStreamClientResource = OAuth2Legged.class.getResourceAsStream(CLIENT_SECRET_FILE);
		
		GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(
				new JacksonFactory(),
				new InputStreamReader(inputStreamClientResource));
			
		GoogleCredential credential = new GoogleCredential.Builder().setTransport(new NetHttpTransport())
        .setJsonFactory(new JacksonFactory())
        .setClientSecrets(clientSecrets)
        .build()
        .setFromTokenResponse(new TokenResponse().setRefreshToken(tokenResponse.getRefreshToken()));
		
		//generate a new access token
		credential.refreshToken();
		
		logger.info("buildCredentialFromSavedToken(): Refresh credential success.");
		
		return credential;
	}
	
}


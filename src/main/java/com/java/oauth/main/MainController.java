package com.java.oauth.main;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.java.oauth.common.OAuth2Legged;

@Controller
public class MainController {
	
	private static final Logger logger = Logger.getLogger(OAuth2Legged.class);
	
	/**
	 * Simply selects the root view to render by returning its name.
	 */
	@RequestMapping(value = "/main", method = RequestMethod.GET)
	public String mainEntry(ModelAndView model, HttpServletRequest request) {
		
		
		try {
			OAuth2Legged oauth2 = new OAuth2Legged();
			TokenResponse tokenResponse = oauth2.getSavedTokenResponse();
			Credential credentials = oauth2.buildCredentialFromSavedToken(tokenResponse);
			
			logger.info("Got the credentials:" + credentials);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return "";
	}
}

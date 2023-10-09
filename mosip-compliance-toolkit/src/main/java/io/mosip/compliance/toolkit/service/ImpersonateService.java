package io.mosip.compliance.toolkit.service;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.core.authmanager.authadapter.model.AuthUserDetails;
import io.mosip.kernel.openid.bridge.api.constants.Constants;
import io.mosip.kernel.openid.bridge.api.constants.Errors;
import io.mosip.kernel.openid.bridge.api.exception.ServiceException;
import io.mosip.kernel.openid.bridge.dto.AccessTokenResponse;
import io.mosip.kernel.openid.bridge.dto.AccessTokenResponseDTO;
import io.mosip.kernel.openid.bridge.dto.IAMErrorResponseDto;

@Component
public class ImpersonateService {

	private static final String REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

	@Autowired
	private RestTemplate restTemplate;

	@Value("${mosip.iam.module.clientid}")
	private String clientID;

	@Value("${mosip.iam.module.clientsecret}")
	private String clientSecret;

	@Value("${mosip.iam.module.admin_realm_id}")
	private String realmID;

	@Value("${mosip.iam.token_endpoint}")
	private String tokenEndpoint;

	@Value("${auth.token.header:Authorization}")
	private String authTokenHeader;

	@Value("${auth.jwt.expiry:1800000}")
	private int authTokenExpiry;

	@Value("${mosip.security.secure-cookie:false}")
	private boolean isSecureCookie;

	@Value("#{'${auth.allowed.urls}'.split(',')}")
	private List<String> allowedUrls;

	@Autowired
	private ObjectMapper objectMapper;

	public void impersonatePartner(String partnerId, String redirectUrl, HttpServletResponse res, String state)
			throws IOException {
		AuthUserDetails authUserDetails = (AuthUserDetails) SecurityContextHolder.getContext().getAuthentication()
				.getPrincipal();
		String subjectToken = authUserDetails.getToken();
		String requestSubject = partnerId;

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add(Constants.GRANT_TYPE, GRANT_TYPE_TOKEN_EXCHANGE);
		map.add(Constants.CLIENT_ID, clientID);
		map.add(Constants.CLIENT_SECRET, clientSecret);
		map.add("subject_token", subjectToken);
		map.add("requested_token_type", REQUESTED_TOKEN_TYPE);
		map.add("requested_subject", requestSubject);

		Map<String, String> pathParam = new HashMap<>();
		pathParam.put("realmId", realmID);

		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(tokenEndpoint);
		uriBuilder.queryParam(Constants.STATE, state);
		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
		ResponseEntity<String> responseEntity = null;
		try {
			responseEntity = restTemplate.exchange(uriBuilder.buildAndExpand(pathParam).toUriString(), HttpMethod.POST,
					entity, String.class);

		} catch (HttpClientErrorException | HttpServerErrorException e) {
			IAMErrorResponseDto keycloakErrorResponseDto = parseKeyClockErrorResponse(e);

			throw new ServiceException(Errors.ACESSTOKEN_EXCEPTION.getErrorCode(),
					Errors.ACESSTOKEN_EXCEPTION.getErrorMessage() + Constants.WHITESPACE
							+ keycloakErrorResponseDto.getError_description(),
					e);
		}
		AccessTokenResponse accessTokenResponse = null;
		try {
			accessTokenResponse = objectMapper.readValue(responseEntity.getBody(), AccessTokenResponse.class);
		} catch (IOException exception) {
			throw new ServiceException(Errors.RESPONSE_PARSE_ERROR.getErrorCode(),
					Errors.RESPONSE_PARSE_ERROR.getErrorMessage() + Constants.WHITESPACE + exception.getMessage(),
					exception);
		}
		AccessTokenResponseDTO accessTokenResponseDTO = new AccessTokenResponseDTO();
		accessTokenResponseDTO.setAccessToken(accessTokenResponse.getAccess_token());
		accessTokenResponseDTO.setExpiresIn(accessTokenResponse.getExpires_in());
		accessTokenResponseDTO.setIdToken(accessTokenResponse.getId_token());

		String accessToken = accessTokenResponseDTO.getAccessToken();
		Cookie stateCookie = new Cookie("state", state);
		stateCookie.setHttpOnly(true);
		stateCookie.setSecure(true);
		stateCookie.setPath("/");
		res.addCookie(stateCookie);
		
		final Cookie cookie = new Cookie(authTokenHeader, accessToken);
		cookie.setMaxAge(authTokenExpiry);
		cookie.setHttpOnly(true);
		cookie.setSecure(isSecureCookie);
		cookie.setPath("/");
		res.addCookie(cookie);
		
		res.setStatus(302);
		redirectUrl = redirectUrl + "?impersonateMode=readOnly";
		res.sendRedirect(redirectUrl);
	}

	public boolean matchesAllowedUrls(String url) {
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean hasMatch = allowedUrls.contains(url.contains("#") ? url.split("#")[0] : url);
		if (!hasMatch) {
			hasMatch = allowedUrls.stream().filter(pattern -> antPathMatcher.isPattern(pattern))
					.anyMatch(pattern -> antPathMatcher.match(pattern, url));
		}
		return hasMatch;
	}

	private IAMErrorResponseDto parseKeyClockErrorResponse(HttpStatusCodeException exception) {
		IAMErrorResponseDto keycloakErrorResponseDto = null;
		try {
			keycloakErrorResponseDto = objectMapper.readValue(exception.getResponseBodyAsString(),
					IAMErrorResponseDto.class);

		} catch (IOException e) {
			throw new ServiceException(Errors.RESPONSE_PARSE_ERROR.getErrorCode(),
					Errors.RESPONSE_PARSE_ERROR.getErrorMessage() + Constants.WHITESPACE + e.getMessage());
		}
		return keycloakErrorResponseDto;
	}

}

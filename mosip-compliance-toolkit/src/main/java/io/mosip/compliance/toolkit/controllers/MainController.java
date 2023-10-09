package io.mosip.compliance.toolkit.controllers;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.compliance.toolkit.constants.PartnerTypes;
import io.mosip.compliance.toolkit.service.ImpersonateService;
import io.mosip.kernel.core.authmanager.authadapter.model.AuthUserDetails;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.openid.bridge.api.constants.Errors;
import io.mosip.kernel.openid.bridge.api.exception.ServiceException;

@RestController
public class MainController {

	@Value("${mosip.toolkit.sbi.ports}")
	private String sbiPorts;

	@Value("${mosip.toolkit.documentupload.allowed.file.type}")
	private String allowedFileTypes;

	@Value("${mosip.toolkit.documentupload.allowed.file.nameLength}")
	private String allowedFileNameLegth;

	@Value("${mosip.toolkit.documentupload.allowed.file.size}")
	private String allowedFileSize;

	@Value("${mosip.toolkit.sbi.timeout}")
	private String sbiTimeout;

	@Value("${mosip.toolkit.sbi.keyrotation.iterations}")
	private String keyRotationIterations;

	@Value("${mosip.toolkit.languages.rtl}")
	private String rtlLanguages;

	@Value("${mosip.service.datashare.incorrect.partner.id}")
	private String incorrectPartnerId;

	@Value("${mosip.service.abis.partner.type}")
	private String abisPartnerType;

	@Value("${mosip.toolkit.roles.impersonate}")
	private String impersonatePartnerRole;

	@Autowired
	private ImpersonateService impersonateService;

	private AuthUserDetails authUserDetails() {
		return (AuthUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	}

	private boolean isAbisPartner() {
		boolean flag = false;
		String authorities = authUserDetails().getAuthorities().toString();
		String partnerType = PartnerTypes.ABIS.getCode();
		if (authorities.contains(partnerType)) {
			flag = true;
		}
		return flag;
	}

	@ResponseFilter
	@GetMapping("/configs")
	public ResponseWrapper<Map<String, String>> getConfigValues() {
		ResponseWrapper<Map<String, String>> responseWrapper = new ResponseWrapper<>();
		Map<String, String> configMap = new HashMap<String, String>();
		configMap.put("sbiPorts", sbiPorts);
		configMap.put("sbiTimeout", sbiTimeout);
		configMap.put("allowedFileTypes", allowedFileTypes);
		configMap.put("allowedFileNameLegth", allowedFileNameLegth);
		configMap.put("allowedFileSize", allowedFileSize);
		configMap.put("keyRotationIterations", keyRotationIterations);
		configMap.put("rtlLanguages", rtlLanguages);
		configMap.put("incorrectPartnerId", incorrectPartnerId);
		configMap.put("impersonatePartnerRole", impersonatePartnerRole);
		if (isAbisPartner()) {
			configMap.put("abisPartnerType", abisPartnerType);
		} else {
			configMap.put("abisPartnerType", "");
		}
		responseWrapper.setResponse(configMap);
		return responseWrapper;
	}

	@PreAuthorize("hasAnyRole(@authorizedRoles.getImpersonate())")
	@GetMapping(value = "/impersonatePartner/{partnerId}/{redirectURI}")
	public void impersonatePartner(@CookieValue(name = "state", required = false) String state,
			@PathVariable("partnerId") String partnerId, @PathVariable("redirectURI") String redirectURI,
			@RequestParam(name = "state", required = false) String stateParam, HttpServletRequest req,
			HttpServletResponse res) throws IOException {
		String redirectUrl = new String(Base64.decodeBase64(redirectURI.getBytes()));
		boolean matchesAllowedUrls = impersonateService.matchesAllowedUrls(redirectUrl);
		if (!matchesAllowedUrls) {
			throw new ServiceException(Errors.ALLOWED_URL_EXCEPTION.getErrorCode(),
					Errors.ALLOWED_URL_EXCEPTION.getErrorMessage());
		}
		String stateValue = EmptyCheckUtils.isNullEmpty(state) ? stateParam : state;
		if (EmptyCheckUtils.isNullEmpty(stateValue)) {
			throw new ServiceException(Errors.STATE_NULL_EXCEPTION.getErrorCode(),
					Errors.STATE_NULL_EXCEPTION.getErrorMessage());
		}

		// there is no UUID.parse method till so using this as alternative
		try {
			if (!UUID.fromString(stateValue).toString().equals(stateValue)) {
				throw new ServiceException(Errors.STATE_NOT_UUID_EXCEPTION.getErrorCode(),
						Errors.STATE_NOT_UUID_EXCEPTION.getErrorMessage());
			}
		} catch (IllegalArgumentException exception) {
			throw new ServiceException(Errors.STATE_NOT_UUID_EXCEPTION.getErrorCode(),
					Errors.STATE_NOT_UUID_EXCEPTION.getErrorMessage());
		}
		try {
			impersonateService.impersonatePartner(partnerId, redirectUrl, res, stateValue);
		} catch (ServiceException e) {
			ExceptionUtils.logRootCause(e);
			res.setStatus(401);
			res.sendRedirect(redirectUrl + "?impersonateError=exists&impersonatePartnerId=" + partnerId);
		}
	}

	@ResponseFilter
	@GetMapping("/logoutPartner")
	public void logoutPartner(@RequestParam(name = "redirecturi", required = true) String redirectURI, HttpServletRequest req,
			HttpServletResponse res) throws IOException {
		String redirectUrl = new String(Base64.decodeBase64(redirectURI.getBytes()));
		boolean matchesAllowedUrls = impersonateService.matchesAllowedUrls(redirectUrl);
		if (!matchesAllowedUrls) {
			throw new ServiceException(Errors.ALLOWED_URL_EXCEPTION.getErrorCode(),
					Errors.ALLOWED_URL_EXCEPTION.getErrorMessage());
		}
		final Cookie cookie = new Cookie("Authorization", null);
		cookie.setMaxAge(0);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath("/");
		res.sendRedirect(redirectUrl);
	}

}

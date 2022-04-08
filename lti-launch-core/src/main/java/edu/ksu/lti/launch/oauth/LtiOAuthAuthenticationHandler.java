package edu.ksu.lti.launch.oauth;

import edu.ksu.lti.launch.model.LtiProductFamilyCode;
import edu.ksu.lti.launch.model.LtiRequestParams;
import edu.ksu.lti.launch.security.CanvasInstanceChecker;
import edu.ksu.lti.launch.service.ToolConsumer;
import edu.ksu.lti.launch.service.ToolConsumerService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.OAuthAuthenticationHandler;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This switches out the OAuth principal for a LTI principal. The LTI launch has a principal on it, but that's the
 * service who's sending the user, we switch it out for a principal representing the actual user.
 */
public class LtiOAuthAuthenticationHandler implements OAuthAuthenticationHandler {

    private ToolConsumerService toolConsumerService;

    private boolean checkInstance;

    private boolean validateLti;

    private LtiUserAuthorityFactory userAuthorityFactory = new DefaultLtiUserAuthorityFactory();

    public LtiOAuthAuthenticationHandler(ToolConsumerService toolConsumerService) {
        this.toolConsumerService = toolConsumerService;
    }

    public void setUserAuthorityFactory(LtiUserAuthorityFactory userAuthorityFactory) {
        this.userAuthorityFactory = userAuthorityFactory;
    }

    public void setCheckInstance(boolean checkInstance) {
        this.checkInstance = checkInstance;
    }

    public void setValidateLti(boolean validateLti) {
        this.validateLti = validateLti;
    }

    @Override
    public Authentication createAuthentication(HttpServletRequest request,
                                               ConsumerAuthentication consumerAuthentication,
                                               OAuthAccessProviderToken authToken) {
        if (validateLti) {
            validateBasicLaunchRequest(request);
        }

        String key = consumerAuthentication.getConsumerCredentials().getConsumerKey();
        ToolConsumer consumer = toolConsumerService.getConsumer(key);
        if (consumer == null) {
            throw new InvalidOAuthParametersException("Failed to lookup tool consumer for: " + key);
        }

        String resourceId = request.getParameter(LtiRequestParams.resource_link_id.name());
        // According to the spec context_id is optional.
        String context = request.getParameter(LtiRequestParams.context_id.name());
        if (context == null || context.isEmpty()) {
            context = resourceId;
        }

        HashSet<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_LTI_USER"));
        authorities.addAll(userAuthorityFactory.getLtiUserAuthorities(request.getParameter("roles")));

        String name = null;

        // Depending on the platform the principal is in a different parameter, associate the right principal.
        String toolConsumerInfoProductFamilyCode = request.getParameter(LtiRequestParams.tool_consumer_info_product_family_code.name());
        List<String> supportedProductFamilyCodeList = Stream.of(LtiProductFamilyCode.values())
                .map(Enum::name)
                .collect(Collectors.toList());
        if (supportedProductFamilyCodeList.contains(toolConsumerInfoProductFamilyCode)) {
            LtiProductFamilyCode ltiProductFamilyCode = LtiProductFamilyCode.valueOf(toolConsumerInfoProductFamilyCode);
            if (ltiProductFamilyCode != null) {
                switch (ltiProductFamilyCode) {
                    case canvas:
                        name = request.getParameter(LtiRequestParams.custom_canvas_user_login_id.name());
                        String isRootAdmin = request.getParameter(LtiRequestParams.custom_canvas_user_isrootaccountadmin.name());
                        if (isRootAdmin != null && Boolean.parseBoolean(isRootAdmin)) {
                            authorities.add(new RootAccountAdminAuthority());
                        }
                        break;
                    case moodle:
                        name = request.getParameter(LtiRequestParams.ext_user_username.name());
                        break;
                    default:
                        name = request.getParameter(LtiRequestParams.lis_person_sourcedid.name());
                        break;
                }
            }
        }

        LtiPrincipal principal = new LtiPrincipal(consumer, name, context);
        Authentication authentication = new LtiAuthenticationToken(consumerAuthentication.getConsumerCredentials(), principal, authorities);

        // TODO This shouldn't be in the core code and should be listening for authentication events.
        // We do this after checking authentication as we will present the return URL and don't
        // want people to be able to fake this.
        if (checkInstance) {
            String consumerUrl = consumer.getUrl();
            if (consumerUrl == null || consumerUrl.isEmpty()) {
                throw new IllegalArgumentException("Not URL set on " + key + " but we are set to check instances.");
            }
            CanvasInstanceChecker checker = new CanvasInstanceChecker(consumerUrl, null);
            checker.validateInstance(request);
        }
        return authentication;
    }

    private void validateBasicLaunchRequest(HttpServletRequest request) {
        // We can cope with this being null
        String returnUrl = request.getParameter(LtiRequestParams.launch_presentation_return_url.name());

        {
            String resourceLinkId = request.getParameter(LtiRequestParams.resource_link_id.name());
            if (resourceLinkId == null || resourceLinkId.isEmpty()) {
                // This should be replaced with a factory call so that when we don't have a return URL we have a different exception which displays a message instead.
                throw new InvalidLtiLaunchException("Missing required parameter: resource_link_id", returnUrl);
            }
        }
        {
            String ltiVersion = request.getParameter(LtiRequestParams.lti_version.name());
            if (ltiVersion == null) {
                throw new InvalidLtiLaunchException("Missing required parameter: lti_version", returnUrl);
            }

            if (!"LTI-1p0".equals(ltiVersion)) {
                throw new InvalidLtiLaunchException("Unsupported LTI version: " + ltiVersion, returnUrl);
            }
        }
        {
            String ltiMessageType = request.getParameter(LtiRequestParams.lti_message_type.name());
            if (ltiMessageType == null) {
                throw new InvalidLtiLaunchException("Missing required parameter: lti_message_type", returnUrl);
            }

            if (!"basic-lti-launch-request".equals(ltiMessageType)) {
                throw new InvalidLtiLaunchException("Unsupported lti_message_type: " + ltiMessageType, returnUrl);
            }
        }
    }

}

package net.eisele.glassfish.twofactorsam;

import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static javax.servlet.http.HttpServletResponse.SC_REQUEST_TIMEOUT;
import static net.eisele.glassfish.twofactorsam.util.Utils.getBaseURL;
import static net.eisele.glassfish.twofactorsam.util.Utils.getFullRequestURL;
import static net.eisele.glassfish.twofactorsam.util.Utils.notNull;
import static net.eisele.glassfish.twofactorsam.util.Utils.redirect;
import static net.eisele.glassfish.twofactorsam.util.Utils.sendError;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.eisele.glassfish.twofactorsam.auth.Authenticator;
import net.eisele.glassfish.twofactorsam.auth.MockAuthenticator;
import net.eisele.glassfish.twofactorsam.jaspic.HttpMsgContext;
import net.eisele.glassfish.twofactorsam.jaspic.HttpServerAuthModule;

public class TwoFactorServerAuthModule extends HttpServerAuthModule {
    
    public static final String FORM_ACTION = "/j_security_check";
    public static final String FORM_USERNAME = "j_username";
    public static final String FORM_PASSWORD = "j_password";
    public static final String FORM_TOKEN = "j_token";
    
    private static final String SAVED_URL = "net.eisele.glassfish.twofactorsam.savedurl";
    private static final String SAVED_AUTHENTICATOR = "net.eisele.glassfish.twofactorsam.authenticator";

    @Override
    public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response,
            HttpMsgContext httpMsgContext) throws AuthException {
        
        if (isFirstFactorAuthentication(request)) {
            Authenticator authenticator = new MockAuthenticator();
            
            boolean authenticated = authenticator.authenticateFirstFactor(
                (String) request.getParameter(FORM_USERNAME), 
                (String) request.getParameter(FORM_PASSWORD)
            );
            
            if (authenticated) {
                saveAuthenticator(request, authenticator);
                redirect(response, getBaseURL(request) + "/token.jsp");
                return SEND_CONTINUE;
            } else {
                // TODO: Send to error page
            }
            
        } else if (isSecondFactorAuthentication(request)) {
            
            Authenticator authenticator = getSavedAuthenticator(request);
            if (authenticator == null) {
                // Session expired between sending and entering the token, or user
                // never did first challenge.
                sendError(response, SC_REQUEST_TIMEOUT);
                return SEND_FAILURE;
            }
                
            boolean authenticated = authenticator.authenticateSecondFactor(
                (String) request.getParameter(FORM_TOKEN)
            );
            
            if (authenticated) {
                
                String savedURL = getSavedURL(request);
                if (savedURL == null) {
                    // Session expired between sending and entering password, or user
                    // never went to protected resource. Just direct to the root of the application.
                    savedURL = getBaseURL(request);
                    saveURL(request, savedURL);
                }
                
                // Note: JASPIC doesn't really support authenticating AND redirecting during the same request, 
                // so we need to redirect first and then finally do the authentication with the container on 
                // the request we redirected to.
                redirect(response, savedURL);
                return SEND_CONTINUE;
            } else {
                // TODO: Send to error page
            }
            
        } else if (isOnOriginalURLAfterAuthenticate(request)) {
            
            Authenticator authenticator = getSavedAuthenticator(request);
            
            // Register the authentication data with the container. This will be processed
            // after we return from this method with the SUCCESS status.
            httpMsgContext.registerWithContainer(
                authenticator.getUsername(), 
                authenticator.getRoles()
            );
                
            removeSavedURL(request);
            removeSavedAuthenticator(request);
            
            return SUCCESS;
        }
        
        if (httpMsgContext.isProtected()) {
            saveURL(request);
            redirect(response, getBaseURL(request) + "/login.jsp");
            return SEND_CONTINUE;
        }
        
        // No authentication request and not a protected resource. Just return.
        // TODO: officially we must set the unauthenticated identity here, but just
        // returning also works.
        return SUCCESS;
    }
    
    private boolean isFirstFactorAuthentication(HttpServletRequest request) {
        return 
            request.getServletPath().startsWith(FORM_ACTION) && 
            notNull(request.getParameter(FORM_USERNAME), request.getParameter(FORM_PASSWORD));
    }
    
    private boolean isSecondFactorAuthentication(HttpServletRequest request) {
        return 
            request.getServletPath().startsWith(FORM_ACTION) && 
            notNull(request.getParameter(FORM_TOKEN));
    }
    
    private boolean isOnOriginalURLAfterAuthenticate(HttpServletRequest request) {
        
        String savedURL = getSavedURL(request);
        Authenticator authenticator = getSavedAuthenticator(request);
        
        return 
            notNull(savedURL, authenticator) &&
            authenticator.isAuthenticated() &&
            savedURL.equals(getFullRequestURL(request));
    }
    
    
    private void saveURL(HttpServletRequest request) {
        request.getSession().setAttribute(SAVED_URL, getFullRequestURL(request));
    }
    
    private void saveURL(HttpServletRequest request, String URL) {
        request.getSession().setAttribute(SAVED_URL, URL);
    }
    
    private String getSavedURL(HttpServletRequest request) {
        return (String) request.getSession().getAttribute(SAVED_URL);
    }
    
    private void removeSavedURL(HttpServletRequest request) {
        request.getSession().removeAttribute(SAVED_URL);
    }
    
    private void saveAuthenticator(HttpServletRequest request, Authenticator authenticator) {
        request.getSession().setAttribute(SAVED_AUTHENTICATOR, authenticator);
    }
    
    private Authenticator getSavedAuthenticator(HttpServletRequest request) {
        return (Authenticator) request.getSession().getAttribute(SAVED_AUTHENTICATOR);
    }
    
    private void removeSavedAuthenticator(HttpServletRequest request) {
        request.getSession().removeAttribute(SAVED_AUTHENTICATOR);
    }

}

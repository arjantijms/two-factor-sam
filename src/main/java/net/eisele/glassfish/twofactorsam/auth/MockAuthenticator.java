package net.eisele.glassfish.twofactorsam.auth;

import static java.util.Arrays.asList;

import java.io.Serializable;
import java.util.List;

public class MockAuthenticator implements Serializable, Authenticator {

    private static final long serialVersionUID = 3691108953933314885L;
    
    private String username;
    private List<String> roles;
    private String token;
    private boolean authenticated;

    @Override
    public boolean authenticateFirstFactor(String username, String password) {
        
        if ("foo".equals(username) && "bar".equals(password)) {
            this.username = username;
            token = "abc";
            return true;
        }
        
        return false;
    }
    
    @Override
    public boolean authenticateSecondFactor(String token) {
        
        authenticated = false;
        
        if (this.token.equals(token)) {
            roles = asList("architect", "user");
            authenticated = true;
        }
        
        return authenticated;
    }
    
    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public List<String> getRoles() {
        return roles;
    }
    
    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

}

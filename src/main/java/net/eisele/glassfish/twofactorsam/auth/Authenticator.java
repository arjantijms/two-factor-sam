package net.eisele.glassfish.twofactorsam.auth;

import java.util.List;

public interface Authenticator {

    boolean authenticateFirstFactor(String username, String password);

    boolean authenticateSecondFactor(String token);

    String getUsername();

    List<String> getRoles();
    
    boolean isAuthenticated();

}
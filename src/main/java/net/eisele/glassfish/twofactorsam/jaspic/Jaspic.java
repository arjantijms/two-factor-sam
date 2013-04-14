/*
 * Copyright 2013 OmniFaces.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package net.eisele.glassfish.twofactorsam.jaspic;

import static java.lang.Boolean.TRUE;
import static net.eisele.glassfish.twofactorsam.util.Utils.isEmpty;

import java.io.IOException;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;

/**
 * A set of utility methods for using the JASPIC API
 * 
 * @author Arjan Tijms
 *
 */
public final class Jaspic {
	
	// Key in the MessageInfo Map that when present AND set to true indicated a protected resource is being accessed.
	// When the resource is not protected, GlassFish omits the key altogether. WebSphere does insert the key and sets
	// it to false.
	private static final String IS_MANDATORY = "javax.security.auth.message.MessagePolicy.isMandatory";
	private static final String REGISTER_SESSION = "javax.servlet.http.registerSession";

	private Jaspic() {}
	
	public static void cleanSubject(Subject subject) {
	    if (subject != null) {
            subject.getPrincipals().clear();
        }
	}
	
	public static boolean isRegisterSession(MessageInfo messageInfo) {
		return Boolean.valueOf((String)messageInfo.getMap().get(REGISTER_SESSION));
	}
	
	public static boolean isProtectedResource(MessageInfo messageInfo) {
		return Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY));
	}
	
	@SuppressWarnings("unchecked")
	public static void setRegisterSession(MessageInfo messageInfo) {
		messageInfo.getMap().put("javax.servlet.http.registerSession", TRUE.toString());
		// Legacy fall back for GlassFish 3.1
		messageInfo.getMap().put("com.sun.web.RealmAdapter.register", TRUE.toString());
	}
	
	public static void notifyContainerAboutLogin(Subject clientSubject, CallbackHandler handler, String username, List<String> roles) {
		
	    try {
    		// 1. Create a handler (kind of directive) to add the caller principal (AKA user principal =basically user name, or user id) that
    		// the authenticator provides.
    		//
    		// This will be the name of the principal returned by e.g. HttpServletRequest#getUserPrincipal
	        // 
	        // 2 Execute the handler right away
            //
            // This will typically eventually (NOT right away) add the provided principal in an application server specific way to the JAAS 
	        // Subject.
            // (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.)
    		
	        handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, username) });
    		
    		if (!isEmpty(roles)) {
        		// 1. Create a handler to add the groups (AKA roles) that the authenticator provides. 
        		//
        		// This is what e.g. HttpServletRequest#isUserInRole and @RolesAllowed for
        		//
        		// 2. Execute the handler right away
                //
                // This will typically eventually (NOT right away) add the provided roles in an application server specific way to the JAAS 
    	        // Subject.
                // (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.)
		
    		    handler.handle(new Callback[] { new GroupPrincipalCallback(clientSubject, roles.toArray(new String[roles.size()])) });
    		}
			
		} catch (IOException | UnsupportedCallbackException e) {
			// Should not happen
			throw new IllegalStateException(e);
		}
	}
	
}
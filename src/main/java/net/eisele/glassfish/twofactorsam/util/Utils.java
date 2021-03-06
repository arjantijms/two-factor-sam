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
package net.eisele.glassfish.twofactorsam.util;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An assortment of various utility methods.
 * 
 * @author Arjan Tijms
 *
 */
public final class Utils {
    
    private Utils() {}
	
	public static boolean notNull(Object... objects) {
	    for (Object object : objects) {
            if (object == null) {
                return false;
            }
        }

        return true;
	}
	
	public static String getBaseURL(HttpServletRequest request) {
		String url = request.getRequestURL().toString();
		return url.substring(0, url.length() - request.getRequestURI().length()) + request.getContextPath();
	}
	
	public static void redirect(HttpServletResponse response, String location) {
		try {
			response.sendRedirect(location);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public static void sendError(HttpServletResponse response, int errorCode) {
	    try {
	        response.sendError(errorCode);
	    } catch (IOException e) {
	        // Ignore
	    }
	}
	
	public static String getFullRequestURL(HttpServletRequest request) {
	    StringBuffer queryURL = request.getRequestURL();
	    String queryString = request.getQueryString();
	    
	    return (isEmpty(queryString) ? queryURL : queryURL.append("?" + queryString)).toString();
	}
	
	/**
     * Returns the first non-<code>null</code> object of the argument list, or <code>null</code> if there is no such
     * element.
     * @param <T> The generic object type.
     * @param objects The argument list of objects to be tested for non-<code>null</code>.
     * @return The first non-<code>null</code> object of the argument list, or <code>null</code> if there is no such
     * element.
     */
    @SafeVarargs
    public static <T> T coalesce(T... objects) {
        for (T object : objects) {
            if (object != null) {
                return object;
            }
        }

        return null;
    }
    
    /**
     * Returns true if the given collection is null or is empty.
     *
     * @param collection The collection to be checked on emptiness.
     * @return True if the given collection is null or is empty.
     */
    public static boolean isEmpty(Collection<?> collection) {
        return collection == null || collection.isEmpty();
    }
    
    /**
     * Returns true if the given string is null or is empty.
     *
     * @param string The string to be checked on emptiness.
     * @return True if the given string is null or is empty.
     */
    public static boolean isEmpty(String string) {
        return string == null || string.isEmpty();
    }
    
    /**
     * Returns <code>true</code> if the given object equals one of the given objects.
     * @param <T> The generic object type.
     * @param object The object to be checked if it equals one of the given objects.
     * @param objects The argument list of objects to be tested for equality.
     * @return <code>true</code> if the given object equals one of the given objects.
     */
    @SafeVarargs
    public static <T> boolean isOneOf(T object, T... objects) {
        for (Object other : objects) {
            if (object == null ? other == null : object.equals(other)) {
                return true;
            }
        }

        return false;
    }

}

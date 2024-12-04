package com.telusko.part29springsecex.config;

import com.telusko.part29springsecex.service.JWTService;
import com.telusko.part29springsecex.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
public class JwtFilter extends OncePerRequestFilter {
//OncePerRequestFilter - Everytime send a req u want to filter activated . it will be executed only once
    @Autowired
    private JWTService jwtService;

    @Autowired
    ApplicationContext context; //we are using this ApplicationContext to get bean

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//  Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJraWxsIiwiaWF0IjoxNzIzMTgzNzExLCJleHAiOjE3MjMxODM4MTl9.5nf7dRzKRiuGurN2B9dHh_M5xiu73ZzWPr6rbhOTTHs
        String authHeader = request.getHeader("Authorization"); // will get the token with bearer
        String token = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7); //skip bearer & start from token
            username = jwtService.extractUserName(token);
        }
         //already authenticated -SecurityContextHolder.getContext().getAuthentication()
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(username);
            if (jwtService.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                //auth token knows user but no idea about the req obj. this req obj have lot of data
                authToken.setDetails(new WebAuthenticationDetailsSource()
                        .buildDetails(request)); // with this we can use build details & pass the req obj
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
        //if one filter is completed then go for the next filter
    }
}
// ultimately what we have to do is if this filter is success then will forward it to UPAF
//validate the token if the token is valid in that case you will create a authentication obj
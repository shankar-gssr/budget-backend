package com.shank.budget.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String origin = request.getHeader("Origin");
        String uri = request.getRequestURI();
        String method = request.getMethod();

        String servletPath = request.getServletPath();
        String contextPath = request.getContextPath();
        String queryString = request.getQueryString();
        String pathName = request.getHeader("REQUEST-PATH");

        // DEBUG: Request info
        System.out.println(":: ORIGIN :: " + origin);
        System.out.println(":: REQUEST URI :: " + uri);
        System.out.println(":: REQUEST METHOD :: " + method);
        System.out.println(":: REQUEST URL :: " + request.getRequestURL());
        System.out.println(":: CONTENT LENGTH :: " + request.getContentLength());
        System.out.println(":: SERVLET PATH :: " + servletPath);
        System.out.println(":: CONTEXT PATH :: " + contextPath);
        System.out.println(":: QUERY STRING :: " + queryString);
        System.out.println(":: PATH :: " + pathName);

        filterChain.doFilter(request, response);

    }
}

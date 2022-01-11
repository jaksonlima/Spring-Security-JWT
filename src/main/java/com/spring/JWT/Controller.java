package com.spring.JWT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/")
public class Controller {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JWTUtil jwtUtil;

    @GetMapping
    public ResponseEntity<?> jwt() {
        Authentication authenticationContext = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authenticationContext.getPrincipal());
    }

    @PostMapping("/autentication")
    public ResponseEntity<?> createToken(@RequestBody AuthenticationRequest request) throws Exception {
        return ResponseEntity.ok(new AuthenticationResponse(authenticationAndCreateToken(request)));
    }

    private String authenticationAndCreateToken(AuthenticationRequest request) throws Exception {
        try {
            final UsernamePasswordAuthenticationToken payloadAuth = new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword());

            authenticationManager.authenticate(payloadAuth);
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
        }

        final  UserDetails userDetails = myUserDetailsService.loadUserByUsername(request.getUsername());

        return jwtUtil.generateToken(userDetails);
    }
}

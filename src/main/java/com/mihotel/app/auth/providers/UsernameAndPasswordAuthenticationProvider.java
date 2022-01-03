package com.mihotel.app.auth.providers;

import com.mihotel.app.model.entity.User;
import com.mihotel.app.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
public class UsernameAndPasswordAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Get data from the new Authentication attempt:
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        System.out.println(authentication.getCredentials());

        // Find User in Repository:
        List<User> users = userRepository.findByUsername(username);
        if(users.size() > 0) {
            if (passwordEncoder.matches(pwd, users.get(0).getPwd())) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(users.get(0).getRole()));
                return new UsernamePasswordAuthenticationToken(
                        username,
                        pwd,
                        authorities
                );
            } else {
                throw new BadCredentialsException("Invalid Username or Password");
            }
        } else {
            throw new BadCredentialsException("Invalid Username or Password");
        }

    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return authenticationType.equals(UsernamePasswordAuthenticationToken.class);
    }

}

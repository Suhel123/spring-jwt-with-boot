package spring.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import spring.jwt.userservcie.CustomeUserDetailsService;

@Configuration
@EnableWebSecurity
public class MyJwtSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	CustomeUserDetailsService customeUserDetailsService;
	@Autowired
	JwtAuthenticationFilter jwtFiletr;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
	http
		.csrf().
		disable()
		.cors()
		.disable()
		.authorizeRequests()
		.antMatchers("/genrateToken").permitAll().anyRequest().authenticated().and()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	
	        http.addFilterBefore(jwtFiletr, UsernamePasswordAuthenticationFilter.class);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	
		auth.userDetailsService(customeUserDetailsService);
	}

	
	@Bean
  public PasswordEncoder passwordEncoder() {
	  
	  return NoOpPasswordEncoder.getInstance();
  }
	
	@Bean
	public AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
		
	}
}

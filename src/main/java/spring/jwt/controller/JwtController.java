package spring.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import spring.jwt.user.JwtRequest;
import spring.jwt.user.JwtResponse;
import spring.jwt.userservcie.CustomeUserDetailsService;
import spring.jwt.util.JwtUtil;

@RestController
public class JwtController {

	@Autowired
	private JwtUtil jwt;
	
	@Autowired
	private CustomeUserDetailsService customeUserDetailsService;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@RequestMapping(value="/genrateToken",method = RequestMethod.POST)
	ResponseEntity<?>genRateToken(@RequestBody JwtRequest jwtRequest){
		
		try {
			this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(), jwtRequest.getPassword()));
			
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			throw new BadCredentialsException("Bad Credential");
		}
	   UserDetails userDetails=this.customeUserDetailsService.loadUserByUsername(jwtRequest.getUsername());
	   String token=this.jwt.generateToken(userDetails);
	   return ResponseEntity.ok(new JwtResponse(token));
		
	}
}

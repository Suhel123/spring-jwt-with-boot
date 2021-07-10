package spring.jwt.userservcie;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomeUserDetailsService implements UserDetailsService {

	

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		    
		if(username.equals("suhel")) {
			
			return new User("suhel", "12345",new ArrayList<>());
		}else {
		
			throw new UsernameNotFoundException("UserName not found");
		}
		
	}

}

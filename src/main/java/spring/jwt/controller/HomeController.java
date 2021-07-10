package spring.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

	
	@GetMapping("/welcome")
	public String home(){
		
	return "this page is not allowed with out Authorization";
		
	}

}

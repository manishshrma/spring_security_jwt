package springjwt.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import springjwt.demo.model.AuthenticationRequest;
import springjwt.demo.model.AuthenticationResponse;
import springjwt.demo.util.JwtUtil;

@RestController
public class HelloResource {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private MyUserDetailService userDetailService;
    @Autowired
    private JwtUtil jwtUtil;


    @RequestMapping(value = "/auth")
    public String home() {
        return "home controller";
    }

    @RequestMapping(value = "/mypost", method = RequestMethod.POST)
    public void postmethod(@RequestBody AuthenticationRequest auth) {
        System.out.println(auth.getUsername());
    }


    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username and password", e);
        }
        final UserDetails userDetails = userDetailService.loadUserByUsername(authenticationRequest.getUsername());
        String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));

    }

}

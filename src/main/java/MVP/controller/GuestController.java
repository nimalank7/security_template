package MVP.controller;

import MVP.Entity.User;
import MVP.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class GuestController {

    private final UserRepository userRepository;

    @Autowired
    public GuestController(UserRepository userRepository) {

        this.userRepository = userRepository;

    }

    @GetMapping("/")
    public String hello() {

        return "homepage";
    }

    @GetMapping("/locked")
    public String locked() {
        return "locked";
    }
}

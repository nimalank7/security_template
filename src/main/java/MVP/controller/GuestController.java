package MVP.controller;

import MVP.Entity.User;
import MVP.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class GuestController {

    private final UserRepository userRepository;

    @Autowired
    public GuestController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/")
    public String hello(Model model) {
        model.addAttribute("user", new User());
        return "homepage";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/logout")
    public String logout() {
        System.out.println("Logged out");
        return "logout";
    }

    @GetMapping("/locked")
    public String locked() {
        return "locked";
    }

    @PostMapping("/register")
    public String newuser(@ModelAttribute User user){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(11);
        String encoded_password = encoder.encode(user.getPassword());
        user.setPassword(encoded_password);
        userRepository.save(user);
        return "redirect:/";
    }
}

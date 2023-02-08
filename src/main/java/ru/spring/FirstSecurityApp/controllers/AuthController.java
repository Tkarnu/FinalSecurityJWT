package ru.spring.FirstSecurityApp.controllers;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.spring.FirstSecurityApp.dto.PersonDTO;
import ru.spring.FirstSecurityApp.models.Person;
import ru.spring.FirstSecurityApp.security.JWTUtil;
import ru.spring.FirstSecurityApp.services.RegistrationService;
import ru.spring.FirstSecurityApp.util.PersonValidator;

import javax.validation.Valid;
import java.util.Map;


@RestController
@RequestMapping("/auth")
public class AuthController {

    private final RegistrationService registrationService;
    private final PersonValidator personValidator;
    private final ModelMapper modelMapper;
    private final JWTUtil jwtUtil;
    @Autowired
    public AuthController(RegistrationService registrationService, PersonValidator personValidator, ModelMapper modelMapper, JWTUtil jwtUtil) {
        this.registrationService = registrationService;
        this.personValidator = personValidator;
        this.modelMapper = modelMapper;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/login")
    public String loginPage() {
        return "auth/login";
    }

    @GetMapping("/registration")
    public String registrationPage(@ModelAttribute("person") Person person) {
        return "auth/registration";
    }

    @PostMapping("/registration")
    public Map<String, String> performRegistration(@RequestBody @Valid PersonDTO personDTO,
                                                   BindingResult bindingResult) {

        Person person = convertToPerson(personDTO);

        personValidator.validate(person, bindingResult);

        if (bindingResult.hasErrors())
            return Map.of("message", "Ошибка!");

        registrationService.register(person);

        String token = jwtUtil.generateToken(person.getUsername());
        return Map.of("jwt-token", token);
    }

    public Person convertToPerson(PersonDTO personDTO) {
        return this.modelMapper.map(personDTO, Person.class);
    }
}

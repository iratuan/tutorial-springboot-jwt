# Tutorial springboot + spring security + jwt

- Autor: Iratuã Júnior (inspirado no tutorial da Giuliana Bezerra [github](https://github.com/giuliana-bezerra/spring-security-jwt/tree/main)
- Data: 06/11/2024
- Versão do springboot: 3.3.5
- Versão jdk: 18
- [Respositorio no github](https://github.com/iratuan/tutorial-springboot-jwt)

### Passo 1 - Criação do projeto

Para iniciar esse projeto, você deverá criar um novo projeto springboot e adicionar as seguintes dependências no pom.xml

```xml
<dependencies>

    <!-- Spring Boot Web Starter: fornece recursos essenciais para criar uma aplicação web com Spring MVC, 
         incluindo o servidor embutido Tomcat e configurações de REST -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <!-- Spring Boot Data JPA Starter: permite interações com o banco de dados usando JPA e Hibernate, 
         oferecendo funcionalidades ORM para simplificar as operações de banco de dados -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>

    <!-- Spring Boot Security Starter: provê funcionalidades de autenticação e autorização para 
         proteger a aplicação com padrões de segurança do Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <!-- Spring Boot OAuth2 Resource Server: fornece suporte para proteger endpoints como um servidor 
         de recursos que valida tokens OAuth2 e implementa autenticação baseada em JWT -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>

    <!-- H2 Database: banco de dados em memória usado para desenvolvimento e testes, útil para 
         simular interações de banco de dados sem a necessidade de um banco externo durante o runtime -->
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>

    <!-- Spring Boot DevTools: ferramenta para melhorar a experiência de desenvolvimento, com recursos 
         como reinicialização automática e configurações de cache, usado somente em ambiente de desenvolvimento -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-devtools</artifactId>
        <scope>runtime</scope>
        <optional>true</optional>
    </dependency>

    <!-- Lombok: biblioteca que reduz o código boilerplate, como getters, setters e construtores, 
         anotando classes com @Data, @Builder, etc., facilitando a manutenção do código -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>

    <!-- Spring Boot Test Starter: conjunto de ferramentas de teste para o Spring Boot, 
         incluindo JUnit, Mockito e outras bibliotecas para testes unitários e de integração -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>

    <!-- Spring Security Test: fornece utilitários para testar componentes de segurança 
         da aplicação, como autenticação e autorização, durante os testes -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>

</dependencies>

```
- Spring Boot Starter Web:
  Fornece recursos essenciais para criar uma aplicação web com Spring MVC. Inclui suporte para o servidor embutido Tomcat e funcionalidades REST.
- Spring Boot Starter Data JPA:
  Facilita interações com o banco de dados usando JPA e Hibernate. Permite operações ORM (mapeamento objeto-relacional) para simplificar o acesso e a manipulação de dados no banco.
- Spring Boot Starter Security:
  Adiciona suporte para autenticação e autorização, usando Spring Security para proteger a aplicação. Oferece funcionalidades de segurança configuráveis para proteger endpoints e gerenciar acessos.
- Spring Boot OAuth2 Resource Server:
  Suporte para proteger endpoints como um servidor de recursos OAuth2, validando tokens e oferecendo autenticação baseada em JWT para integrar autenticações externas.
- H2 Database:
  Banco de dados em memória, utilizado principalmente para desenvolvimento e testes. Permite simular interações de banco de dados sem um servidor de banco de dados externo, facilitando o desenvolvimento rápido.
- Spring Boot DevTools:
  Ferramenta para aprimorar a experiência de desenvolvimento, com funcionalidades como reinicialização automática e desativação de cache. Usado apenas no ambiente de desenvolvimento.
- Lombok:
  Biblioteca que reduz o código boilerplate em Java, como getters, setters e construtores. Anotações como @Data e @Builder facilitam a criação e manutenção do código, tornando-o mais limpo e enxuto.
- Spring Boot Starter Test:
  Conjunto de ferramentas para testes em aplicações Spring Boot, incluindo JUnit, Mockito e outras bibliotecas que permitem a realização de testes unitários e de integração.
- Spring Security Test:
  Utilitários para testar a segurança da aplicação, incluindo funcionalidades de autenticação e autorização. Permite simular autenticações e validar o comportamento de segurança durante os testes.

Essa lista serve para entender o propósito de cada dependência, ajudando a manter o controle sobre os recursos utilizados na aplicação.


Feito isso, você abrirá o seu projeto em sua IDE de preferência (visual code, intellij )
____________________
### Passo 2 - Estrutura do projeto e classes necessárias

A arquitetura do projeto será no padrão layers, ou seja, os recursos serão segmentados por sua função.

Iremos adotar para esse tutorial a seguinte estrutura de diretórios/pacotes

```text
- src
  - main
    - java
      - br.com.aygean.security
        - config
        - controller
        - domain
        - dto
        - repository
        - service
    - resources
      - application.properties
  - test
``` 

#### Explicando cada pacote

Aqui está a descrição de cada pacote dentro da estrutura de um projeto Spring Boot, considerando a organização típica de responsabilidade de cada pacote:

- **br.com.aygean.security.config:**
  
  Contém classes de configuração relacionadas à segurança do projeto. Geralmente inclui a configuração do Spring Security, como as regras de autorização, autenticação, filtros de segurança personalizados, e configurações de CORS. Exemplo: SecurityConfig, JwtConfig.

- **br.com.aygean.security.controller:**

  Contém as classes que definem os endpoints REST relacionados à segurança, como endpoints de login, logout, registro de usuários, e renovação de tokens. Os controllers geralmente são anotados com @RestController e mapeiam URLs específicas para atender a essas funcionalidades. Exemplo: AuthController.

- **br.com.aygean.security.domain:** 

  Inclui as classes de entidade ou modelos de domínio que representam os dados de segurança no sistema, como User, Role, Permission. Essas classes geralmente são mapeadas para tabelas do banco de dados e contêm anotações JPA.

- **br.com.aygean.security.dto:**

  Contém classes de Data Transfer Object (DTO) utilizadas para transferir dados entre o cliente e o servidor. Esses objetos são úteis para encapsular dados de entrada e saída das APIs de segurança, como UserLoginDTO, UserRegistrationDTO, TokenDTO. Eles servem para abstrair os detalhes de entidades e proteger informações sensíveis.

- **br.com.aygean.security.repository:**

  Contém interfaces para o acesso ao banco de dados, geralmente estendendo o JpaRepository ou CrudRepository. Essas interfaces fornecem métodos para realizar operações CRUD (criação, leitura, atualização e exclusão) e consultas relacionadas às entidades de segurança, como UserRepository e RoleRepository.

- **br.com.aygean.security.service:** 
 
  Contém as classes de serviço responsáveis pela lógica de negócios relacionada à segurança. As classes neste pacote implementam operações complexas e processam regras de negócio, como autenticação de usuário, autorização, geração e validação de tokens JWT. Exemplo: UserService, AuthService.

Essa organização modular facilita a compreensão e manutenção do código, promovendo a separação de responsabilidades e garantindo um projeto mais escalável e estruturado.

### Criando o primeiro controller

Para iniciar as nossas requisições, iremos criar um controller **REST** que irá simular uma rota privada.

**Crie a classe PrivateController no pacote controller**

```java
package br.com.aygean.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("private")
public class PrivateController {

    @GetMapping
    public String getMessage() {
        return "Hello World from private controller";
    }
}
```

Explicando o `PrivateController`:

1. **`@RestController`**:
    - Essa anotação indica que a classe é um controlador REST, ou seja, ela irá processar e retornar respostas HTTP em formato JSON ou texto para o cliente. Ao usar `@RestController`, não é necessário adicionar `@ResponseBody` em cada método.

2. **`@RequestMapping("private")`**:
    - Define o caminho de URL base para todos os endpoints dentro desta classe. Isso significa que todos os endpoints definidos aqui serão acessíveis sob o caminho `/private`. Por exemplo, o método `getMessage` estará disponível em `/private`.

3. **`public class PrivateController`**:
    - A declaração da classe que define o controlador `PrivateController`. Esse controlador pode incluir endpoints para rotas privadas ou protegidas que requerem autenticação.

4. **`@GetMapping`**:
    - Essa anotação mapeia o método `getMessage` para requisições HTTP GET. Quando um cliente acessa o endpoint `/private` com uma requisição GET, o método `getMessage` será invocado.

5. **`public String getMessage()`**:
    - Método público que retorna uma `String`. Esse é o método mapeado para o endpoint GET `/private` e define o que será retornado ao cliente.

6. **`return "Hello World from private controller";`**:
    - A linha de retorno envia uma mensagem de texto `"Hello World from private controller"` como resposta para o cliente que acessou o endpoint. É uma resposta simples de exemplo, mas em uma aplicação real poderia retornar dados dinâmicos ou personalizados.

Em resumo, essa classe `PrivateController` é um controlador REST simples com um endpoint que responde a uma requisição GET em `/private` com uma mensagem de saudação.

### Criando o controller de autenticação

Esse controller é o ponto de entrada para a autenticação, que será feita através de uma requisição **HTTP POST** passando o usuário e senha de acesso (obs: não é o intuito desse tutorial explicar o funcionamento do cadastro de usuário)

```java
package br.com.aygean.security.controller;


import br.com.aygean.security.dto.AuthRequest;
import br.com.aygean.security.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }


    @PostMapping("authenticate")
    public String authenticate(
            @RequestBody AuthRequest authRequest) {
        return authService.authenticate(authRequest);
    }
}
```

Explicando o `AuthController`:

1. **`@RestController`**:
    - Indica que a classe é um controlador REST, permitindo que os métodos respondam diretamente com dados JSON ou texto.

2. **`AuthService authService`**:
    - Injeta uma instância do `AuthService`, que contém a lógica de autenticação. Isso permite que o controlador delegue a autenticação ao serviço.

3. **`AuthController(AuthService authService)`**:
    - Construtor que injeta a dependência `authService`, utilizando injeção de dependência para instanciar o serviço necessário.

4. **`@PostMapping("authenticate")`**:
    - Mapeia o método `authenticate` para o endpoint `POST /authenticate`. Esse endpoint será utilizado para a autenticação.

5. **`public String authenticate(@RequestBody AuthRequest authRequest)`**:
    - Método que recebe um objeto `AuthRequest` como corpo da requisição. O objeto `AuthRequest` contém os dados de login. O método delega ao `authService` para processar a autenticação e retorna o resultado (por exemplo, um token JWT ou uma mensagem de sucesso).

Esse controlador fornece um endpoint de autenticação básico, delegando a lógica ao serviço e retornando o resultado da autenticação para o cliente.

#### Seguindo o lastro do código ####
Note que, na etapa atual, seu projeto não compilaria porque faltam muitos recursos. Iremos criar cada um dos recursos e entender o funcionamento básico de cada um deles.

### Criando o `AuthService`

O `AuthService` é o serviço responsável por autenticar o usuário, recebendo um `DTO` AuthRequest, que contem dois campos: `username` e `password`.

```java
package br.com.aygean.security.service;

import br.com.aygean.security.dto.AuthRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthService(JwtService jwtService, AuthenticationManager authenticationManager) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public String authenticate(AuthRequest authRequest) {
        // Cria um objeto Authentication a partir do AuthRequest
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authRequest.username(),
                authRequest.password()
        );

        // Autentica o usuário
        Authentication authenticatedUser = authenticationManager.authenticate(authentication);

        // Gera o token para o usuário autenticado
        return jwtService.generateToken(authenticatedUser);
    }
}
```

Explicando o `AuthService`:

1. **`@Service`**:
    - Define a classe como um serviço do Spring, permitindo que ela seja injetada em outras partes do aplicativo e gerenciada pelo contêiner Spring.

2. **`JwtService jwtService`**:
    - Instância do `JwtService`, responsável por gerar tokens JWT para usuários autenticados.

3. **`AuthenticationManager authenticationManager`**:
    - Gerenciador de autenticação que valida as credenciais dos usuários, integrando-se ao Spring Security para autenticação.

4. **`AuthService(JwtService jwtService, AuthenticationManager authenticationManager)`**:
    - Construtor que injeta as dependências `jwtService` e `authenticationManager`, necessárias para autenticação e geração de tokens.

5. **`authenticate(AuthRequest authRequest)`**:
    - Método que realiza a autenticação. Recebe um objeto `AuthRequest` com as credenciais de login do usuário.

6. **`UsernamePasswordAuthenticationToken`**:
    - Cria um objeto de autenticação com o nome de usuário e senha a partir do `authRequest`.

7. **`authenticationManager.authenticate(authentication)`**:
    - Autentica o usuário com as credenciais fornecidas. Caso as credenciais sejam válidas, retorna um objeto `Authentication` representando o usuário autenticado.

8. **`jwtService.generateToken(authenticatedUser)`**:
    - Gera um token JWT para o usuário autenticado e o retorna, permitindo o acesso a recursos protegidos.

Esse serviço autentica o usuário e gera um token JWT, encapsulando a lógica de autenticação e delegando a geração de tokens ao `JwtService`.

### Criando o JwtService

Iremos criar agora a classe `JwtService`, que será responsável por gerar o `Token JWT` responsável por autorizar determinado usuário acessar determinada rota privada.

```java
package br.com.aygean.security.service;
import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
    private final JwtEncoder encoder;

    @Autowired
    public JwtService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        long expiry = 36000L;

        String scope = authentication
                .getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors
                        .joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("spring-security-jwt")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiry))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();

        return encoder.encode(
                        JwtEncoderParameters.from(claims))
                .getTokenValue();
    }

}
```
Explicando o `JwtService`:

1. **`@Service`**:
    - Define a classe como um serviço gerenciado pelo Spring, permitindo que ela seja injetada em outros componentes do aplicativo.

2. **`JwtEncoder encoder`**:
    - Dependência que codifica o token JWT usando as configurações de codificação fornecidas. O `JwtEncoder` cria o token com base nos `JwtClaimsSet`.

3. **`JwtService(JwtEncoder encoder)`**:
    - Construtor que injeta a dependência `JwtEncoder`, necessária para criar e codificar tokens JWT.

4. **`generateToken(Authentication authentication)`**:
    - Método responsável por gerar um token JWT com base nas informações de autenticação do usuário.

5. **`Instant now`**:
    - Representa o momento atual para definir o tempo de emissão (`issuedAt`) e o tempo de expiração do token.

6. **`long expiry = 36000L`**:
    - Define o tempo de expiração do token em segundos (10 horas).

7. **`String scope`**:
    - Extrai as permissões do usuário (autoridades) a partir da autenticação e as converte em uma `String` única, separada por espaços.

8. **`JwtClaimsSet claims`**:
    - Conjunto de declarações (claims) do JWT. Define o emissor (`issuer`), o momento de emissão (`issuedAt`), a expiração (`expiresAt`), o usuário (`subject`), e o escopo de permissões (`scope`).

9. **`encoder.encode(JwtEncoderParameters.from(claims))`**:
    - Codifica as declarações (claims) usando o `JwtEncoder` e retorna o valor do token.

Este serviço `JwtService` gera um token JWT baseado nas informações de autenticação, incluindo nome de usuário, permissões, data de expiração e emissor, encapsulando as configurações em um JWT seguro e assinado.

### Criando a classe USerDetailsServiceImpl
Nesse ponto, precisaremos criar uma implementação da interface `UserDetailsService`, cuja a funcionalidade será explicada logo mais.

```java
package br.com.aygean.security.service;
import br.com.aygean.security.dto.UserAuthenticated;
import br.com.aygean.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Autowired
    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(user -> new UserAuthenticated(user))
                .orElseThrow(
                        () -> new UsernameNotFoundException("User Not Found with username: " + username));
    }

}

```

Explicando o  `UserDetailsServiceImpl`:

1. **`@Service`**:
    - Define a classe como um serviço Spring, permitindo que ela seja injetada em outras partes do aplicativo e gerenciada pelo contêiner do Spring.

2. **`UserRepository userRepository`**:
    - Dependência para acesso ao repositório de usuários. Utilizado para buscar usuários pelo nome de usuário.

3. **`UserDetailsServiceImpl(UserRepository userRepository)`**:
    - Construtor que injeta a dependência `UserRepository`, permitindo a busca de informações sobre usuários no banco de dados.

4. **`UserDetailsService` Interface**:
    - A classe implementa a interface `UserDetailsService`, que é uma interface do Spring Security responsável por carregar dados específicos do usuário durante o processo de autenticação.

5. **`loadUserByUsername(String username)`**:
    - Método que busca um usuário pelo nome de usuário. Retorna um objeto `UserDetails`, que encapsula informações de autenticação e autorização sobre o usuário.

6. **`UserAuthenticated`**:
    - Um DTO ou classe que implementa `UserDetails`. Ao carregar o usuário com `UserAuthenticated`, a aplicação consegue obter dados do usuário e suas permissões.

7. **`UsernameNotFoundException`**:
    - Exceção lançada quando o usuário não é encontrado no banco de dados. Essa exceção indica ao Spring Security que a autenticação falhou.

Essa classe implementa a lógica de busca de usuários para o Spring Security e facilita o processo de autenticação, garantindo que o usuário exista e tenha as informações de autenticação necessárias.

### Criando o DTO `UserAuthenticated` que implementa a interface `UserDetails`. 

A implementação da Interface `UserDetails` é importante, pois o service `UserDetailsServiceImpl` faz um mapeamento entre a entidade `User` e `UserAuthenticated`.

```java
package br.com.aygean.security.dto;

import java.util.Collection;
import java.util.List;

import br.com.aygean.security.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


public class UserAuthenticated implements UserDetails {
    private final User user;

    public UserAuthenticated(User user) {
        this.user = user;
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "read");
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
```

Aqui está a explicação da classe `UserAuthenticated`:

1. **`UserAuthenticated`**:
    - Implementa a interface `UserDetails` do Spring Security, que define os dados de autenticação do usuário. Essa classe encapsula um objeto `User` e fornece as informações necessárias para autenticação e autorização.

2. **`User user`**:
    - Armazena uma instância da entidade `User`, que contém os dados do usuário, como `username` e `password`.

3. **`UserAuthenticated(User user)`**:
    - Construtor que recebe um objeto `User` e o armazena na variável `user`, permitindo o acesso aos dados do usuário autenticado.

4. **`getUsername()`**:
    - Retorna o `username` do usuário, obtido a partir do objeto `User`.

5. **`getPassword()`**:
    - Retorna o `password` do usuário, obtido a partir do objeto `User`.

6. **`getAuthorities()`**:
    - Retorna uma lista de permissões do usuário. Neste exemplo, fornece uma única permissão `"read"`. A lista pode ser expandida conforme necessário para incluir outras permissões ou papéis.

7. **`isAccountNonExpired()`**:
    - Retorna `true`, indicando que a conta do usuário não está expirada.

8. **`isAccountNonLocked()`**:
    - Retorna `true`, indicando que a conta do usuário não está bloqueada.

9. **`isCredentialsNonExpired()`**:
    - Retorna `true`, indicando que as credenciais do usuário não estão expiradas.

10. **`isEnabled()`**:
    - Retorna `true`, indicando que a conta do usuário está ativa.

Essa classe `UserAuthenticated` fornece uma implementação personalizada de `UserDetails`, encapsulando um usuário e definindo as permissões e o status da conta para autenticação e autorização no Spring Security.

### Criando a entidade `User` e o `Repository` respectivo.

Agora, iremos criar os recursos necessários para persistir a entidade que será responsável por gravar os dados de acesso no banco de dados.

```java
package br.com.aygean.security.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Table(name = "USERS")
@Entity
public class User {
    @Id
    private String username;
    private String password;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        User user = (User) o;
        return getUsername() != null && Objects.equals(getUsername(), user.getUsername());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}

```
Aqui está uma explicação detalhada da classe `User`:

1. **`@Getter`, `@Setter`**:
    - Lombok gera automaticamente os métodos `get` e `set` para todos os campos da classe, facilitando o acesso e modificação dos atributos `username` e `password`.

2. **`@ToString`**:
    - Lombok gera automaticamente um método `toString()` que inclui os atributos da classe, facilitando a depuração e exibição de informações do objeto.

3. **`@RequiredArgsConstructor`**:
    - Lombok gera um construtor que inclui todos os atributos `final` da classe. Como não há atributos `final`, não terá efeito direto, mas está pronto para inclusão de atributos imutáveis, se necessário.

4. **`@Table(name = "USERS")`**:
    - Define o nome da tabela no banco de dados para esta entidade (`USERS`). Mapeia a classe `User` à tabela `USERS`.

5. **`@Entity`**:
    - Define que esta classe é uma entidade JPA, permitindo que o Hibernate ou outro ORM a mapeie para uma tabela de banco de dados.

6. **`@Id`**:
    - Indica que `username` é a chave primária da entidade, identificando cada instância `User` de forma única no banco de dados.

7. **`private String username` e `private String password`**:
    - `username`: Identificador exclusivo do usuário, usado como chave primária.
    - `password`: Armazena a senha do usuário. Em um sistema real, essa senha deve ser criptografada para maior segurança.

8. **`equals(Object o)`**:
    - Método `equals` personalizado que compara duas instâncias `User` com base no campo `username`. Inclui uma verificação para evitar problemas com proxies gerados pelo Hibernate (usando `HibernateProxy`), garantindo uma comparação precisa entre objetos reais e proxies.

9. **`hashCode()`**:
    - Método `hashCode` personalizado que utiliza a classe efetiva (`getPersistentClass()`) para gerar um código de hash. Isso garante consistência ao trabalhar com proxies gerados pelo Hibernate.

Essa classe `User` representa uma entidade de usuário no banco de dados, com campos para `username` e `password`, e inclui métodos para comparação e hash personalizados para compatibilidade com proxies do Hibernate.




```java
package br.com.aygean.security.repository;

import br.com.aygean.security.domain.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
```

Aqui está uma explicação detalhada do repositório `UserRepository`:

1. **`@Repository`**:
    - Marca a interface como um repositório Spring, facilitando a detecção automática pelo Spring e o gerenciamento de exceções relacionadas ao acesso a dados.

2. **`CrudRepository<User, Long>`**:
    - Estende o `CrudRepository`, que fornece operações CRUD (Create, Read, Update, Delete) padrão para a entidade `User`. O `CrudRepository` usa a classe `User` e uma chave primária do tipo `Long` para suas operações. No entanto, a chave primária do `User` na sua definição está como `String` (`username`), portanto é recomendável alterar `Long` para `String` no parâmetro genérico do `CrudRepository`.

3. **`Optional<User> findByUsername(String username)`**:
    - Declaração de um método personalizado que busca um usuário pelo `username`. Retorna um `Optional<User>`, que pode estar vazio caso o usuário não seja encontrado no banco de dados.

Esse repositório `UserRepository` fornece acesso ao banco de dados para a entidade `User`, permitindo operações básicas e uma busca personalizada por `username`, essencial para a autenticação e identificação de usuários.

### Criando o arquivo de configuração `SecurityConfig`.
Agora vem a classe mais complexa do nosso componente, a classe SecurityConfig, que é a responsável por orquestrar o funcionamento do springSecurity.

```java
package br.com.aygean.security.config;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Value("${jwt.public.key}")
    private RSAPublicKey key;
    @Value("${jwt.private.key}")
    private RSAPrivateKey priv;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/authenticate").permitAll()
                                .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .oauth2ResourceServer(
                        conf -> conf.jwt(
                                jwt -> jwt.decoder(jwtDecoder())));
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.key).build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(this.key).privateKey(this.priv).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
```
Aqui está a explicação da classe `SecurityConfig`:

1. **`@Configuration`**:
    - Indica que esta classe é uma classe de configuração e define beans para o contexto da aplicação Spring.

2. **`@EnableWebSecurity`**:
    - Habilita a configuração personalizada de segurança do Spring Security.

3. **`@Value("${jwt.public.key}")` e `@Value("${jwt.private.key}")`**:
    - Injeta as chaves RSA pública e privada do arquivo de configuração (como `application.properties` ou `application.yml`). Estas chaves são usadas para assinar e validar tokens JWT.

4. **`SecurityFilterChain filterChain(HttpSecurity http)`**:
    - Define a configuração de segurança HTTP para a aplicação:
        - **`csrf(csrf -> csrf.disable())`**: Desabilita o CSRF, que é desnecessário em APIs REST para simplificar a configuração.
        - **`authorizeHttpRequests(...)`**: Configura as permissões de acesso:
            - **`/authenticate`**: Endpoint público acessível a todos (usado para autenticação).
            - **`anyRequest().authenticated()`**: Exige autenticação para todas as outras requisições.
        - **`httpBasic(Customizer.withDefaults())`**: Habilita a autenticação básica (útil para desenvolvimento).
        - **`oauth2ResourceServer(...)`**: Configura o servidor de recursos OAuth2 para validar tokens JWT usando o `jwtDecoder()`.

5. **`PasswordEncoder passwordEncoder()`**:
    - Define o codificador de senha como `BCryptPasswordEncoder`, um algoritmo seguro para armazenar senhas de forma criptografada.

6. **`JwtDecoder jwtDecoder()`**:
    - Cria um decodificador de JWT usando a chave pública RSA para validar tokens JWT assinados. Isso garante que apenas tokens válidos possam ser usados para autenticação.

7. **`JwtEncoder jwtEncoder()`**:
    - Configura um codificador JWT com a chave pública e privada RSA, permitindo que a aplicação assine tokens JWT.
    - **`JWK jwk = new RSAKey.Builder(this.key).privateKey(this.priv).build();`**: Cria um `JWK` com as chaves RSA.
    - **`JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));`**: Armazena as chaves em uma fonte de chaves JWT.
    - **`return new NimbusJwtEncoder(jwks);`**: Cria um `NimbusJwtEncoder` para codificar os tokens JWT.

8. **`AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)`**:
    - Obtém o `AuthenticationManager` a partir do `AuthenticationConfiguration`, que é responsável por gerenciar a autenticação, como login e validação de credenciais dos usuários.

A `SecurityConfig` configura a segurança da aplicação Spring Boot, definindo autenticação e autorização, o uso de tokens JWT para segurança de APIs, além de configurar codificação segura de senhas e manipulação de tokens JWT com chaves RSA.
___________________
## Resumindo tudo até aqui.

### Índice do Tutorial

1. **Introdução**
    - Autor, Data, Versão do Spring Boot e JDK.
    - Objetivo: Implementar autenticação e autorização com Spring Security e JWT.

2. **Passo 1 - Criação do Projeto**
    - **Configuração do `pom.xml`**: Adição das dependências essenciais.
    - **Explicação das Dependências**: Detalhes de cada biblioteca usada, como Spring Boot Web, Data JPA, Security, H2 Database, etc.

3. **Passo 2 - Estrutura do Projeto e Pacotes Necessários**
    - **Organização de Pacotes**: Definição de cada pacote e suas responsabilidades (config, controller, domain, dto, repository, service).
    - **Explicação dos Pacotes**: Descrição de cada pacote e os exemplos de classes correspondentes.

4. **Criação do `PrivateController`**
    - **Implementação e Explicação do Controller**: Controller simples para simular uma rota privada acessível apenas após autenticação.

5. **Criação do `AuthController` para Autenticação**
    - **Endpoint de Autenticação**: Implementação do endpoint `authenticate` para autenticação de usuários e retorno de token JWT.
    - **Explicação da Estrutura do Controller**: Descrição das anotações e métodos.

6. **Implementação do `AuthService`**
    - **Responsabilidades do Serviço**: Autenticação do usuário e geração de token JWT.
    - **Métodos e Fluxo**: Explicação detalhada dos métodos `authenticate`, uso de `UsernamePasswordAuthenticationToken`, e integração com `JwtService`.

7. **Implementação do `JwtService`**
    - **Geração de Token JWT**: Método `generateToken` para criar e assinar tokens JWT.
    - **Configuração de Claims e Expiração**: Uso de `JwtClaimsSet` para definir o emissor, tempo de expiração e permissões.

8. **Implementação do `UserDetailsServiceImpl`**
    - **Busca e Carregamento do Usuário**: Implementação da interface `UserDetailsService` para integração com o Spring Security.
    - **Descrição dos Métodos**: Explicação dos métodos, `UserAuthenticated` e exceção `UsernameNotFoundException`.

9. **Criação do DTO `UserAuthenticated`**
    - **Implementação do `UserDetails`**: Definição das informações de autenticação e autorização do usuário.
    - **Métodos de Autorização**: `getAuthorities`, `isAccountNonExpired`, `isAccountNonLocked`, `isCredentialsNonExpired`, e `isEnabled`.

10. **Criação da Entidade `User` e Repositório `UserRepository`**
    - **Definição da Entidade `User`**: Atributos `username` e `password`, e métodos `equals` e `hashCode`.
    - **Implementação do `UserRepository`**: Interface para CRUD e busca de usuário por `username`.

11. **Configuração da Classe `SecurityConfig`**
    - **Configurações de Segurança**: Configuração do filtro de segurança com `SecurityFilterChain`, autenticação JWT e métodos de encriptação de senha.
    - **Explicação dos Beans**: `PasswordEncoder`, `JwtEncoder`, `JwtDecoder`, e `AuthenticationManager`.

---

### Resumo do Tutorial

Este tutorial orienta na criação de uma API Spring Boot protegida com Spring Security e autenticação baseada em JWT (JSON Web Tokens). Os passos abordam desde a configuração inicial do projeto, estruturação de pacotes, até a implementação de classes para controle de acesso e geração de tokens seguros.

O `AuthController` fornece um ponto de entrada para autenticação, recebendo credenciais e retornando um token JWT para acesso seguro. O `AuthService` e `JwtService` são responsáveis por autenticar o usuário e gerar o token, enquanto o `UserDetailsServiceImpl` busca os detalhes do usuário no banco de dados. A classe `SecurityConfig` integra todas as configurações de segurança, usando `BCrypt` para criptografia de senhas e `RSA` para assinar e validar os tokens JWT.

O tutorial proporciona uma visão clara de cada componente de segurança, permitindo o desenvolvimento de uma API com acesso protegido, pronta para integração em aplicações empresariais.

__________________
## Recursos adicionais

- Arquivo application.properties
```properties
spring.application.name=sboot-security-jwt

spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=sa
spring.h2.console.enabled=true
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

jwt.private.key=classpath:app.key
jwt.public.key=classpath:app.pub
```

- app.key
```text
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDcWWomvlNGyQhA
iB0TcN3sP2VuhZ1xNRPxr58lHswC9Cbtdc2hiSbe/sxAvU1i0O8vaXwICdzRZ1JM
g1TohG9zkqqjZDhyw1f1Ic6YR/OhE6NCpqERy97WMFeW6gJd1i5inHj/W19GAbqK
LhSHGHqIjyo0wlBf58t+qFt9h/EFBVE/LAGQBsg/jHUQCxsLoVI2aSELGIw2oSDF
oiljwLaQl0n9khX5ZbiegN3OkqodzCYHwWyu6aVVj8M1W9RIMiKmKr09s/gf31Nc
3WjvjqhFo1rTuurWGgKAxJLL7zlJqAKjGWbIT4P6h/1Kwxjw6X23St3OmhsG6HIn
+jl1++MrAgMBAAECggEBAMf820wop3pyUOwI3aLcaH7YFx5VZMzvqJdNlvpg1jbE
E2Sn66b1zPLNfOIxLcBG8x8r9Ody1Bi2Vsqc0/5o3KKfdgHvnxAB3Z3dPh2WCDek
lCOVClEVoLzziTuuTdGO5/CWJXdWHcVzIjPxmK34eJXioiLaTYqN3XKqKMdpD0ZG
mtNTGvGf+9fQ4i94t0WqIxpMpGt7NM4RHy3+Onggev0zLiDANC23mWrTsUgect/7
62TYg8g1bKwLAb9wCBT+BiOuCc2wrArRLOJgUkj/F4/gtrR9ima34SvWUyoUaKA0
bi4YBX9l8oJwFGHbU9uFGEMnH0T/V0KtIB7qetReywkCgYEA9cFyfBIQrYISV/OA
+Z0bo3vh2aL0QgKrSXZ924cLt7itQAHNZ2ya+e3JRlTczi5mnWfjPWZ6eJB/8MlH
Gpn12o/POEkU+XjZZSPe1RWGt5g0S3lWqyx9toCS9ACXcN9tGbaqcFSVI73zVTRA
8J9grR0fbGn7jaTlTX2tnlOTQ60CgYEA5YjYpEq4L8UUMFkuj+BsS3u0oEBnzuHd
I9LEHmN+CMPosvabQu5wkJXLuqo2TxRnAznsA8R3pCLkdPGoWMCiWRAsCn979TdY
QbqO2qvBAD2Q19GtY7lIu6C35/enQWzJUMQE3WW0OvjLzZ0l/9mA2FBRR+3F9A1d
rBdnmv0c3TcCgYEAi2i+ggVZcqPbtgrLOk5WVGo9F1GqUBvlgNn30WWNTx4zIaEk
HSxtyaOLTxtq2odV7Kr3LGiKxwPpn/T+Ief+oIp92YcTn+VfJVGw4Z3BezqbR8lA
Uf/+HF5ZfpMrVXtZD4Igs3I33Duv4sCuqhEvLWTc44pHifVloozNxYfRfU0CgYBN
HXa7a6cJ1Yp829l62QlJKtx6Ymj95oAnQu5Ez2ROiZMqXRO4nucOjGUP55Orac1a
FiGm+mC/skFS0MWgW8evaHGDbWU180wheQ35hW6oKAb7myRHtr4q20ouEtQMdQIF
snV39G1iyqeeAsf7dxWElydXpRi2b68i3BIgzhzebQKBgQCdUQuTsqV9y/JFpu6H
c5TVvhG/ubfBspI5DhQqIGijnVBzFT//UfIYMSKJo75qqBEyP2EJSmCsunWsAFsM
TszuiGTkrKcZy9G0wJqPztZZl2F2+bJgnA6nBEV7g5PA4Af+QSmaIhRwqGDAuROR
47jndeyIaMTNETEmOnms+as17g==
-----END PRIVATE KEY-----
```

- app.pub
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3FlqJr5TRskIQIgdE3Dd
7D9lboWdcTUT8a+fJR7MAvQm7XXNoYkm3v7MQL1NYtDvL2l8CAnc0WdSTINU6IRv
c5Kqo2Q4csNX9SHOmEfzoROjQqahEcve1jBXluoCXdYuYpx4/1tfRgG6ii4Uhxh6
iI8qNMJQX+fLfqhbfYfxBQVRPywBkAbIP4x1EAsbC6FSNmkhCxiMNqEgxaIpY8C2
kJdJ/ZIV+WW4noDdzpKqHcwmB8FsrumlVY/DNVvUSDIipiq9PbP4H99TXN1o746o
RaNa07rq1hoCgMSSy+85SagCoxlmyE+D+of9SsMY8Ol9t0rdzpobBuhyJ/o5dfvj
KwIDAQAB
-----END PUBLIC KEY-----
```

- data.sql
```sql
INSERT INTO USERS(username, password) VALUES ('username','$2a$10$GiseHkdvwOFr7A9KRWbeiOmg/PYPhWVjdm42puLfOzR/gIAQrsAGy');
```
- schema.sql
```sql
CREATE TABLE USERS
(
    username VARCHAR(50) PRIMARY KEY,
    password VARCHAR(255) NOT NULL
);

```

- Requisições HTTP para testes

  Nesse ponto você poderá usar o postman, isomnia ou qualquer client REST.
```text
##
# curl -X POST http://localhost:8080/auth
#  -H "Content-Type: application/json"
#  -d '{"username": "seu_username", "password": "sua_password"}'
POST http://localhost:8080/authenticate
Content-Type: application/json

{"username": "username", "password": "password"}

<> 2024-11-06T151919.200.txt

###

# curl -X GET http://localhost:8080/private
#  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzcHJpbmctc2VjdXJpdHktand0Iiwic3ViIjoidXNlcm5hbWUiLCJleHAiOjE3MzA5NDYyNjIsImlhdCI6MTczMDkxMDI2Miwic2NvcGUiOiJyZWFkIn0.IvFRcJ9GHX-NZWdNx7lKtTFuDXsrShgKFv5cvEtc5cjWet7e7j8YaDR74qyYrx6Xy4C7T1gA47MX7LpK5oK5mI5fgz-VPv2dbT1z3Hw6IAbrA2FmBT0NzvjMT1B-Zd670JbBE1OHbkNoERL2NKjeHrzlu0NESijczVGoqXqbA6tFFoSUrPI6lHwlevyMpt0jL4UZOn6YQ65O8DHMj8I75NH1JLc-WLj2r3_FSJo9j5QQZTyXfc1Mc_vPlvgZIFln11n1xPRgesGdmrCNANhUgnw0CaPAJIMn4R_8nJoxvBa5u8GB14n5y0bH5vjJ_cLP3wGQF8FhmIn0U25_Dh9AEg"
GET http://localhost:8080/private
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzcHJpbmctc2VjdXJpdHktand0Iiwic3ViIjoidXNlcm5hbWUiLCJleHAiOjE3MzA5NTMxNTksImlhdCI6MTczMDkxNzE1OSwic2NvcGUiOiJyZWFkIn0.PctZN-6SbtSXsNt8r1vVf8j0XWqB4Vlx_5tkE5mMHK2WuRWG4_bWdencQ4I2cw1qbaGeRhqP5Ut6uFG0lEqQj0thDSjdOWlnpjDqTFa0_sawogGSU_dPrPxGx7PC1hR8NniGv3NZlYpxjzaAEQps20PEC4nJp3GQ05ci9Oxsj_wTyy0LvzU_95rlAukFWGD-BFpexWk1XWk0EkNtk9A-2SZyKcYCfXGJJb788Jz6ymYsRW3tcKwj_VjBoGVvb7I8Ualju-SqWQLia1X6Rxwh1t1X-RZkpvoBrbSA5dPITEdPpF9IquRyScKezHCTw9B8uFEHRhbxuq2iVy6uKC3OyA

<> 2024-11-06T151952.200.txt
<> 2024-11-06T151941.200.txt

###
```

Creio que, com as informações acima, você consiga tranquilamente seguir o tutorial e replicar em seus projetos.

[**Iratuã Júnior** @iratuan](https://github.com/iratuan)

___________________
## Melhorias

### Criação do container do postgres
Primeiramente, adicione a dependência do postgres no `pom.xml` do seu projeto.
```xml
 <dependency>
   <groupId>org.postgresql</groupId>
   <artifactId>postgresql</artifactId>
   <scope>runtime</scope>
</dependency>
```

Após isso, modifique o seu arquivo `application.properties` para o conteúdo abaixo:

```properties
spring.application.name=sboot-security-jwt

# Configuração do DataSource
spring.datasource.url=jdbc:postgresql://localhost:5432/mydatabase
spring.datasource.username=myuser
spring.datasource.password=mypassword

# Configurações adicionais para o PostgreSQL
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect

# Configuração para mostrar as queries SQL no console
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true

# Configuração para gerenciamento de schema (opcional)
spring.jpa.hibernate.ddl-auto=update


jwt.private.key=classpath:app.key
jwt.public.key=classpath:app.pub

```

Após isso, crie o arquivo `docker-compose.yml` na raiz do seu projeto.

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15  # Utilize a versão que preferir
    container_name: postgres_container
    environment:
      POSTGRES_USER: myuser        # Substitua por seu usuário
      POSTGRES_PASSWORD: mypassword  # Substitua pela sua senha
      POSTGRES_DB: mydatabase       # Substitua pelo nome do seu banco de dados
    volumes:
      - ./data:/var/lib/postgresql/data  # Monta a pasta `data` para persistir os dados
    ports:
      - "5432:5432"

```
*** Não esqueça de criar o diretório `data` na raiz do seu projeto.

Execute o comando `docker compose up -d` para subir o container.

____________________
### Evoluções futuras
- Criar a funcionalidade de adicionar as `ROLES` no `TOKEN JWT`, para que, futuras funcionalidades possam filtra o acesso (`AUTORIZAÇÃO`) dos recursos disponíveis na API.
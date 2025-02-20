# Cloud-Native Architecture / Microservice Template
## Non Functional Requirements Template

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=arafkarsh_ms-springboot-334-vanilla&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=arafkarsh_ms-springboot-334-vanilla) 
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=arafkarsh_ms-springboot-334-vanilla&metric=bugs)](https://sonarcloud.io/summary/new_code?id=arafkarsh_ms-springboot-334-vanilla)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=arafkarsh_ms-springboot-334-vanilla&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=arafkarsh_ms-springboot-334-vanilla) 
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=arafkarsh_ms-springboot-334-vanilla&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=arafkarsh_ms-springboot-334-vanilla)

1. Java 23 (Minimum Requirement: Java 17)
2. SpringBoot 3.4.1
3. Jakarta EE 10 

Cloud-native (or microservice) architecture is an approach to application design in which software is 
broken down into small, independent services that communicate through lightweight APIs, enabling 
more agile development, scalability, and resilience. Rather than running a single monolithic codebase, 
each microservice can be developed, deployed, and scaled independently. 

This decomposition—often containerized and orchestrated using tools such as Kubernetes—allows teams 
to quickly iterate on features, take advantage of cloud-native capabilities (like auto-scaling and 
automated deployments), and release updates with minimal disruption to the entire system. According 
to the Cloud Native Computing Foundation (CNCF), this approach fosters loosely coupled systems that 
are resilient, manageable, and observable, combined with robust automation (CNCF, 2023).

Key Features of Microservice (Sources: CNCF, 2023; Fowler, 2014):

1.	Service Independence: Each microservice is autonomous, allowing for separate development, deployment, and scaling without affecting others.
2. Containerization: Services are commonly packaged in containers (e.g., Docker), providing consistency across different environments and efficient resource utilization.
3.	Lightweight Communication: Microservices communicate via lightweight protocols (often HTTP/REST or gRPC), reducing overhead and complexity.
4.	Scalability: Independent scaling of services ensures you can allocate resources exactly where needed, improving performance and cost-efficiency.
5.	Continuous Delivery and Deployment: Automation enables frequent, reliable releases to production while minimizing disruption.
6.	Resilience: Failure of one service doesn’t necessarily bring the entire system down, as microservices are loosely coupled and can handle faults gracefully.

References

- CNCF. (2023). What is Cloud Native? https://www.cncf.io/blog/2023/02/03/what-is-cloud-native/ 
- Fowler, M. (2014). Microservices. https://martinfowler.com/articles/microservices.html

## What the Template Provides out of the box

1. Security Auth/Authorization using AOP and Filters
2. Exception Handling with Exception Framework using AOP ( ..microservice.adapters.aop)
3. Log Management using AOP (json and text formats) using Logback  (...adapters.filters)
4. Standardized REST Responses (...domain.models.StandardResponse)
5. Security using JWT Tokens / KeyCloak Auth (...microservice.adapters.security, ...microservice.security)
6. Encrypting Sensitive Data using Encryption Algorithms (...microservice.security)
7. JPA configurations for H2 and PostgreSQL (...server.config)
8. Observability Using Micrometer, Prometheus and Open Telemetry.
9. Database Password Encryption using Jasypt. Checkout the shell programs encrypt and decrypt.
10. Digital Signatures using Standard Java Cryptography.
11. Open API based Swagger API Docs (...microservice.adapters.controllers)

## How to Setup and use the template

### Encrypting Database Passwords for the Property Files

This microservice template offers a range of built-in functionalities. To simplify the demonstration of 
various features, an encrypted password is utilized for connecting to H2 and PostgreSQL databases. 
The template includes utilities for encrypting and decrypting passwords, ensuring that the encryption 
key is securely stored outside the application’s runtime context.

To know more about how to setup these passwords (for H2 & PostgreSQL) and environment variables
checkout Session 1.2

Encrypted H2 (In Memory) Database Password. Uses H2 database in Dev (Profile) mode.
![Package Structure](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/encrypt/Security-H2-psd.jpg)
Encrypted PostgreSQL Database Password. Uses PostgreSQL DB in Staging & Prod (profile) mode.
![Package Structure](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/encrypt/Security-PostgreSQL-psd.jpg)
Password can be decrypted only using an Encryption Key stored in System Enviornment variable
![Package Structure](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/encrypt/Security-Encryption-pro.jpg)

If the Quality Gate check fails, it's because the password is encrypted within the application’s 
properties file, with the encryption key stored externally, outside the application’s context.

However, quality standards mandate that passwords should be securely stored in a vault, such as
HashiCorp Vault, for enhanced security.

### Microservice Package Structure

![Package Structure](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/MS-Pkg-Structure.jpg)

io.fusion.air.microservice
1. adapters (All the Implementations from App/Service perspective)
2. domain (All Entities, Models, Interfaces for the implementations)
3. security (All Security related modules)
4. server (Managing the Service - from a server perspective, Setups (Cache, DB, Kafka etc, Configs)
5. utils (Standard Utilities)

### Security Framework with Spring Security, JWT, KeyCloak, & Cryptography
![Security Structure](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/Fusion-Security-Pkg.png)

1.	Adapters Package (left side) – Integrations with Spring MVC, AOP, Filters, and Web Security.
2. Security Package (right side) – Core libraries and utilities for JWT creation, validation, cryptography, etc.

#### 1. Adapters Package (io.fusion.air.microservice.adapters)

A. Filters Package
1.	JWT Auth Filter
- A javax.servlet.Filter (or jakarta.servlet.Filter) that intercepts requests early in the servlet chain.
- It extracts JWTs from headers, validates or parses them, and stores user claims in a ClaimsManager for downstream use.
2.	Log Filter
- Another servlet filter for logging requests. Possibly logs details like request URIs, IP addresses, timings, etc.
3.	Security Filter
- A filter that enforces security rules at the servlet layer (e.g., blocking requests with invalid data or applying firewall rules).
- Complements or replaces Spring Security’s default filter chain in some scenarios.
These filters run before the DispatcherServlet. They can reject or manipulate requests if authentication or security checks fail.

B. Spring Framework (DispatcherServlet)
- DispatcherServlet is the central Spring MVC component that routes incoming HTTP requests to the
  appropriate controller endpoints. Checkout the [API flow in Part 4 of my Java 23 series.](https://arafkarsh.medium.com/java-23-springboot-3-3-4-api-flow-logging-part-4-1000546bcd62) 

C. AOP Package
- Authorization Request Aspect
- A Spring AOP aspect that intercepts controller or service methods to enforce authorization rules.
- Typically checks whether the user has the necessary roles/permissions based on JWT claims or
  custom annotations (@AuthorizationRequired).

Checkout the [Java 23, SpringBoot 3.3.4, & Jakarta EE 10](https://arafkarsh.medium.com/java-23-springboot-3-3-4-jakarta-10-125bc815d6c1) 
for more details on this topic.

### Template Tutorials - Java 23, SpringBoot 3.3.4 & Jakarta 10 Series
1. [Java 23, SpringBoot 3.3.4 & Jakarta 10 — Part 1](https://arafkarsh.medium.com/java-23-springboot-3-3-4-jakarta-10-125bc815d6c1)
2. [Java 23, SpringBoot 3.3.4: AOP Exception Handling — Part 2](https://arafkarsh.medium.com/java-23-springboot-3-3-4-aop-exception-handling-part-2-e6adc86c8a26)
3. [Java 23, SpringBoot 3.3.4: Logback Setup — Part 3 ](https://arafkarsh.medium.com/java-23-springboot-3-3-4-logback-setup-part-3-c2ffe2d0a358)
4. [Java 23, SpringBoot 3.3.4: Log/Events: API Flow & Logging — Part 4](https://arafkarsh.medium.com/java-23-springboot-3-3-4-api-flow-logging-part-4-1000546bcd62)
5. [Java 23, SpringBoot 3.3.4: Metrics: Micrometer, Prometheus, Actuator — Part 5](https://arafkarsh.medium.com/java-23-springboot-3-3-4-metrics-micrometer-prometheus-actuator-part-5-f67f0581815c)
6. [Java 23, SpringBoot 3.3.4: Metrics: Micrometer & AOP — Part 6](https://arafkarsh.medium.com/java-23-springboot-3-3-4-metrics-micrometer-aop-part-6-808dcb97dcb7)
7. [Java 23, SpringBoot 3.3.4: Tracing: OpenTelemetry — Part 7](https://arafkarsh.medium.com/java-23-springboot-3-3-4-tracing-opentelemetry-part-7-937df4867c9c)
8. Java 23, SpringBoot 3.4.1: Tracing: OpenTelemetry Zero Code— Part 8 Coming Soon
9. [Java 23, SpringBoot 3.4.1: Containers: Alpine Multi-Architecture — Part 9](https://arafkarsh.medium.com/java-23-springboot-3-4-1-multi-architecture-containers-part-9-b8c70ed3842f)
10. [Java 23, SpringBoot 3.4.1: Containers: Kubernetes — Part 10](https://arafkarsh.medium.com/java-23-springboot-3-4-1-kubernetes-containers-part-10-1b3b3b3b1b1b)
11. Java 23, SpringBoot 3.4.1: Filters: Security, Log — Part 11 Coming Soon
12. Java 23, SpringBoot 3.4.1: AOP: Spring Security — Part 12 Coming Soon
13. Java 23, SpringBoot 3.4.1: Security: JSON Web Token — Part 13 Coming Soon
14. Java 23, SpringBoot 3.4.1: CRUD : Domain Driven Design — Part 14 Coming Soon
15. Java 23, SpringBoot 3.4.1: CRUD Queries & Page Sort — Part 15 Coming Soon

### Pre-Requisites

1. SpringBoot 3.3.4
2. Java 23 (Minimum Requirement Java 17)
3. Jakarta EE 10 (jakarta.servlet.*, jakarta.persistence.*, javax.validation.*)
4. Maven 3.8.6
5. Git 2.31

## 1. Setting up the Template

### Step 1.1 - Getting Started

1. git clone [https://github.com/arafkarsh/ms-springboot-334-vanilla](https://github.com/arafkarsh/ms-springboot-334-vanilla)
2. cd ms-springboot-334-vanilla

###  Step 1.2 - Setup Encrypted DB Password in Property files

#### 1.2.1 Encrypt the Database passwords for H2 and PostgreSQL 

If you dont encrypt the password with your Encryption Key it will throw an exception saying unable to decrypt the password.
Here are the steps to encrypt the password.

Run the follwing command line option
```
$ source encrypt your-db-password your-encrypton-key
```
![Passowrd-Gen](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/Password-Gen.jpg)

Your encryption key will be set in the following Environment variable. SpringBoot Will automatically 
pickup the encryption key from this environment variable. 
```
JASYPT_ENCRYPTOR_PASSWORD=your-encrypton-key
```

#### 1.2.2 Update the Database passwords for H2 and PostgreSQL in the Property files

Update the property file in the local file
```
spring.datasource.password=ENC(kkthRIyJ7ogLJP8PThfXjqko33snTUa9lY1GkyFpzr7KFRVhRVXLOMwNSIzr4EjFGAOWLhWTH5cAWzRzAfs33g==)
```
AND
- the property template in src/main/resources/app.props.tmpl
- dev src/main/resources/application-dev.properties
```
spring.datasource.password=ENC(kkthRIyJ7ogLJP8PThfXjqko33snTUa9lY1GkyFpzr7KFRVhRVXLOMwNSIzr4EjFGAOWLhWTH5cAWzRzAfs33g==)
```
AND 
the property files for 
- staging src/main/resources/application-staging.properties 
- prod src/main/resources/application-prod.properties
```
spring.datasource.password=ENC(/J0gRHIdlhBHFwpNo3a+1q3+8Uig5+uSNQHO/lCGOrfg/e8Wt2o3v1eC4TaquaDVGREOEFphpw1B84lOtxgeIA==)
```
#### 1.2.3 - Generating the Encrypted Text from REST Endpoint

You can use the following REST Endpoint to encrypt the sensitive data. This will work only after setting
the environment variable JASYPT_ENCRYPTOR_PASSWORD and creating the first DB password
using the command line options.

![Passowrd-Van](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/ms-vanilla-encrypt.jpg)

###  Step 1.3 - Compile (Once your code is ready)

#### 1.3.1 Compile the Code
Execute the "compile" from ms-springboot-334-vanilla
1. compile OR ./compile (Runs in Linux and Mac OS)
2. mvn clean; mvn -e package; (All Platforms)
3. Use the IDE Compile options

#### 1.3.2 What the "Compile" Script will do

1. Clean up the target folder
2. Generate the build no. and build date (takes application.properties backup)
3. build final output SpringBoot fat jar and maven thin jar
4. copy the jar files (and dependencies) to src/docker folder
5. copy the application.properties file to current folder and src/docker folder

In Step 1.3.2 application.properties file will be auto generated by the "compile" script. This is a critical step.
Without generated application.properties file the service will NOT be running. There is pre-built application properties file.
Following three property files are critical (to be used with Spring Profiles)

1. application.properties
2. application-dev.properties
3. application-staging.properties
4. application-prod.properties

### Step 1.4 - Run the Application 

#### 1.4.1 - Spring Profiles

1. dev (Development Mode)
2. staging (Staging Mode)
3. prod (Production Mode)

#### 1.4.2 - Start the Service
1. Linux or Mac OS - Profiles (dev, staging, or prod)
```aiignore
run 
```
```aiignore
run dev 
```
```aiignore
run staging 
```
```aiignore
run prod 
```

2. All Platforms - Profiles (dev, staging, or prod)
```aiignore
 mvn spring-boot:run -Dspring-boot.run.profiles=dev
```
```aiignore
 mvn spring-boot:run -Dspring-boot.run.profiles=staging
```
```aiignore
 mvn spring-boot:run -Dspring-boot.run.profiles=prod
```

3. Microsoft Windows - Profiles (dev, staging, or prod)
```aiignore
java -jar target/ms-vanilla-service-*-spring-boot.jar --spring.profiles.active=dev  -Djava.security.manager=java.lang.SecurityManager -Djava.security.policy=./vanilla.policy
```
```aiignore
java -jar target/ms-vanilla-service-*-spring-boot.jar --spring.profiles.active=staging  -Djava.security.manager=java.lang.SecurityManager -Djava.security.policy=./vanilla.policy
```
```aiignore
java -jar target/ms-vanilla-service-*-spring-boot.jar --spring.profiles.active=prod  -Djava.security.manager=java.lang.SecurityManager -Djava.security.policy=./vanilla.policy
```

#### 1.4.3 - Test the Service 
1. test OR ./test (Runs in Linux or Mac OS)
2. Execute the curl commands directly (from the test script)

#### 1.4.4 - Running through IDE
Check the application.properties (in the project root directory) to change the profile Ex. spring.profiles.default=dev

#### 1.4.5 - $ run prod (Result) 
![Run Results](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/MS-Run-Result.jpg)


#### 1.4.6 - MS Cache Swagger UI Docs for Testing
![Swagger Docs](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/MS-Vanilla-Swagger-UI.jpg)

### Step 1.5 - Testing the APIs Using Swagger API Docs or Postman

To test the APIs (in secure mode - you will see a lock icon in the Swagger Docs). These test tokens are generated
based on the flag server.token.test=true in the application.properties file. (Change the app.props.tmpl if you want to
change in the build process.) In the Production environment, this flag should be false. These tokens can be generated only in
an Auth Service. All the services need not generate these tokens unless for the developers to test it out.
In a real world scenario, disable (Comment out the function generateTestToken() from the code  java file 
ServiceEventListener.java in the package documentation io.fusion.air.microservice.server.service)  this feature for 
production environment. 

#### Step 1.5.1: Copy the Auth Token
![Authorize Request](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/ms-vanilla-with-Test-Tokens.jpg)

#### Step 1.5.2: Click on the Authorize Button (Top Left the Swagger UI)

![Authorize Request](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/ms-vanilla-with-Test-Tokens-2.jpg)

#### Step 1.5.3: Enter the Token and Click Authorize

![Authorize Request](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/ms-vanilla-with-Test-Tokens-3.jpg)

#### Step 1.5.4: Enter the Refresh Token & Tx Token with every request that needs authorization

![Authorize Request](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/ms-vanilla-with-Test-Tokens-4.jpg)

### Step 1.6 -  Import Swagger API Docs Into Postman

What is Postman?
- Postman is an API platform for building and using APIs. Postman simplifies each step of the API 
lifecycle and streamlines collaboration so you can create better APIs—faster.
- Download Postman for Windows, Mac & Linux. https://www.postman.com/

#### Step 1.6.1: Swagger Open API 3.0 Docs JSON Format
![Swagger JSON](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/Import-API-into-Postman-0.jpg)

#### Step 1.6.2: Import Into Postman - Set the Link
![Postman Import](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/Import-API-Into-Postman-1.jpg)

#### Step 1.6.3: Import Into Postman - Confirm
![Postman Import](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/Import-API-into-Postman-2.jpg)
![Postman Import](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/Import-API-into-Postman-3.jpg)

#### Step 1.6.4: Test the API
![Postman Import](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/Import-API-into-Postman-4.jpg)

### Step 1.7 - JWT Token Validation example

####  1.7.1 Public API (Without Token Validation) - ...adapters.controllers.open.*
![No-Authorizet](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/JWT-Public.jpg)

#### 1.7.2 Secure API with a Single Token (Primarily to be used by ADMIN)
![Authorizet-Single](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/JWT-Single.jpg)

#### 1.7.3 Secure API with an Additional Tx Token which contains App Specific Claims.
![Authorize-Tx](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/JWT-Tx.jpg)

#### 1.7.4 All the APIs under the Secure Package (under ...adapters.controllers.secured.*)
![Secured-Pkg](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/JWT-Secured-Pkg.jpg)

## 2. CRUD Operations Demo & Error Handling

### 2.1 CRUD Operations 

#### 2.1.1 GET Query Execution and Fallback Data

![Crud Get](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-1-get-fallback.jpg)

#### 2.1.2 POST Create Data - Product 1
![Crud Post-1](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-2-post-prod-1-A.jpg)

#### 2.1.3 POST Create Data - Product 1 : Result
![Crud Post-2](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-2-post-prod-1-B.jpg)

#### 2.1.4 POST Create Data - Product 2 
![Crud Post-3](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-3-post-prod-2.jpg)

#### 2.1.5 POST Create Data - Product 3
![Crud Post-4](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-4-post-prod-3.jpg)

#### 2.1.6 GET All the Data (Created in Steps 2.2 - 2.5)
![Crud Get-6](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-5-get-from-db.jpg)

#### 2.1.7 GET Single Record
![Crud Get-7](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-6-get-from-db.jpg)

#### 2.1.8 PUT Update the Product Price
![Crud Get-8](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-7-put-update-price.jpg)

#### 2.1.9 PUT Update the Product - DeActivate the Product > Set isActive Flag = False
![Crud Get-9](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-8-put-deactivate.jpg)

#### 2.1.10 State of the Records after Inserts and Updates
![Crud Get-10](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-9-db-records.jpg)

### 2.2 Error Handling for SpringBoot App / Service

#### 2.2.1 Error Handling - Invalid Input
![Error-1](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-error-1-post-invalid-input-A.jpg)

#### 2.2.2 Error Handling - Invalid Input - Result
![Error-2](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-error-1-post-invalid-input-B.jpg)

#### 2.2.3 Error Handling - Invalid Input - Field Validations
![Error-3](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-error-2-post-invalid-input-A.jpg)

#### 2.2.4 Error Handling - Invalid Input - Field Validations - Result
![Error-4](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-error-2-post-invalid-input-B.jpg)

#### 2.2.5 Error Handling - Version Mismatch based o JPA @Version Annotation
![Error-5](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/crud/crud-error-3-post-Version-Mismatch-B.jpg)

### 2.3 Log Management 

#### 2.3.1 Log Success Messages
![Log-1](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/log/Log-Messages-1.jpg)

#### 2.3.2 Log Failure Messages
![Log-2](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/log/Log-Messages-2.jpg)

## 3. Configure the Template: Setup Org, Service, & Container Name, Versions, API Path in app.props.tmpl

1. git clone https://github.com/arafkarsh/ms-springboot-334-vanilla.git
2. cd ms-springboot-334-vanilla

Update the Properties Template

1. Update the Org Name in src/main/resources/app.props.tmpl file (service.org)
2. Update the Microservice name in src/main/resources/app.props.tmpl file (service.name)
3. Update the API Version in src/main/resources/app.props.tmpl file (service.api.version)
4. Update the API Name in src/main/resources/app.props.tmpl file (service.api.name)
5. Update the Container Name in src/main/resources/app.props.tmpl file (service.container)
6. Update the Server Version src/main/resources/app.props.tmpl file (server.version)
   Pom File
   <version>0.4.0</version>
   app.props.tmpl
   Microservice Server Properties
   server.version=0.4.0

Sample Property File Template
![Property File](https://raw.githubusercontent.com/arafkarsh/ms-springboot-334-vanilla/master/diagrams/MS-Property-File.jpg)

When you change the version in POM.xml, update that info in src/main/resources/app.props.tmpl - server.version property also.

## 4. Docker Container Setup

### Step 4.1 - Verify Container Name and Org Name

1. Verify the Org Name in src/main/resources/app.props.tmpl file (service.org)
2. Verify the container name in src/main/resources/app.props.tmpl file (service.container)
3. Verify the microservice name in src/main/resources/app.props.tmpl file (service.api.name)

### Step 4.2 - Build the image

1. build (Build the Container)
2. scan (Scan the container vulnerabilities)

### Step 4.3 - Test the image

1. start (Start the Container)
2. logs (to view the container logs) - Wait for the Container to Startup
3. Check the URL in a Browser

### Step 4.4 - Push the image to Container Cloud Repository

Update the Org Name in src/main/resources/app.props.tmpl file (service.org)
Setup the Docker Hub or any other Container Registry

1. push (Push the Container to Docker Hub)

### Step 4.5 Other Commands

1. stop (Stop the Container)
2. stats (show container stats)


(C) Copyright 2021-25 : Apache 2 License : Author: Araf Karsh Hamid

<pre>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
</pre>

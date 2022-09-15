## API Endpoints

- /register/l1
```
METHOD: POST
INPUT: {f_name: String, l_name, String, email: String, password: String}
DESC: Level 1 Registration
```

- /register/l2
```
METHOD: POST
INPUT: {salary: String, address, String, email: String, password: String}
DESC: Level 2 Registration. Email+Password should match with L1 registration
```

- /login
```
METHOD: POST
INPUT: {email: String, password: String}
DESC: Returns the access and refresh tokens when registration is completed. No more than 2 active sessions are allowed.
```

- /logout
```
METHOD: POST
INPUT: {token: String}
DESC: Logs out the session basis the refreshToken sent
```

- /getDetails
```
METHOD: GET
DESC: Access token needs to be present in the request headers
```

- /refreshToken
```
METHOD: POST
INPUT: {token: String}
DESC: Generates a new set of access and refresh tokens basis the refreshToken sent
```

# Akamai Test
A lightweight API to generate tokens for the users and validate them. Written on Python and using FastAPI as Framework.

## Description
This API has been developed based on these objectives:
- Minimal service that issues and validates tokens.
- Containarized service
- Using token based authentication, validations and logs.

Taking this into account, I made some assumptions which has defined the development of the service:
- Service will have a DB that will storage the users. 
    - To avoid external services, SQLite will be used and the DB will be stored on disk.
    - A pre-populated DB will be included with the proyect.
- API will have 2 endpoints, one for issue tokens and another one for validate them.
    - Issuance endpoint will require basic auth with username and password of an user stored on the DB.
    - Validation endpoint will require Bearer authentication with the token of the user.
- An extra endpoint will be included outside the objectives. This endpoint will allow to create new users. Useful for testing purposes.
- Tokens will be based on JWT with the algorithm RS256.
- Tokens will be encrypted with a private key and decrypted with a public key. Both keys will be present on the proyect and accessible for the service and the container.

Before explaining the proyect, I will explain how to run it. It's always good to have a TLDR;

## Makefile and how to run the proyect
I created a makefile to be able to build and run the proyect without any copy and paste. Is very simple and it only have 3 options:
- `make build`: build the docker image using secure mounting for some important files (public, private and vault key. Check **Public and Private Keys** and **Dockerfile** sections).
- `make run`: run the proyect based on the image generated after `make build`. This command forward the port 80 of the container to the por 8080 of the local machine. So, every request that want to be done to the container should be done to http://localhost:8080.
- `make test`: Just for testing purposes, runs all of the test of the proyect using pytest. Doesn't have coverage, it could be a great addition to the proyect

### Pre-populated DB
There is DB on the repository that have users stored. Ït could be done for testing purposes, but there is also the possibility to create new users on the API.

The information stored on the DB is the following one:
```
{
    "id": "102a6691-1550-43d6-8ddf-886ab468fcf9",
    "password": "DjinnSilex123",
    "name": "Hans"
}

{
    "id": "383ddcde-21bb-49cb-8406-e06b6fbbad11",
    "password": "ChozoChosen456",
    "name": "Samus"
}

{
    "id": "f6abb7b0-d886-4ec2-9649-d0dd6ed92e0b",
    "password": "FindingGanon789",
    "name": "Link"
}
```
Each of these users is usable when the container is up&running.

## Service

### API
First, the main component of the proyect is the API. Is based on Python and **FastAPI**. I decided to use **FastAPI** because is easy to generate simple proyects, has great functionality as an ORM, is really fast and lightweight. I didn't want to use **Django** even when it's really powerful because has a lot of dependencies which makes the service bigger than FastAPI. Also, this proyect just teach me a lot of features and limitations of FastAPI that I didn't know about.

The API is divided on 4 files: `main`, `models`, `settings` and `utils`. I also have a folder for tests (based on pytest).
#### `main.py`
Where the main logic of the API is implemented. Here the FastAPI application is created and the endpoints are defined. I have implemented 3 endpoints:
- `GET /issue-token`: endpoint where the users can ask for a token based on their username and password. This endpoints requires Basic Auth with username and password. The endpoint will check if the user is found in the DB and if the password matches the one that the user has in the DB. After that, the service will generate a JWT based on the algorythm RS256 and the private key and will return the JWT to the user.
- `GET /verify-token`: here, the users can verify if their tokens are valid. The authentication of this endpoint is Bearer Auth, where the user will include the token and the API will take it to verify it. The API will try to decrypt the token with the public key. If the decryption is ok, a `{"validation_check": "success"}` will be returned to the user
- `POST /user`: endpoint for testing purposes. Sending a JSON like this:     
    ```{
        "name": "username",
        "password": "userpassword" 
    }
    ```
    will create an user into the DB. This user could then be used on the other endpoints. This endpoints hashes the password that is going to be stored on the DB, this is for security reasons and will also help us to validate that an user is correctly authenticated.

Just to clarify, there are 2 points that are also important. First, I followed the philosophy of "clean views" witch means, maintain the views as small as possible. This is a personal take but has influenced the structure of the files and the proyect.

Second, `lifespan` function is a necessity. This will create the DB and all of the tables required (in this case only one) on the DB on application startup time. This is a commodity to avoid issues on the DB starting up the application.

#### `models.py`
Here is where the DB models are found, or model in this case as we only have one. The model is User and it stores an `id`, a `name` and a `password`.
- `id`: as I needed an identifier for the users on their tokens, this was the main candidate. Having a plain integer `id` is not good, so I take another approach, an UUID. 
- `name`: string that is indexed. As I am going to check if an user is present on the DB, I need to index it to improve performance on DB and API sides.
- `password`: just a string. On DB side I cannot hash the string, so I decided to do it on the `/user` endpoint.

#### `settings.py`
This file just have the configuration of the connection to the DB and the initialization of it. `main.py` uses this file to create the DB and the tables when the app initialize.

#### `utils.py`
I named this file utils because is the main file used by the views. Has the complete logic of: hashing passwords, generate tokens and validate tokens.

##### Hashing passwords
`verify_password` will verify the password. As the password is hashed on the DB, the verification will be done trying to hash the password in plain_text obtained during the authentication of the user on the endpoint `/issue-token`.

`hash_password` will hashs the password. This is done used "bcrypt" as schema. This function is used when saving the user to the DB.

##### Generate tokens
To generate tokens, first is required to validate the user. Function `check_user_authentication` check in the DB if there is a user with the username received. If it is not found, a 404 response will be returned. If the user is found but the password doens't match with the one on the DB, a 403 response will be returned. If the user and the password is correct, the information of the user is returned.

Then, the function `generate_user_token` will generate the token. This function receives a parameter `sub`. This parameter will be the subject of the token. In this case, and to be able to identify the user, the `sub` parameter will be the id of the user in the DB (remember that the id is an uuid). This function also receives an `expires_in` parameter. There is a constant named `ACCESS_TOKEN_EXPIRE_MINUTES` that is the one passed to this parameter. I could have improve it more making it a environment variable, but time constrains make that quite difficult. 

The function `generate_user_token` will generate a json with `sub` and `exp` (the later will only be pressent if `expires_in` parameter is sent) and then will try to encode it with the private key and the algorithm RS256. I will explain later why I'm using ansible and the status of the public and private keys. But, at this point, is only required to understand that the file that contains the private key is opened and readed to use the private key on the encryptation of the token.

##### Validate tokens
Last but not least, it is the function `validate_user_token`. This function receives a bearer token (checked by the dependency `OAuth2PasswordBearer`) and will try to decrypt the token to check if it's valid. To be able to decrypt the token, the file where the public key is found is opened and readed to use it on the decrypt of the token. Again, I will explain the status of the public and private keys in the next section.

If the token doesn't have sub, the token has expired or the token is invalid, a 401 response will be returned.

### Public and Private Keys
It is not really secure to have private and public keys in a Github repository. For the sake of the test, I decided to store them there, but I also decided to to a twist to them. Both files (privateKey.pem and publicKey.pem) are encrypted with ansible-vault. That gives it a little bit of security againts plain reads of the files, is not much but better than nothing.

To be able to encrypt these two files, I needed a key. That key is found inside the file vaultKey.txt. But that key is also encrypted. This time, I encrypted it with base64. 

This is why the lines 20 and 21 on utils.py I open the file vaultKey.txt, read it and decrypt with base64. With that key, I can then open the private and public key files on `generate_user_token` and `validate_user_token`, read the files and decrypt using ansible-vault. Decrypting them doesn't decrypt the file, as I open it on read-bytes mode, it just decrypt the filestream.

With this, we have a very thin layer of security. Better than nothing.

## Dockerfile
The file doesn't have anything really complicated aside of installing python packages using pip. But, as the test should focus on security, I should also try to achieve it. 

The public, private and vault keys are files that are encrypted, but that doesn't mean that I can copy them into the container as I want. Docker gives us the possibility of mounting some files securitly during the build to then use them on the Dockerfile. On the docker build, I defined the flag `--secret` to these tree files and on the Dockerfile I used these statements:
```
RUN --mount=type=secret,id=PUBLIC_KEY_FILE \
    cat /run/secrets/PUBLIC_KEY_FILE > /app/publicKey.pem
```
To copy the data inside the file into a file on the container. These type of secure mounting is ephimeral and will be destroyed after the build. 

I also tried to add the variables on the `vars.env` file using this secure mount. The `vars.env` file only have environment variables for the algorithm of the token encrypt/decrypt and the path of the files where the public, private and vault keys are. It would have been great if I could have done that, but for some reasing even when I tried to mount securetly the environment variables using the Docker documentation, the environment variables on the container where blank.

The DB is also copied into the container, so everytime the container is build and up, is possible to have a pre-populated DB ready to go. The port 80 is exposed to be able to forwarding it to the port of our local.

# Quick start

```bash

npm run keycloak # Build the theme one time (some assets will be copied to 
              # public/keycloak_static, they are needed to dev your page outside of Keycloak)
npm run start # start the react development server

```

## Test in docker locally

```bash
npm run keycloak # to build theme

docker build -t test .

docker tag docker.io/library/test test_local #rename for local use

docker compose up
    
```
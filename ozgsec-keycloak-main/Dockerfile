FROM registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/base-image as node-builder

COPY package.json .
RUN npm install
COPY . . 
RUN npm run keycloak

FROM quay.io/keycloak/keycloak:24.0.4@sha256:ff02c932f0249c58f32b8ff1b188a48cc90809779a3a05931ab67f5672400ad0 as builder

# Copy the theme into the image
COPY --from=node-builder ./build_keycloak/target/ozgsec-keycloak-theme-keycloak-theme-2.1.6.jar /opt/keycloak/providers

ENV KC_HEALTH_ENABLED=true
ENV KC_FEATURES=token-exchange
ENV KC_DB=postgres
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:24.0.4@sha256:ff02c932f0249c58f32b8ff1b188a48cc90809779a3a05931ab67f5672400ad0
COPY --from=builder /opt/keycloak/ /opt/keycloak/
WORKDIR /opt/keycloak

# Start in dev mode
# ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev"]

# Start in production mode
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]

FROM node:22.5.1-bookworm@sha256:86915971d2ce1548842315fcce7cda0da59319a4dab6b9fc0827e762ef04683a as builder
LABEL maintainer="ozgsec@neuland-homeland.de"

# checkov:skip=CKV_DOCKER_2

WORKDIR /usr/app/
ENV PORT 3000
EXPOSE 3000

ARG NEXT_PUBLIC_ENVIRONMENT
ENV NEXT_PUBLIC_ENVIRONMENT=$NEXT_PUBLIC_ENVIRONMENT

COPY package.json .
COPY package-lock.json .
COPY ./prisma prisma
RUN npm ci

COPY . .

ENV NODE_ENV production
RUN npm run build

FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:9f702c576ea50445bc8493ddec25b4e3ec0ee572b67c1b943014fa13b10d96ac

USER 53111

WORKDIR /usr/app/
ENV PORT 3000
ENV NODE_ENV production

# Copy libs for prisma
COPY --from=builder /lib/x86_64-linux-gnu /lib/x86_64-linux-gnu
COPY --from=builder --chown=53111:53111 /usr/app/.next /usr/app/.next
COPY --from=builder /usr/app/node_modules /usr/app/node_modules
COPY --from=builder /usr/app/package.json /usr/app/package.json
COPY --from=builder --chown=53111:53111 /usr/app/public /usr/app/public

CMD [ "./node_modules/next/dist/bin/next", "start" ]

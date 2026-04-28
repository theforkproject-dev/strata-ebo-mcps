FROM node:24-slim

WORKDIR /app

ARG CACHE_BUST=0
RUN printf "%s" "$CACHE_BUST" > /tmp/cache-bust

COPY package.json ./
COPY src ./src
COPY bin ./bin
COPY docs ./docs
COPY vendor ./vendor
COPY README.md ./README.md

ENV NODE_ENV=production
ENV STRATA_MODULE=file:///app/vendor/strata-ebo-turnstile/src/index.js
ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

CMD ["node", "src/server.js"]

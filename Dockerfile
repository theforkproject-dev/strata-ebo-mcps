FROM node:24-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6

WORKDIR /app

ARG CACHE_BUST=0
RUN printf "%s" "$CACHE_BUST" > /tmp/cache-bust

COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
       /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
       /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-* /root/.npm
COPY src ./src
COPY bin ./bin
COPY policies ./policies
COPY docs ./docs
COPY vendor ./vendor
COPY README.md ./README.md

ENV NODE_ENV=production
ENV STRATA_MODULE=file:///app/vendor/strata-ebo-turnstile/src/index.js
ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

CMD ["node", "src/server.js"]

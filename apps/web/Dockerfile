FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22-alpine AS runtime
ENV NODE_ENV=production \
    HOSTNAME=0.0.0.0 \
    PORT=3000
WORKDIR /app
RUN addgroup -S sentinel && adduser -S -G sentinel -u 10001 sentinel
COPY --from=build --chown=sentinel:sentinel /app/.next/standalone ./
COPY --from=build --chown=sentinel:sentinel /app/.next/static ./.next/static
USER sentinel
EXPOSE 3000
CMD ["node", "server.js"]

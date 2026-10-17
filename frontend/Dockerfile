FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY vite.config.js index.html ./
COPY src/ ./src/
RUN npm run build

FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

COPY serve.js ./
COPY --from=builder /app/dist ./dist

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:' + (process.env.PORT || 3000)).then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "serve.js"]

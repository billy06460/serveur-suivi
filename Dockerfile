FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
COPY public ./public
ENV PORT=8080 TRUST_PROXY=1 FORCE_HTTPS=1
USER node
EXPOSE 8080
CMD ["node","server.js"]

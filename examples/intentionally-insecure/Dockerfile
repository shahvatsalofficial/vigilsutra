FROM node:latest
RUN curl -fsSL https://example.invalid/install.sh | sh
COPY . /app
CMD ["node", "/app/server.js"]

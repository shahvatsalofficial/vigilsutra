# Local image. Not published to a registry by this repository.
#   docker build -t vigilsutra .
#   docker run --rm -v "$PWD:/scan:ro" vigilsutra audit /scan
FROM node:22-bookworm-slim
WORKDIR /opt/vigilsutra
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
COPY advisories ./advisories
RUN npm ci && chown -R node:node /opt/vigilsutra
USER node
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["--help"]

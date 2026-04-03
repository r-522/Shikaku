# Stage 1: Build Vue frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ .
RUN npm run build

# Stage 2: Build Rust backend
FROM rust:1.88-bookworm AS backend-builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
# sqlx macros require DATABASE_URL at compile time even for query_unchecked!
ENV DATABASE_URL=postgres://postgres:postgres@localhost:5432/shikaku
ENV SQLX_OFFLINE=true
COPY backend/Cargo.toml backend/Cargo.lock* ./
# Pre-fetch dependencies with a dummy main so the layer is cached
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -rf src
COPY backend/src ./src
RUN touch src/main.rs && cargo build --release

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=backend-builder /app/target/release/shikaku-backend ./shikaku-backend
COPY --from=frontend-builder /app/frontend/dist ./dist
ENV PORT=8080
EXPOSE 8080
CMD ["./shikaku-backend"]

FROM rust:slim-bookworm AS chef
RUN cargo install --locked cargo-chef
WORKDIR /SRC

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# Install system deps
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libssl-dev \
    libsasl2-2 \
    libsasl2-modules \
    libkrb5-dev  \
    libsasl2-dev \
    make \
    pkgconf

COPY --from=planner /SRC/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --release --locked


FROM debian:bookworm-slim
ARG APP=/usr/src/openwec
ARG DATA=/var/lib/openwec/data
ARG DB=/var/lib/openwec/db

EXPOSE 5985 5986
ENV APP_USER=openwec

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgssapi-krb5-2 \
    libsasl2-2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP} ${DATA} ${DB}

COPY --from=builder /SRC/target/release/openwec ${APP}/openwec
COPY --from=builder /SRC/target/release/openwecd ${APP}/openwecd
COPY ./docker/entrypoint.sh ${APP}/entrypoint.sh

RUN chown -R $APP_USER:$APP_USER ${APP} ${DATA} ${DB}

USER $APP_USER
WORKDIR ${APP}

CMD ["./entrypoint.sh"]

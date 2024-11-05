FROM alpine:3.20 AS chef
RUN apk add --no-cache rust cargo && cargo install cargo-chef
WORKDIR /SRC

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# Install system deps
RUN apk upgrade --no-cache && apk add --no-cache \
    build-base \
    cmake \
    clang-dev \
    bash \
    openssl-dev \
    krb5-dev  \
    pkgconf \
    rust-bindgen

COPY --from=planner /SRC/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --release --locked


FROM alpine:3.20
ARG APP=/usr/src/openwec
ARG DATA=/var/lib/openwec/data
ARG DB=/var/lib/openwec/db

EXPOSE 5985 5986
ENV APP_USER=openwec

RUN apk upgrade --no-cache && apk add --no-cache \
    libgcc \
    libssl3 libcrypto3 \
    krb5-libs \
    && addgroup $APP_USER \
    && adduser -G $APP_USER -D $APP_USER \
    && mkdir -p ${APP} ${DATA} ${DB}

COPY --from=builder /SRC/target/release/openwec ${APP}/openwec
COPY --from=builder /SRC/target/release/openwecd ${APP}/openwecd
COPY ./docker/entrypoint.sh ${APP}/entrypoint.sh

RUN chown -R $APP_USER:$APP_USER ${APP} ${DATA} ${DB}

USER $APP_USER
WORKDIR ${APP}

CMD ["./entrypoint.sh"]

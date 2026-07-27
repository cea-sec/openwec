# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/devcontainers/rust:latest
RUN apt-get update && apt-get install -y \
    libsasl2-dev \
    libssl-dev \
    pkg-config \
    ca-certificates \
    cmake \
    clang \
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*

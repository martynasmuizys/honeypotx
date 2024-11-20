FROM archlinux:base-devel
WORKDIR /usr/hpx

COPY . .

RUN pacman -Syu --noconfirm
RUN pacman -S clang neovim rustup --noconfirm
RUN rustup default stable
RUN cargo run -- generate

EXPOSE 8080

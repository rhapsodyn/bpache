# bpache = ~~better apache~~

Deadly simple & naive static web server, written in c99, tested on MacOS.

## Model

Like good-old Apache, one process for one connection, no async-io at all.

## Run

1. `make`
2. open `http://localhost:2048/site/index.html` in browser.
